"""Tests for ravensight.essentials_scorer — dataset loader and validator."""
import copy
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ravensight.essentials_scorer import _validate, load_essentials

COMMITTED = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "defaults"
    / "essentials_enterprise_it.json"
)


def _valid() -> dict[str, Any]:
    """Build a minimal valid dataset."""
    return {
        "schema_version": 1,
        "domains": [
            {
                "name": "Patching",
                "priority_phase": 1,
                "domain_type": "technical",
                "description": "Keep systems patched.",
            },
            {
                "name": "Governance",
                "priority_phase": None,
                "domain_type": "capability",
                "description": "Own the risk.",
            },
        ],
        "actions": [
            {
                "id": "IT.ABC-01.1",
                "principle": {"id": "IT.ABC-01", "name": "P", "statement": "S"},
                "action_text": "Do the thing.",
                "domains": ["Patching"],
                "mitre_technique_names": ["Phishing"],
                "igp": {
                    "not_effective": [{"id": "n1", "text": "no"}],
                    "partially_effective": [],
                    "fully_effective": [{"id": "f1", "text": "yes"}],
                },
                "references": {
                    "ism_excl_e8": ["ISM-0001"],
                    "e8_ism": [],
                    "nist_csf_2": ["PR.PS-02"],
                    "nist_800_171r3": [],
                    "aescsf": [],
                },
            }
        ],
    }


def _write(tmp_path: Path, data: Any) -> str:
    """Write data as JSON and return the path string."""
    p = tmp_path / "ess.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Return captured WARNING records."""
    return [r for r in caplog.records if r.levelno == logging.WARNING]


# --- loader paths ---


@pytest.mark.parametrize("path", [None, "", "   ", "\t\n"])
def test_unset_path_is_silent(path: str | None, caplog: pytest.LogCaptureFixture) -> None:
    """None or blank paths return {} with no warning."""
    with caplog.at_level(logging.WARNING):
        assert load_essentials(path) == {}
    assert not _warnings(caplog)


def test_missing_file_warns(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A missing file returns {} with one warning naming the path."""
    p = str(tmp_path / "nope.json")
    with caplog.at_level(logging.WARNING):
        assert load_essentials(p) == {}
    assert len(_warnings(caplog)) == 1
    assert p in caplog.text


def test_directory_path_warns(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A directory path (OSError) returns {} with one warning."""
    with caplog.at_level(logging.WARNING):
        assert load_essentials(str(tmp_path)) == {}
    assert len(_warnings(caplog)) == 1


def test_non_utf8_warns(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Non-UTF-8 bytes return {} with one warning."""
    p = tmp_path / "bad.json"
    p.write_bytes(b"\xff\xfe\x00\xff{")
    with caplog.at_level(logging.WARNING):
        assert load_essentials(str(p)) == {}
    assert len(_warnings(caplog)) == 1


def test_invalid_json_warns(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Invalid JSON returns {} with one warning."""
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert load_essentials(str(p)) == {}
    assert len(_warnings(caplog)) == 1


def test_non_dict_root_warns(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A non-dict root returns {} with one warning."""
    with caplog.at_level(logging.WARNING):
        assert load_essentials(_write(tmp_path, [1, 2])) == {}
    assert len(_warnings(caplog)) == 1


def test_missing_schema_version_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A missing schema_version is rejected."""
    data = _valid()
    del data["schema_version"]
    with caplog.at_level(logging.WARNING):
        assert load_essentials(_write(tmp_path, data)) == {}
    assert len(_warnings(caplog)) == 1


@pytest.mark.parametrize("version", [2, 0, "1", 1.0, True])
def test_wrong_schema_version_warns(
    version: Any, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Wrong, non-int and bool schema_version values are rejected."""
    data = _valid()
    data["schema_version"] = version
    with caplog.at_level(logging.WARNING):
        assert load_essentials(_write(tmp_path, data)) == {}
    assert len(_warnings(caplog)) == 1


def test_valid_minimal_loads_unchanged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A valid fixture loads unchanged without warnings."""
    data = _valid()
    with caplog.at_level(logging.WARNING):
        assert load_essentials(_write(tmp_path, data)) == data
    assert not _warnings(caplog)


def test_optional_fields_accepted() -> None:
    """Optional chapter fields and the ISM note are accepted when valid."""
    data = _valid()
    action = data["actions"][0]
    action["action_text_chapter"] = "text"
    action["mitre_technique_names_chapter"] = ["T"]
    action["references"]["ism_excl_e8_note"] = "note"
    assert _validate(data) == []


def test_problem_warning_truncates_to_three(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The warning reports the count and at most three problems."""
    data = _valid()
    template = data["actions"][0]
    data["actions"] = []
    for i in range(5):
        action = copy.deepcopy(template)
        action["id"] = f"bad{i}"
        data["actions"].append(action)
    assert len(_validate(data)) == 5
    with caplog.at_level(logging.WARNING):
        assert load_essentials(_write(tmp_path, data)) == {}
    assert len(_warnings(caplog)) == 1
    assert "(5 problems)" in caplog.text
    assert caplog.text.count("has a bad id") == 3


def test_non_hashable_domain_type_is_a_problem(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A list or dict domain_type yields a problem, not an exception."""
    for bad in ([], ["technical"], {}, {"a": 1}):
        data = _valid()
        data["domains"][0]["domain_type"] = bad
        assert any("domain_type" in p for p in _validate(data))
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            assert load_essentials(_write(tmp_path, data)) == {}
        assert len(_warnings(caplog)) == 1


def test_nul_byte_path_warns(caplog: pytest.LogCaptureFixture) -> None:
    """A path containing a NUL byte returns {} with one warning."""
    with caplog.at_level(logging.WARNING):
        assert load_essentials("bad\x00path.json") == {}
    assert len(_warnings(caplog)) == 1


def test_huge_integer_json_warns(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A JSON integer over the int-string digit limit returns {} with one warning."""
    p = tmp_path / "huge.json"
    p.write_text('{"schema_version": ' + "9" * 5000 + "}", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert load_essentials(str(p)) == {}
    assert len(_warnings(caplog)) == 1


@pytest.mark.parametrize("bad_id", ["IT.ABC-01.1\n", "ISM-0001\n"])
def test_trailing_newline_ids_rejected(bad_id: str) -> None:
    """Action and ISM ids with a trailing newline are rejected."""
    data = _valid()
    if bad_id.startswith("IT"):
        data["actions"][0]["id"] = bad_id
    else:
        data["actions"][0]["references"]["ism_excl_e8"] = [bad_id]
    assert _validate(data)


def test_long_bad_id_message_is_capped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A 10,000-character bad id cannot flood the warning."""
    data = _valid()
    data["actions"][0]["id"] = "x" * 10_000
    with caplog.at_level(logging.WARNING):
        assert load_essentials(_write(tmp_path, data)) == {}
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert len(warnings[0].getMessage()) < 1000


# --- validation rules, mutated one at a time ---


def _m_action_id(d: dict[str, Any]) -> None:
    d["actions"][0]["id"] = "IT.AB-1.1"


def _m_duplicate_id(d: dict[str, Any]) -> None:
    d["actions"].append(copy.deepcopy(d["actions"][0]))


def _m_unknown_domain(d: dict[str, Any]) -> None:
    d["actions"][0]["domains"] = ["Nowhere"]


def _m_empty_domains(d: dict[str, Any]) -> None:
    d["actions"][0]["domains"] = []


def _m_bad_ism(d: dict[str, Any]) -> None:
    d["actions"][0]["references"]["ism_excl_e8"] = ["ISM-12"]


def _m_bad_e8_ism(d: dict[str, Any]) -> None:
    d["actions"][0]["references"]["e8_ism"] = ["0001"]


def _m_igp_missing_key(d: dict[str, Any]) -> None:
    del d["actions"][0]["igp"]["fully_effective"]


def _m_igp_extra_key(d: dict[str, Any]) -> None:
    d["actions"][0]["igp"]["extra"] = []


def _m_igp_item_shape(d: dict[str, Any]) -> None:
    d["actions"][0]["igp"]["not_effective"] = ["just a string"]


def _m_igp_item_id(d: dict[str, Any]) -> None:
    d["actions"][0]["igp"]["not_effective"] = [{"id": 1, "text": "x"}]


def _m_igp_not_list(d: dict[str, Any]) -> None:
    d["actions"][0]["igp"]["not_effective"] = {}


def _m_ref_non_str(d: dict[str, Any]) -> None:
    d["actions"][0]["references"]["nist_csf_2"] = ["ok", 5]


def _m_ref_missing(d: dict[str, Any]) -> None:
    del d["actions"][0]["references"]["aescsf"]


def _m_note_not_str(d: dict[str, Any]) -> None:
    d["actions"][0]["references"]["ism_excl_e8_note"] = 3


def _m_phase_range(d: dict[str, Any]) -> None:
    d["domains"][0]["priority_phase"] = 4


def _m_phase_bool(d: dict[str, Any]) -> None:
    d["domains"][0]["priority_phase"] = True


def _m_phase_str(d: dict[str, Any]) -> None:
    d["domains"][0]["priority_phase"] = "1"


def _m_domain_type(d: dict[str, Any]) -> None:
    d["domains"][0]["domain_type"] = "other"


def _m_domain_desc(d: dict[str, Any]) -> None:
    d["domains"][0]["description"] = None


def _m_domain_dup(d: dict[str, Any]) -> None:
    d["domains"][1]["name"] = "Patching"


def _m_domain_name(d: dict[str, Any]) -> None:
    d["domains"][0]["name"] = 7


def _m_domain_not_dict(d: dict[str, Any]) -> None:
    d["domains"][0] = "x"


def _m_domains_not_list(d: dict[str, Any]) -> None:
    d["domains"] = {}


def _m_actions_empty(d: dict[str, Any]) -> None:
    d["actions"] = []


def _m_action_not_dict(d: dict[str, Any]) -> None:
    d["actions"][0] = "x"


def _m_principle(d: dict[str, Any]) -> None:
    del d["actions"][0]["principle"]["statement"]


def _m_action_text(d: dict[str, Any]) -> None:
    d["actions"][0]["action_text"] = 1


def _m_action_text_chapter(d: dict[str, Any]) -> None:
    d["actions"][0]["action_text_chapter"] = 1


def _m_mitre(d: dict[str, Any]) -> None:
    d["actions"][0]["mitre_technique_names"] = "Phishing"


def _m_mitre_chapter(d: dict[str, Any]) -> None:
    d["actions"][0]["mitre_technique_names_chapter"] = [1]


@pytest.mark.parametrize(
    "mutate",
    [
        _m_action_id,
        _m_duplicate_id,
        _m_unknown_domain,
        _m_empty_domains,
        _m_bad_ism,
        _m_bad_e8_ism,
        _m_igp_missing_key,
        _m_igp_extra_key,
        _m_igp_item_shape,
        _m_igp_item_id,
        _m_igp_not_list,
        _m_ref_non_str,
        _m_ref_missing,
        _m_note_not_str,
        _m_phase_range,
        _m_phase_bool,
        _m_phase_str,
        _m_domain_type,
        _m_domain_desc,
        _m_domain_dup,
        _m_domain_name,
        _m_domain_not_dict,
        _m_domains_not_list,
        _m_actions_empty,
        _m_action_not_dict,
        _m_principle,
        _m_action_text,
        _m_action_text_chapter,
        _m_mitre,
        _m_mitre_chapter,
    ],
)
def test_each_rule_rejects(mutate: Callable[[dict[str, Any]], None]) -> None:
    """Each single-rule mutation of a valid fixture produces a problem."""
    assert _validate(_valid()) == []
    data = _valid()
    mutate(data)
    assert _validate(data)


def test_problem_messages_name_action_id() -> None:
    """Action problems name the action id."""
    data = _valid()
    data["actions"][0]["action_text"] = 1
    assert any("IT.ABC-01.1" in p for p in _validate(data))


def test_problem_messages_name_domain_index() -> None:
    """Domain problems name the domain index."""
    data = _valid()
    data["domains"][1]["domain_type"] = "bad"
    assert any("domain[1]" in p for p in _validate(data))


# --- committed dataset ---


def test_committed_dataset_loads_with_expected_counts() -> None:
    """The committed dataset validates and has the verified counts."""
    data = load_essentials(str(COMMITTED))
    assert data
    assert data["schema_version"] == 1
    actions = data["actions"]
    assert len(actions) == 58
    assert len({a["principle"]["id"] for a in actions}) == 28
    assert len(data["domains"]) == 8
    assert sum(len(a["domains"]) for a in actions) == 212
    assert (
        sum(len(v) for a in actions for v in a["igp"].values()) == 529
    )
    assert sum("mitre_technique_names_chapter" in a for a in actions) == 37
    assert sum("action_text_chapter" in a for a in actions) == 4
