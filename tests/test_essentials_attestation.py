"""Tests for load_essentials_attestation in ravensight.essentials_scorer."""
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from ravensight.essentials_scorer import load_essentials, load_essentials_attestation

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "defaults" / "essentials_enterprise_it.json"
EXAMPLE = ROOT / "data" / "defaults" / "essentials_attestation.example.json"
DEFAULT = {"status": "Not assessed", "reason": "", "domains": []}
STATUSES = [
    "Not applicable",
    "Not assessed",
    "Not effective",
    "Partially effective",
    "Fully effective",
]


@pytest.fixture
def essentials() -> dict[str, Any]:
    """Return a hand-built mini Essentials dataset."""
    return {
        "domains": [{"name": "Alpha domain"}, {"name": "Beta domain"}],
        "actions": [
            {"id": "IT.AAA-01.1", "principle": {"id": "AAA-01"}},
            {"id": "IT.AAA-01.2", "principle": {"id": "AAA-01"}},
            {"id": "IT.BBB-02.1", "principle": {"id": "BBB-02"}},
            {"id": "IT.CCC-03.1", "principle": {"id": "CCC-03"}},
        ],
    }


def _write(tmp_path: Path, data: Any) -> str:
    """Write data as JSON and return the path as a string."""
    path = tmp_path / "att.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _load_one(
    tmp_path: Path, essentials: dict, caplog: pytest.LogCaptureFixture, entry: Any,
    key: str = "AAA-01",
) -> dict:
    """Load a one-entry file and return the result."""
    caplog.set_level(logging.WARNING)
    return load_essentials_attestation(_write(tmp_path, {key: entry}), essentials)


def test_blank_or_none_path_is_silent(
    essentials: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """A blank or None path gives defaults without a warning."""
    caplog.set_level(logging.WARNING)
    for path in (None, "", "   "):
        result = load_essentials_attestation(path, essentials)
        assert result == {"AAA-01": DEFAULT, "BBB-02": DEFAULT, "CCC-03": DEFAULT}
    assert caplog.records == []


@pytest.mark.parametrize(
    "bad", [None, {}, [], "x", {"actions": "x"}, {"actions": [1, None, {"principle": 3}]}]
)
def test_bad_essentials_gives_empty(bad: Any, tmp_path: Path) -> None:
    """Missing or malformed essentials gives {}."""
    assert load_essentials_attestation(_write(tmp_path, {}), bad) == {}
    assert load_essentials_attestation(None, bad) == {}


def test_missing_essentials_argument(tmp_path: Path) -> None:
    """Omitting essentials gives {}."""
    assert load_essentials_attestation(_write(tmp_path, {})) == {}


def test_file_level_failures_give_defaults_with_one_warning(
    tmp_path: Path, essentials: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """Each file-level failure returns defaults with exactly one warning."""
    caplog.set_level(logging.WARNING)
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json", encoding="utf-8")
    bad_utf = tmp_path / "utf.json"
    bad_utf.write_bytes(b"\xff\xfe\x00\x80")
    big = tmp_path / "big.json"
    big.write_text("1" * 5000, encoding="utf-8")
    cases = [
        str(tmp_path / "missing.json"),
        str(bad_json),
        str(bad_utf),
        str(tmp_path),
        "bad\x00path",
        str(big),
        _write(tmp_path, [1, 2]),
    ]
    for path in cases:
        caplog.clear()
        result = load_essentials_attestation(path, essentials)
        assert result == {"AAA-01": DEFAULT, "BBB-02": DEFAULT, "CCC-03": DEFAULT}, path
        assert len(caplog.records) == 1, path


@pytest.mark.parametrize("status", STATUSES)
def test_valid_statuses_stored(
    status: str, tmp_path: Path, essentials: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """Each valid status is stored as given with reason and domains."""
    entry = {"status": status, "reason": "my reason", "domains": ["Beta domain"]}
    result = _load_one(tmp_path, essentials, caplog, entry)
    assert result["AAA-01"] == entry
    assert caplog.records == []


def test_domains_optional(
    tmp_path: Path, essentials: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """Absent domains becomes an empty list."""
    result = _load_one(tmp_path, essentials, caplog, {"status": "Not effective", "reason": ""})
    assert result["AAA-01"] == {"status": "Not effective", "reason": "", "domains": []}


def test_domains_order_kept(
    tmp_path: Path, essentials: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """Domain order is preserved."""
    entry = {"status": "Fully effective", "reason": "r", "domains": ["Beta domain", "Alpha domain"]}
    result = _load_one(tmp_path, essentials, caplog, entry)
    assert result["AAA-01"]["domains"] == ["Beta domain", "Alpha domain"]


BAD_ENTRIES = [
    ("non-dict", "text"),
    ("non-dict-list", ["a"]),
    ("status-case", {"status": "fully effective", "reason": "r"}),
    ("status-int", {"status": 3, "reason": "r"}),
    ("status-list", {"status": ["Fully effective"], "reason": "r"}),
    ("status-dict", {"status": {"a": 1}, "reason": "r"}),
    ("status-none", {"status": None, "reason": "r"}),
    ("status-missing", {"reason": "r"}),
    ("reason-int", {"status": "Fully effective", "reason": 5}),
    ("reason-none", {"status": "Fully effective", "reason": None}),
    ("reason-missing", {"status": "Fully effective"}),
    ("example", {"status": "Fully effective", "reason": "EXAMPLE: replace"}),
    ("example-lower", {"status": "Fully effective", "reason": "example: x"}),
    ("example-spaces", {"status": "Fully effective", "reason": "   Example: x"}),
    ("domains-str", {"status": "Fully effective", "reason": "r", "domains": "Alpha domain"}),
    ("domains-none", {"status": "Fully effective", "reason": "r", "domains": None}),
    ("domains-nonstr", {"status": "Fully effective", "reason": "r", "domains": [1]}),
    ("domains-unknown", {"status": "Fully effective", "reason": "r", "domains": ["Nope"]}),
    ("domains-dup", {"status": "Fully effective", "reason": "r",
                     "domains": ["Alpha domain", "Alpha domain"]}),
    ("domains-case", {"status": "Fully effective", "reason": "r", "domains": ["alpha domain"]}),
    ("domains-unhashable", {"status": "Fully effective", "reason": "r",
                            "domains": [["Alpha domain"]]}),
    ("domains-dict", {"status": "Fully effective", "reason": "r", "domains": [{"a": 1}]}),
]


@pytest.mark.parametrize("entry", [e for _, e in BAD_ENTRIES], ids=[n for n, _ in BAD_ENTRIES])
def test_bad_entry_skipped_with_one_warning(
    entry: Any, tmp_path: Path, essentials: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """A bad entry leaves the default and warns once."""
    result = _load_one(tmp_path, essentials, caplog, entry)
    assert result["AAA-01"] == DEFAULT
    assert len(caplog.records) == 1


@pytest.mark.parametrize("key", ["ZZZ-99", "aaa-01", "AAA-01 ", "IT.AAA-01.1"])
def test_bad_key_skipped(
    key: str, tmp_path: Path, essentials: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """Unknown or wrong-case ids are skipped with one warning."""
    good = {"status": "Fully effective", "reason": "r"}
    result = _load_one(tmp_path, essentials, caplog, good, key=key)
    assert result == {"AAA-01": DEFAULT, "BBB-02": DEFAULT, "CCC-03": DEFAULT}
    assert len(caplog.records) == 1


def test_bad_entry_does_not_affect_good(
    tmp_path: Path, essentials: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """A bad entry leaves neighbouring good entries intact."""
    caplog.set_level(logging.WARNING)
    data = {
        "AAA-01": {"status": "bogus", "reason": "r"},
        "BBB-02": {"status": "Not effective", "reason": "ok", "domains": ["Alpha domain"]},
    }
    result = load_essentials_attestation(_write(tmp_path, data), essentials)
    assert result["AAA-01"] == DEFAULT
    assert result["BBB-02"] == {
        "status": "Not effective", "reason": "ok", "domains": ["Alpha domain"],
    }
    assert result["CCC-03"] == DEFAULT
    assert len(caplog.records) == 1


def test_result_shape_and_fresh_lists(tmp_path: Path, essentials: dict[str, Any]) -> None:
    """Each value has exactly the three keys and its own domains list."""
    result = load_essentials_attestation(None, essentials)
    assert list(result) == ["AAA-01", "BBB-02", "CCC-03"]
    for value in result.values():
        assert set(value) == {"status", "reason", "domains"}
    result["AAA-01"]["domains"].append("x")
    assert result["BBB-02"]["domains"] == []
    assert load_essentials_attestation(None, essentials)["AAA-01"]["domains"] == []


def test_committed_example_keys_and_reasons() -> None:
    """Example keys are real principle ids and every reason is a placeholder."""
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    principle_ids = {
        a["principle"]["id"] for a in json.loads(DATASET.read_text(encoding="utf-8"))["actions"]
    }
    assert 3 <= len(data) <= 4
    assert set(data) <= principle_ids
    for entry in data.values():
        assert entry["reason"].startswith("EXAMPLE:")
        assert set(entry) <= {"status", "reason", "domains"}


def test_committed_example_untouched_claims_nothing(caplog: pytest.LogCaptureFixture) -> None:
    """The untouched example loads to all Not assessed, warning for each placeholder."""
    caplog.set_level(logging.WARNING)
    ess = load_essentials(str(DATASET))
    result = load_essentials_attestation(str(EXAMPLE), ess)
    assert len(result) == 28
    assert all(v == DEFAULT for v in result.values())
    assert len(caplog.records) == len(json.loads(EXAMPLE.read_text(encoding="utf-8")))


def test_committed_example_with_prefix_stripped_loads(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """With the EXAMPLE: prefix removed the declared ratings load."""
    caplog.set_level(logging.WARNING)
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    edited = {
        k: {**v, "reason": v["reason"].replace("EXAMPLE: ", "", 1)} for k, v in raw.items()
    }
    ess = load_essentials(str(DATASET))
    result = load_essentials_attestation(_write(tmp_path, edited), ess)
    assert caplog.records == []
    for key, entry in raw.items():
        assert result[key]["status"] == entry["status"]
        assert result[key]["domains"] == entry.get("domains", [])
        assert not result[key]["reason"].startswith("EXAMPLE:")
    assert any(v["domains"] for v in result.values())


def test_no_derived_keys(tmp_path: Path, essentials: dict[str, Any]) -> None:
    """No score, level or percentage appears in any output."""
    data = {"AAA-01": {"status": "Fully effective", "reason": "r", "domains": ["Alpha domain"]}}
    result = load_essentials_attestation(_write(tmp_path, data), essentials)
    for value in result.values():
        assert set(value) == {"status", "reason", "domains"}
    assert not {"score", "level", "percentage"} & {k for v in result.values() for k in v}
