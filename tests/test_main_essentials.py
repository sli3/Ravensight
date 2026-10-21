"""
Tests for the Essentials wiring in main.

No network, LLM or ChromaDB: fetch_alerts and analyse are monkeypatched and
Reporter.generate is replaced by a recording fake. Never touches the real config.toml.
"""

import copy
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest

import main
from ravensight import analyser, wazuh_client
from tests.test_config_check import _CONFIG_TEMPLATE, _capture_generate

_DATASET_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "defaults" / "essentials_enterprise_it.json"
)
_MITRE_JSON = {
    "techniques": [
        {"id": "T1562", "name": "Impair Defenses"},
        {"id": "T1562.001", "name": "Disable or Modify Tools"},
    ]
}


def _mitre_file(tmp_path: Path) -> str:
    """Write a tiny MITRE technique file and return its path."""
    path = tmp_path / "mitre.json"
    path.write_text(json.dumps(_MITRE_JSON), encoding="utf-8")
    return str(path)


def _config(path: Any = None, attestation_path: Any = None) -> dict[str, Any]:
    """Build a config with an [essentials] table holding the given values."""
    table: dict[str, Any] = {}
    if path is not None:
        table["path"] = path
    if attestation_path is not None:
        table["attestation_path"] = attestation_path
    return {"essentials": table}


def _analysis() -> dict[str, Any]:
    """Build an analysis whose one finding names a MITRE technique."""
    return {"findings": [{"id": "C1", "description": "Defender disabled", "mitre_ids": ["T1562.001"]}]}


# --- _load_technique_names --------------------------------------------------------------


def test_load_technique_names_valid_file(tmp_path: Path) -> None:
    """A valid MITRE file gives an id to name map."""
    names = main._load_technique_names(_mitre_file(tmp_path))
    assert names["T1562.001"] == "Disable or Modify Tools"
    assert names["T1562"] == "Impair Defenses"


def test_load_technique_names_missing_file(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """A missing file gives {} and one warning."""
    with caplog.at_level(logging.WARNING):
        assert main._load_technique_names(str(tmp_path / "nope.json")) == {}
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1


def test_load_technique_names_bad_json(tmp_path: Path) -> None:
    """Malformed JSON gives {}."""
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main._load_technique_names(str(bad)) == {}


def test_load_technique_names_non_utf8(tmp_path: Path) -> None:
    """A file that is not UTF-8 gives {}."""
    bad = tmp_path / "bin.json"
    bad.write_bytes(b"\xff\xfe\x00\x80")
    assert main._load_technique_names(str(bad)) == {}


@pytest.mark.parametrize("value", [None, "", "   ", 5, ["x"], Path("x.json")])
def test_load_technique_names_unusable_path(value: Any) -> None:
    """A blank or non-str path gives {} without raising."""
    assert main._load_technique_names(value) == {}


# --- _build_essentials ------------------------------------------------------------------


@pytest.mark.parametrize("config", [{}, {"essentials": {}}, {"essentials": "x"}, {"essentials": 5}])
def test_build_essentials_unset_gives_none(config: dict[str, Any]) -> None:
    """No [essentials] table, an empty one or a non-table gives None."""
    assert main._build_essentials(config, _analysis(), None, None) is None


@pytest.mark.parametrize("value", [5, ["x"], True])
def test_build_essentials_non_str_path_gives_none(value: Any) -> None:
    """A non-str path counts as unset and does not raise."""
    assert main._build_essentials(_config(path=value), _analysis(), None, None) is None


def test_build_essentials_missing_dataset_gives_none(tmp_path: Path) -> None:
    """A dataset path that does not exist gives None."""
    config = _config(path=str(tmp_path / "missing.json"))
    assert main._build_essentials(config, _analysis(), None, None) is None


def test_build_essentials_mitre_pointer(tmp_path: Path) -> None:
    """The committed dataset and a tiny MITRE file give an IT.DET-01.1 pointer."""
    result = main._build_essentials(
        _config(path=str(_DATASET_PATH)), _analysis(), _mitre_file(tmp_path), None
    )
    assert result is not None
    assert result["dataset"]
    assert len(result["finding_actions"]) == 1
    action_ids = [a["action_id"] for a in result["finding_actions"][0]["actions"]]
    assert "IT.DET-01.1" in action_ids


def test_build_essentials_ism_pointers_passed_through(tmp_path: Path) -> None:
    """ISM pointers reach the ISM route of the mapper."""
    dataset = json.loads(_DATASET_PATH.read_text(encoding="utf-8"))
    found = None
    for action in dataset["actions"]:
        for field in ("ism_excl_e8", "e8_ism"):
            ids = action.get("references", {}).get(field) if isinstance(action.get("references"), dict) else None
            if ids:
                found = (action["id"], ids[0])
                break
        if found:
            break
    assert found is not None
    ism_id = found[1]
    pointers = [{"id": "C1", "ism": [{"id": ism_id}], "e8": []}]
    analysis = {"findings": [{"id": "C1", "description": "x"}]}
    result = main._build_essentials(_config(path=str(_DATASET_PATH)), analysis, None, pointers)
    assert result is not None
    entries = result["finding_actions"][0]["actions"]
    routes = {r["route"] for a in entries for r in a["reasons"]}
    assert "ism" in routes


def test_build_essentials_returns_attestation(tmp_path: Path) -> None:
    """A valid attestation file entry is returned for its principle."""
    attest = tmp_path / "attest.json"
    attest.write_text(
        json.dumps({"DET-01": {"status": "Fully effective", "reason": "Reviewed"}}),
        encoding="utf-8",
    )
    result = main._build_essentials(
        _config(path=str(_DATASET_PATH), attestation_path=str(attest)), _analysis(), None, None
    )
    assert result is not None
    assert result["attestation"]["DET-01"]["status"] == "Fully effective"
    assert result["attestation"]["DET-01"]["reason"] == "Reviewed"


def test_build_essentials_bad_attestation_gives_defaults(tmp_path: Path) -> None:
    """A malformed attestation file leaves every principle Not assessed."""
    attest = tmp_path / "attest.json"
    attest.write_text("{broken", encoding="utf-8")
    result = main._build_essentials(
        _config(path=str(_DATASET_PATH), attestation_path=str(attest)), _analysis(), None, None
    )
    assert result is not None
    assert result["attestation"]
    assert all(v["status"] == "Not assessed" for v in result["attestation"].values())


def test_build_essentials_non_str_attestation_path_is_unset() -> None:
    """A non-str attestation path is treated as unset."""
    result = main._build_essentials(
        _config(path=str(_DATASET_PATH), attestation_path=5), _analysis(), None, None
    )
    assert result is not None
    assert all(v["status"] == "Not assessed" for v in result["attestation"].values())


@pytest.mark.parametrize("findings", [None, "x", {"id": "C1"}, 5])
def test_build_essentials_non_list_findings_tolerated(findings: Any) -> None:
    """A non-list findings value gives an empty pointer list, not an error."""
    result = main._build_essentials(
        _config(path=str(_DATASET_PATH)), {"findings": findings}, None, None
    )
    assert result is not None
    assert result["finding_actions"] == []


def test_build_essentials_missing_findings_key() -> None:
    """An analysis with no findings key is tolerated."""
    result = main._build_essentials(_config(path=str(_DATASET_PATH)), {}, None, None)
    assert result is not None
    assert result["finding_actions"] == []


# --- Rule 87702 IPv6 artefact: MITRE ids ignored for matching only ----------------------


def _t1110_mitre_file(tmp_path: Path) -> str:
    """Write a MITRE file whose T1110 maps to a name that matches a dataset action."""
    path = tmp_path / "mitre_t1110.json"
    path.write_text(
        json.dumps({"techniques": [{"id": "T1110", "name": "Disable or Modify Tools"}]}),
        encoding="utf-8",
    )
    return str(path)


def _finding(finding_id: str, **extra: Any) -> dict[str, Any]:
    """Build a finding carrying T1110 plus any extra keys."""
    return {"id": finding_id, "description": "x", "mitre_ids": ["T1110"], **extra}


def _routes(result: dict[str, Any], finding_id: str) -> set[str]:
    """Return the reason routes recorded for one finding id."""
    return {
        r["route"]
        for entry in result["finding_actions"]
        if entry["id"] == finding_id
        for a in entry["actions"]
        for r in a["reasons"]
    }


def _build(tmp_path: Path, findings: list[Any], pointers: list | None = None) -> dict[str, Any]:
    """Run _build_essentials over the given findings with the T1110 MITRE file."""
    result = main._build_essentials(
        _config(path=str(_DATASET_PATH)), {"findings": findings}, _t1110_mitre_file(tmp_path), pointers
    )
    assert result is not None
    return result


def test_build_essentials_ignores_mitre_for_87702_ipv6_cluster(tmp_path: Path) -> None:
    """A cluster with the IPv6 artefact note gets no MITRE reason."""
    result = _build(tmp_path, [_finding("C1", notes=[analyser.RULE_87702_IPV6_ARTEFACT_NOTE])])
    assert "mitre" not in _routes(result, "C1")


def test_build_essentials_keeps_mitre_without_artefact_note(tmp_path: Path) -> None:
    """With empty notes the T1110 finding still gets a MITRE reason."""
    result = _build(tmp_path, [_finding("C1", notes=[])])
    assert "mitre" in _routes(result, "C1")


def test_build_essentials_keeps_mitre_with_other_notes(tmp_path: Path) -> None:
    """Unrelated notes do not suppress the MITRE route."""
    result = _build(tmp_path, [_finding("C1", notes=["something else"])])
    assert "mitre" in _routes(result, "C1")


def test_build_essentials_artefact_does_not_mutate_inputs(tmp_path: Path) -> None:
    """The analysis is unchanged after the call and keeps its mitre_ids."""
    analysis = {"findings": [_finding("C1", notes=[analyser.RULE_87702_IPV6_ARTEFACT_NOTE])]}
    snapshot = copy.deepcopy(analysis)
    main._build_essentials(
        _config(path=str(_DATASET_PATH)), analysis, _t1110_mitre_file(tmp_path), None
    )
    assert analysis == snapshot
    assert analysis["findings"][0]["mitre_ids"] == ["T1110"]


def test_build_essentials_artefact_keeps_ism_route(tmp_path: Path) -> None:
    """The ISM route still fires for an artefact cluster."""
    dataset = json.loads(_DATASET_PATH.read_text(encoding="utf-8"))
    ism_id = None
    for action in dataset["actions"]:
        refs = action.get("references")
        for field in ("ism_excl_e8", "e8_ism"):
            ids = refs.get(field) if isinstance(refs, dict) else None
            if ids:
                ism_id = ids[0]
                break
        if ism_id:
            break
    assert ism_id is not None
    pointers = [{"id": "C1", "ism": [{"id": ism_id}], "e8": []}]
    result = _build(
        tmp_path, [_finding("C1", notes=[analyser.RULE_87702_IPV6_ARTEFACT_NOTE])], pointers
    )
    routes = _routes(result, "C1")
    assert "ism" in routes
    assert "mitre" not in routes


def test_build_essentials_mixed_findings(tmp_path: Path) -> None:
    """Only the non-artefact cluster keeps its MITRE reasons."""
    result = _build(
        tmp_path,
        [
            _finding("C1", notes=[analyser.RULE_87702_IPV6_ARTEFACT_NOTE]),
            _finding("C2", notes=[]),
        ],
    )
    assert "mitre" not in _routes(result, "C1")
    assert "mitre" in _routes(result, "C2")


_NOTES_ABSENT = object()  # sentinel: the finding has no "notes" key at all
_NOTES_STRING_CONTAINING_ARTEFACT = f"x {analyser.RULE_87702_IPV6_ARTEFACT_NOTE} x"


@pytest.mark.parametrize(
    "notes", [_NOTES_STRING_CONTAINING_ARTEFACT, None, _NOTES_ABSENT], ids=["string", "none", "absent"]
)
def test_build_essentials_tolerates_odd_notes(tmp_path: Path, notes: Any) -> None:
    """String, None or absent notes and a non-dict item do not raise; MITRE is kept."""
    extra = {} if notes is _NOTES_ABSENT else {"notes": notes}
    result = _build(tmp_path, ["not a dict", _finding("C1", **extra)])
    assert "mitre" in _routes(result, "C1")


# --- Full run ---------------------------------------------------------------------------


def _run_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra_config: str
) -> dict[str, Any]:
    """Run main.main() as a full run with a throwaway config and return what generate received."""
    captured = _capture_generate(monkeypatch, tmp_path)
    monkeypatch.setattr(wazuh_client.Client, "fetch_alerts", lambda self, **kwargs: [])
    monkeypatch.setattr(
        analyser,
        "analyse",
        lambda *args, **kwargs: {"summary": "s", "findings": [], "recommendations": []},
    )
    monkeypatch.setattr(analyser, "extract_alert_clusters", lambda alerts: [])
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(_CONFIG_TEMPLATE.format(tmp=tmp_path) + extra_config, encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["main.py", "--config", str(cfg_path)])
    main.main()
    return captured


def test_full_run_passes_essentials_when_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With an [essentials] table, generate receives the Essentials block as a dict."""
    extra = f'\n[essentials]\npath = "{_DATASET_PATH}"\n'
    captured = _run_full(tmp_path, monkeypatch, extra)
    assert isinstance(captured["essentials"], dict)
    assert captured["essentials"]["dataset"]
    assert captured["essentials"]["finding_actions"] == []


def test_full_run_passes_none_when_not_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without an [essentials] table, generate receives essentials=None."""
    captured = _run_full(tmp_path, monkeypatch, "")
    assert "essentials" in captured
    assert captured["essentials"] is None
