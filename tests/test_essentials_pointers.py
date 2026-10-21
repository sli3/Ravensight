"""Tests for build_technique_names and map_findings_to_actions."""
from pathlib import Path
from typing import Any

from ravensight.essentials_scorer import (
    MAX_ESSENTIALS_ACTIONS,
    build_technique_names,
    load_essentials,
    map_findings_to_actions,
)

DATASET = Path(__file__).resolve().parents[1] / "data" / "defaults" / "essentials_enterprise_it.json"

NAMES = {
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1070": "Indicator Removal",
}


def _action(action_id: str, **extra: Any) -> dict:
    """Build a small hand-made action."""
    action = {
        "id": action_id,
        "action_text": "",
        "domains": ["Detection", "Capability X"],
        "mitre_technique_names": [],
        "mitre_technique_names_chapter": [],
        "references": {"ism_excl_e8": [], "e8_ism": []},
        "principle": {"id": "DET-01", "name": "Detect things"},
    }
    action.update(extra)
    return action


def _essentials(*actions: dict) -> dict:
    """Wrap actions in a minimal dataset with two domains."""
    return {
        "domains": [
            {"name": "Detection", "priority_phase": 2},
            {"name": "Capability X", "priority_phase": None},
        ],
        "actions": list(actions),
    }


def _one(findings: list, essentials: dict, ism: list | None = None) -> dict:
    """Map findings and return the first result."""
    return map_findings_to_actions(findings, essentials, NAMES, ism)[0]


def _keys(obj: Any) -> list[str]:
    """Collect every dict key recursively."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            out.extend(_keys(v))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_keys(item))
    return out


def test_build_technique_names_combines_sections() -> None:
    """Techniques and sub-techniques both appear."""
    data = {
        "techniques": [{"id": "T1", "name": "A"}],
        "subtechniques": [{"id": "T1.001", "name": "B"}],
    }
    assert build_technique_names(data) == {"T1": "A", "T1.001": "B"}


def test_build_technique_names_skips_malformed() -> None:
    """Malformed entries and sections are skipped."""
    data = {
        "techniques": ["x", {"id": "", "name": "A"}, {"id": "T2", "name": " "},
                       {"id": 3, "name": "A"}, {"id": "T4", "name": "Ok"}],
        "subtechniques": "nope",
    }
    assert build_technique_names(data) == {"T4": "Ok"}


def test_build_technique_names_non_dict() -> None:
    """Non-dict input gives an empty map."""
    assert build_technique_names(None) == {}
    assert build_technique_names([]) == {}


def test_mitre_direct_match() -> None:
    """A direct technique name match gives a guide reason."""
    ess = _essentials(_action("IT.DET-01.1", mitre_technique_names=["Indicator Removal"]))
    res = _one([{"id": "f1", "mitre_ids": ["T1070"]}], ess)
    assert res["id"] == "f1"
    assert res["omitted"] == 0
    assert res["actions"][0]["reasons"] == [{
        "route": "mitre", "technique_id": "T1070", "technique_name": "Indicator Removal",
        "via_parent": False, "list": "guide",
    }]


def test_mitre_parent_rollup() -> None:
    """A sub-technique rolls up to its parent on the chapter list."""
    ess = _essentials(_action("IT.DET-01.1", mitre_technique_names_chapter=["Impair Defenses"]))
    res = _one([{"id": "f1", "mitre_ids": ["T1562.001"]}], ess)
    assert res["actions"][0]["reasons"] == [{
        "route": "mitre", "technique_id": "T1562.001", "technique_name": "Impair Defenses",
        "via_parent": True, "list": "chapter",
    }]


def test_mitre_case_insensitive() -> None:
    """Name comparison ignores case."""
    ess = _essentials(_action("IT.DET-01.1", mitre_technique_names=["indicator REMOVAL"]))
    res = _one([{"id": "f1", "mitre_ids": ["T1070"]}], ess)
    assert len(res["actions"]) == 1


def test_mitre_guide_and_chapter_separate() -> None:
    """Guide and chapter matches are reported as separate reasons."""
    ess = _essentials(_action(
        "IT.DET-01.1",
        mitre_technique_names=["Indicator Removal"],
        mitre_technique_names_chapter=["Indicator Removal"],
    ))
    res = _one([{"id": "f1", "mitre_ids": ["T1070"]}], ess)
    assert [r["list"] for r in res["actions"][0]["reasons"]] == ["guide", "chapter"]


def test_mitre_unknown_id_adds_nothing() -> None:
    """Unknown technique ids add no actions."""
    ess = _essentials(_action("IT.DET-01.1", mitre_technique_names=["Indicator Removal"]))
    assert _one([{"id": "f1", "mitre_ids": ["T9999"]}], ess)["actions"] == []


def test_mitre_missing_or_bad_ids() -> None:
    """Missing, non-list or non-str mitre_ids never raise."""
    ess = _essentials(_action("IT.DET-01.1", mitre_technique_names=["Indicator Removal"]))
    assert _one([{"id": "f1"}], ess)["actions"] == []
    assert _one([{"id": "f1", "mitre_ids": "T1070"}], ess)["actions"] == []
    res = _one([{"id": "f1", "mitre_ids": [5, None, "T1070"]}], ess)
    assert len(res["actions"]) == 1


def test_ism_route_each_field() -> None:
    """ISM ids match both reference fields."""
    ess = _essentials(_action(
        "IT.DET-01.1",
        references={"ism_excl_e8": ["ISM-1985"], "e8_ism": ["ISM-1815"]},
    ))
    ism = [{"id": "f1", "ism": [{"id": "ISM-1985"}, {"id": "ISM-1815"}]}]
    reasons = _one([{"id": "f1"}], ess, ism)["actions"][0]["reasons"]
    assert {"route": "ism", "ism_id": "ISM-1985", "field": "ism_excl_e8"} in reasons
    assert {"route": "ism", "ism_id": "ISM-1815", "field": "e8_ism"} in reasons


def test_ism_malformed_pointers_never_raise() -> None:
    """Malformed ism_pointers are ignored."""
    ess = _essentials(_action("IT.DET-01.1", references={"ism_excl_e8": ["ISM-1985"]}))
    bad = ["x", {"ism": []}, {"id": "f1", "ism": "no"},
           {"id": "f1", "ism": [5, {"id": 7}, {"nope": 1}]}, {"id": "other", "ism": [{"id": "ISM-1985"}]}]
    assert _one([{"id": "f1"}], ess, bad)["actions"] == []
    assert _one([{"id": "f1"}], ess, "junk")["actions"] == []  # type: ignore[arg-type]


def test_keyword_threshold() -> None:
    """Two shared words do not match, three do."""
    ess = _essentials(_action("IT.DET-01.1", action_text="Forward firewall logs centrally"))
    two = {"id": "f1", "description": "firewall logs", "recommendation": ""}
    three = {"id": "f2", "description": "firewall logs", "recommendation": "forward them"}
    assert _one([two], ess)["actions"] == []
    res = _one([three], ess)
    assert res["actions"][0]["reasons"] == [
        {"route": "keyword", "shared": ["firewall", "forward", "logs"]}
    ]


def test_keyword_generic_words_do_not_count() -> None:
    """Generic words are ignored by the keyword route."""
    ess = _essentials(_action("IT.DET-01.1", action_text="Monitor access logs firewall"))
    f = {"id": "f1", "description": "monitor access logs firewall", "recommendation": ""}
    assert _one([f], ess)["actions"] == []


def test_keyword_only_when_no_mitre_or_ism() -> None:
    """Keyword matches are dropped when a MITRE match exists."""
    ess = _essentials(
        _action("IT.DET-01.1", mitre_technique_names=["Indicator Removal"]),
        _action("IT.DET-01.2", action_text="Forward firewall logs centrally"),
    )
    f = {"id": "f1", "mitre_ids": ["T1070"], "description": "firewall logs forward"}
    res = _one([f], ess)
    assert [a["action_id"] for a in res["actions"]] == ["IT.DET-01.1"]


def test_keyword_suppressed_by_ism_only_match() -> None:
    """An ISM-only match also suppresses the keyword route."""
    ess = _essentials(
        _action("IT.DET-01.1", references={"ism_excl_e8": ["ISM-1985"]}),
        _action("IT.DET-01.2", action_text="Forward firewall logs centrally"),
    )
    ism = [{"id": "f1", "ism": [{"id": "ISM-1985"}]}]
    f = {"id": "f1", "description": "firewall logs", "recommendation": "forward them"}
    res = _one([f], ess, ism)
    assert [a["action_id"] for a in res["actions"]] == ["IT.DET-01.1"]


def test_mitre_non_str_names_never_raise() -> None:
    """Non-str or None technique names add no candidates and never raise."""
    ess = _essentials(_action("IT.DET-01.1", mitre_technique_names=["Indicator Removal"]))
    names = {"T1070": 5, "T1562": None}
    f = {"id": "f1", "mitre_ids": ["T1070", "T1562.001"]}
    res = map_findings_to_actions([f], ess, names)[0]
    assert res["actions"] == []


def test_non_list_findings_return_empty() -> None:
    """Non-list findings give an empty result."""
    ess = _essentials(_action("IT.DET-01.1"))
    assert map_findings_to_actions(None, ess, NAMES) == []  # type: ignore[arg-type]


def test_mitre_parent_same_name_gives_one_reason() -> None:
    """A parent with the same name as the sub-technique adds no duplicate reason."""
    ess = _essentials(_action("IT.DET-01.1", mitre_technique_names=["Same Name"]))
    names = {"T9999": "Same Name", "T9999.001": "same name"}
    f = {"id": "f1", "mitre_ids": ["T9999.001"]}
    res = map_findings_to_actions([f], ess, names)[0]
    reasons = res["actions"][0]["reasons"]
    assert len(reasons) == 1
    assert reasons[0]["via_parent"] is False


def test_skips_bad_findings_and_empty_essentials() -> None:
    """Findings without str ids and plain strings are skipped."""
    ess = _essentials(_action("IT.DET-01.1"))
    out = map_findings_to_actions(["text", {"x": 1}, {"id": 4}, {"id": "ok"}], ess, NAMES)
    assert [r["id"] for r in out] == ["ok"]
    assert map_findings_to_actions([{"id": "a"}], {}, NAMES) == []
    assert map_findings_to_actions([{"id": "a"}], {"actions": "no"}, NAMES) == []


def test_ordering() -> None:
    """More reasons first, then route strength, then action id."""
    ess = _essentials(
        _action("IT.DET-01.3", references={"e8_ism": ["ISM-1"]}),
        _action("IT.DET-01.2", mitre_technique_names=["Indicator Removal"]),
        _action("IT.DET-01.1", mitre_technique_names=["Indicator Removal"]),
        _action("IT.DET-01.4", mitre_technique_names=["Indicator Removal"],
                references={"e8_ism": ["ISM-1"]}),
    )
    ism = [{"id": "f1", "ism": [{"id": "ISM-1"}]}]
    res = _one([{"id": "f1", "mitre_ids": ["T1070"]}], ess, ism)
    assert [a["action_id"] for a in res["actions"]] == [
        "IT.DET-01.4", "IT.DET-01.1", "IT.DET-01.2", "IT.DET-01.3",
    ]


def test_cap_and_omitted() -> None:
    """Seven matches keep five and report two omitted."""
    ess = _essentials(*[
        _action(f"IT.DET-01.{i}", mitre_technique_names=["Indicator Removal"])
        for i in range(1, 8)
    ])
    res = _one([{"id": "f1", "mitre_ids": ["T1070"]}], ess)
    assert len(res["actions"]) == MAX_ESSENTIALS_ACTIONS == 5
    assert res["omitted"] == 2


def test_domains_carry_priority_phase() -> None:
    """Domains carry phases, None for capability or unknown names."""
    ess = _essentials(_action("IT.DET-01.1", mitre_technique_names=["Indicator Removal"],
                              domains=["Detection", "Capability X", "Unknown"]))
    res = _one([{"id": "f1", "mitre_ids": ["T1070"]}], ess)
    assert res["actions"][0]["domains"] == [
        {"name": "Detection", "priority_phase": 2},
        {"name": "Capability X", "priority_phase": None},
        {"name": "Unknown", "priority_phase": None},
    ]


def test_no_rating_wording_in_keys() -> None:
    """No output key suggests a rating."""
    ess = _essentials(_action("IT.DET-01.1", mitre_technique_names=["Indicator Removal"],
                              igp={"fully_effective": "x"}))
    out = map_findings_to_actions([{"id": "f1", "mitre_ids": ["T1070"]}], ess, NAMES)
    for key in _keys(out):
        for word in ("status", "rating", "effective", "score"):
            assert word not in key.lower()


def test_committed_dataset() -> None:
    """A sub-technique finding points at IT.DET-01.1 in the real dataset."""
    ess = load_essentials(str(DATASET))
    names = {"T1562": "Impair Defenses", "T1562.001": "Disable or Modify Tools"}
    out = map_findings_to_actions([{"id": "f1", "mitre_ids": ["T1562.001"]}], ess, names)
    action = next(a for a in out[0]["actions"] if a["action_id"] == "IT.DET-01.1")
    reasons = action["reasons"]
    assert any(r["list"] == "guide" and r["technique_name"] == "Disable or Modify Tools"
               for r in reasons)
    assert any(r["list"] == "chapter" and r["technique_name"] == "Impair Defenses"
               and r["via_parent"] is True for r in reasons)
    assert action["domains"]
    assert any(isinstance(d["priority_phase"], int) for d in action["domains"])
