"""
Tests for the ASD Essentials report section and the essentials JSON block.

No network, no LLM. The end-to-end test uses the committed dataset.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from ravensight import essentials_scorer, reporter
from ravensight.reporter import MAX_FINDING_LABEL_CHARS, Reporter
from tests.test_reporter_findings import _cluster

_FIXED_NOW = datetime(2026, 10, 15, 9, 30, 15, tzinfo=timezone.utc)
_DATASET_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "defaults" / "essentials_enterprise_it.json"
)
_SECTION_HEADING = "## ASD Essentials for enterprise IT"


class _FrozenDatetime:
    """Stand-in for the datetime class whose now() always returns a fixed time."""

    @staticmethod
    def now(tz: Any = None) -> datetime:
        """Return the fixed time, ignoring the timezone argument."""
        return _FIXED_NOW


@pytest.fixture(autouse=True)
def _freeze_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Freeze the reporter clock so rendered reports are comparable."""
    monkeypatch.setattr(reporter, "datetime", _FrozenDatetime)


def _reporter(tmp_path: Path) -> Reporter:
    """Build a Reporter writing into the given temporary directory."""
    return Reporter({"output_dir": str(tmp_path), "overwrite": True})


def _dataset() -> dict[str, Any]:
    """Build a tiny dataset with a source block and two principles."""
    return {
        "schema_version": 1,
        "source": {
            "attribution": "© Commonwealth of Australia 2026",
            "licence": "CC BY 4.0",
            "notice": "UNOFFICIAL test notice.",
        },
        "actions": [
            {"id": "A1", "principle": {"id": "P1", "name": "First principle"}},
            {"id": "A2", "principle": {"id": "P2", "name": "Second principle"}},
        ],
    }


def _action(
    action_id: str,
    principle_id: str,
    phase: int | None = 1,
    reasons: list[dict[str, Any]] | None = None,
    name: str = "Name",
) -> dict[str, Any]:
    """Build one action entry as map_findings_to_actions returns it."""
    return {
        "action_id": action_id,
        "principle_id": principle_id,
        "principle_name": name,
        "domains": [{"name": "Dom", "priority_phase": phase}],
        "reasons": reasons
        if reasons is not None
        else [
            {
                "route": "mitre",
                "technique_id": "T1562.001",
                "technique_name": "Disable or Modify Tools",
                "via_parent": False,
                "list": "guide",
            }
        ],
    }


def _entry(finding_id: str, actions: list[dict[str, Any]], omitted: int = 0) -> dict[str, Any]:
    """Build one finding_actions entry."""
    return {"id": finding_id, "actions": actions, "omitted": omitted}


def _essentials(
    finding_actions: list[Any] | None = None, attestation: Any = None
) -> dict[str, Any]:
    """Build an essentials block around the tiny dataset."""
    return {
        "dataset": _dataset(),
        "finding_actions": finding_actions if finding_actions is not None else [],
        "attestation": attestation if attestation is not None else {},
    }


def _section(essentials: Any, findings: list[Any] | None = None) -> str:
    """Render just the Essentials section."""
    return reporter._render_essentials_section(essentials, findings or [])


def _rows(section: str) -> list[str]:
    """Return the pointer-table body rows of a section."""
    return [
        line
        for line in section.splitlines()
        if line.startswith("| C")
    ]


def _report(tmp_path: Path, essentials: Any = None, **kwargs: Any) -> str:
    """Build the full markdown report, passing essentials only when given."""
    rep = Reporter({"output_dir": str(tmp_path)})
    data = {"summary": "s", "findings": [_cluster(id="C1")]}
    if essentials is None:
        return rep._build_report(data, **kwargs)
    return rep._build_report(data, essentials=essentials, **kwargs)


# --- Absent or empty input leaves the report unchanged ---------------------------------


@pytest.mark.parametrize(
    "essentials",
    [{}, {"dataset": {}, "finding_actions": [], "attestation": {}}, {"dataset": None}, "text"],
)
def test_report_unchanged_without_usable_essentials(
    tmp_path: Path, essentials: Any
) -> None:
    """None, {} and an empty dataset leave the markdown byte-identical."""
    baseline = Reporter({"output_dir": str(tmp_path)})._build_report(
        {"summary": "s", "findings": [_cluster(id="C1")]}
    )
    with_arg = Reporter({"output_dir": str(tmp_path)})._build_report(
        {"summary": "s", "findings": [_cluster(id="C1")]}, essentials=essentials
    )
    assert with_arg == baseline
    assert _SECTION_HEADING not in with_arg
    assert "ASD Essentials" not in with_arg


def test_none_essentials_is_the_default(tmp_path: Path) -> None:
    """Passing essentials=None equals not passing it."""
    rep = Reporter({"output_dir": str(tmp_path)})
    data = {"summary": "s", "findings": []}
    assert rep._build_report(data, essentials=None) == rep._build_report(data)


# --- Section content --------------------------------------------------------------------


def test_section_heading_how_to_read_and_attribution() -> None:
    """The section has its heading, how-to-read wording and the attribution."""
    section = _section(_essentials())
    assert section.startswith(_SECTION_HEADING)
    assert "not a rating" in section
    assert "your own attestation" in section
    assert "unofficial" in section
    assert "© Commonwealth of Australia 2026" in section
    assert "CC BY 4.0" in section
    assert "not produced, endorsed or supported by ASD" in section


def test_section_avoids_forbidden_wording() -> None:
    """The section never uses pass, fail, compliant, score, percent or alignment wording."""
    findings = [_cluster(id="C1"), _cluster(id="C2")]
    actions = [_entry("C1", [_action("A1", "P1", 1, name="First principle")])]
    attestation = {"P1": {"status": "Attested", "reason": "Reviewed", "domains": ["Dom"]}}
    section = _section(_essentials(actions + [_entry("C2", [])], attestation), findings)
    lowered = section.lower()
    for word in ("pass", "fail", "compliant", "score", "aligned", "based on asd"):
        assert word not in lowered
    assert "%" not in section


def test_table_row_content() -> None:
    """One row carries the finding, principle, actions, phase and matched-on text."""
    actions = [
        _action("A1", "P1", 2, name="First principle"),
        _action(
            "A3",
            "P1",
            3,
            reasons=[
                {"route": "ism", "ism_id": "ISM-0001", "field": "e8_ism"},
                {"route": "keyword", "shared": ["logging", "audit"]},
            ],
            name="First principle",
        ),
    ]
    section = _section(_essentials([_entry("C1", actions)]), [_cluster(id="C1")])
    assert "| Finding | Principle | Actions | Priority phase | Matched on |" in section
    rows = _rows(section)
    assert len(rows) == 1
    assert rows[0].startswith("| C1 SSHD brute force attempts | P1 First principle | A1, A3 | Phase 2 |")
    assert "Disable or Modify Tools (T1562.001)" in rows[0]
    assert "ISM-0001" in rows[0]
    assert "audit, logging" in rows[0]


def test_table_shows_typical_rule_description_whole() -> None:
    """A 68-character Wazuh rule description is not cut in the Finding cell."""
    title = "Listened ports status (netstat) changed (new port opened or closed)."
    assert len(title) == 68
    section = _section(
        _essentials([_entry("C1", [_action("A1", "P1")])]),
        [_cluster(id="C1", description=title)],
    )
    rows = _rows(section)
    assert len(rows) == 1
    assert rows[0].startswith(f"| C1 {title} |")
    assert "…" not in rows[0]


def test_table_long_title_cut_at_word_boundary() -> None:
    """A title over the limit is cut at a word boundary within the limit."""
    title = "word " * (MAX_FINDING_LABEL_CHARS // 2)
    section = _section(
        _essentials([_entry("C1", [_action("A1", "P1")])]),
        [_cluster(id="C1", description=title)],
    )
    rows = _rows(section)
    assert len(rows) == 1
    cell = rows[0].split("|")[1].strip()
    assert cell.endswith("word…")
    assert len(cell.removeprefix("C1 ")) <= MAX_FINDING_LABEL_CHARS
    assert len(cell.removeprefix("C1 ")) > 60


def _mitre_reason(tid: str, name: str, via_parent: bool) -> dict[str, Any]:
    """Build one MITRE reason."""
    return {
        "route": "mitre",
        "technique_id": tid,
        "technique_name": name,
        "via_parent": via_parent,
        "list": "guide",
    }


def _matched_row(actions: list[dict[str, Any]]) -> str:
    """Render one finding's actions and return its table row."""
    section = _section(_essentials([_entry("C1", actions)]), [_cluster(id="C1")])
    return _rows(section)[0]


def test_via_parent_reads_parent_of() -> None:
    """A parent match names the finding's own technique id as the child."""
    reason = _mitre_reason("T1070.004", "Indicator Removal", True)
    row = _matched_row([_action("A1", "P1", reasons=[reason])])
    assert "Indicator Removal (parent of T1070.004)" in row
    assert "Indicator Removal (T1070.004)" not in row


def test_direct_match_keeps_plain_wording() -> None:
    """via_parent False still renders Name (Tid)."""
    reason = _mitre_reason("T1070.004", "Indicator Removal", False)
    row = _matched_row([_action("A1", "P1", reasons=[reason])])
    assert "Indicator Removal (T1070.004)" in row
    assert "parent of" not in row


@pytest.mark.parametrize("name,tid", [("Indicator Removal", ""), ("", "T1070.004")])
def test_via_parent_with_one_value_shows_it_alone(name: str, tid: str) -> None:
    """With only a name or only an id the value shows alone."""
    reason = _mitre_reason(tid, name, True)
    row = _matched_row([_action("A1", "P1", reasons=[reason])])
    assert (name or tid) in row
    assert "parent of" not in row


def test_direct_and_parent_reasons_are_distinct_entries() -> None:
    """A direct and a parent reason for one action give two entries, no duplicates."""
    reasons = [
        _mitre_reason("T1070.004", "File Deletion", False),
        _mitre_reason("T1070.004", "Indicator Removal", True),
    ]
    row = _matched_row([_action("A1", "P1", reasons=reasons)])
    assert row.count("File Deletion (T1070.004)") == 1
    assert row.count("Indicator Removal (parent of T1070.004)") == 1


def test_matched_on_is_deduplicated() -> None:
    """The same technique or ISM id across actions is listed once."""
    actions = [_action("A1", "P1"), _action("A2", "P1")]
    section = _section(_essentials([_entry("C1", actions)]), [_cluster(id="C1")])
    assert _rows(section)[0].count("T1562.001") == 1


def test_keyword_words_are_capped() -> None:
    """Keyword words are capped at MAX_MATCHED_WORDS."""
    words = [f"word{i:02d}" for i in range(reporter.MAX_MATCHED_WORDS + 4)]
    actions = [_action("A1", "P1", reasons=[{"route": "keyword", "shared": words}])]
    row = _rows(_section(_essentials([_entry("C1", actions)]), [_cluster(id="C1")]))[0]
    assert f"word{reporter.MAX_MATCHED_WORDS - 1:02d}" in row
    assert f"word{reporter.MAX_MATCHED_WORDS:02d}" not in row


def test_phase_ordering_and_all_phases() -> None:
    """Rows go phase 1, 2, 3, then All phases, then by principle id."""
    actions = [
        _action("A9", "P9", None, name="Capability"),
        _action("A3", "P3", 3, name="Three"),
        _action("A2", "P2", 2, name="Two"),
        _action("A5", "P5", 1, name="Five"),
        _action("A1", "P1", 1, name="One"),
    ]
    section = _section(_essentials([_entry("C1", actions)]), [_cluster(id="C1")])
    rows = _rows(section)
    assert [r.split("|")[2].split()[0] for r in rows] == ["P1", "P5", "P2", "P3", "P9"]
    assert "Phase 1" in rows[0]
    assert "All phases" in rows[4]


def test_phase_is_lowest_across_domains() -> None:
    """A principle shows the lowest integer phase among its actions' domains."""
    action = _action("A1", "P1", 3)
    action["domains"].append({"name": "Other", "priority_phase": 1})
    action["domains"].append({"name": "Cap", "priority_phase": None})
    row = _rows(_section(_essentials([_entry("C1", [action])]), [_cluster(id="C1")]))[0]
    assert "Phase 1" in row


def test_findings_in_id_order() -> None:
    """Findings appear C2 before C10."""
    entries = [_entry("C10", [_action("A1", "P1")]), _entry("C2", [_action("A1", "P1")])]
    findings = [_cluster(id="C10"), _cluster(id="C2")]
    rows = _rows(_section(_essentials(entries), findings))
    assert [r.split()[1] for r in rows] == ["C2", "C10"]


def test_omitted_actions_text() -> None:
    """A finding with omitted actions shows the count once, on its last row."""
    actions = [_action("A1", "P1", 1), _action("A2", "P2", 2)]
    section = _section(_essentials([_entry("C1", actions, omitted=3)]), [_cluster(id="C1")])
    assert section.count("+3 more actions not shown") == 1
    assert "+3 more actions not shown" in _rows(section)[-1]
    single = _section(_essentials([_entry("C1", actions, omitted=1)]), [_cluster(id="C1")])
    assert "+1 more action not shown" in single


def test_row_cap_keeps_highest_severity_and_lists_unmatched() -> None:
    """Over the cap, high-severity findings stay, extras are counted and unmatched ones listed."""
    count = reporter.MAX_POINTER_ROWS + 2
    findings = [_cluster(id=f"C{i}", severity="Low") for i in range(1, count + 1)]
    findings.append(_cluster(id="C99", severity="High"))
    findings.append(_cluster(id="C100", severity="High"))
    entries = [_entry(f["id"], [_action("A1", "P1")]) for f in findings[:-1]]
    entries.append(_entry("C100", []))
    section = _section(_essentials(entries), findings)
    rows = _rows(section)
    assert len(rows) == reporter.MAX_POINTER_ROWS
    assert any(r.startswith("| C99 ") for r in rows)
    assert "3 more findings with pointers not shown (highest severity first)." in section
    assert "No pointers for: C100." in section


def test_single_hidden_finding_is_singular() -> None:
    """One hidden finding uses the singular noun."""
    count = reporter.MAX_POINTER_ROWS + 1
    findings = [_cluster(id=f"C{i}") for i in range(1, count + 1)]
    entries = [_entry(f["id"], [_action("A1", "P1")]) for f in findings]
    section = _section(_essentials(entries), findings)
    assert "1 more finding with pointers not shown (highest severity first)." in section


def test_no_pointers_line() -> None:
    """With no matches the table is replaced by a single line."""
    section = _section(_essentials([_entry("C1", []), _entry("C2", [])]), [_cluster(id="C1")])
    assert "> No Essentials pointers matched the 2 findings in this run." in section
    assert "| Finding |" not in section


def test_declared_ratings_table() -> None:
    """Declared ratings appear in dataset order with names, domains and reasons."""
    attestation = {
        "P1": {"status": "Not assessed", "reason": "", "domains": []},
        "P2": {"status": "Attested", "reason": "Reviewed in May", "domains": ["Dom", "Other"]},
        "P7": {"status": "Not applicable", "reason": "", "domains": []},
    }
    section = _section(_essentials(attestation=attestation))
    assert "These ratings are your own declarations." in section
    assert "| Principle | Rating | Domains | Reason |" in section
    assert "| P2 Second principle | Attested | Dom, Other | Reviewed in May |" in section
    assert "| P7 | Not applicable | — | — |" in section
    assert "P1 First principle |" not in section
    assert "No ratings declared" not in section


def test_no_ratings_declared_lines() -> None:
    """All-default and empty attestations give the no-ratings lines."""
    default = {"P1": {"status": "Not assessed"}, "P2": {"status": "Not assessed"}}
    assert "> No ratings declared. All 2 principles are Not assessed." in _section(
        _essentials(attestation=default)
    )
    assert "> No ratings declared. Every principle is Not assessed." in _section(_essentials())
    bad = _essentials()
    bad["attestation"] = "nonsense"
    assert "> No ratings declared. Every principle is Not assessed." in _section(bad)


def test_reason_is_sanitised() -> None:
    """Pipes and newlines in a reason cannot break the table."""
    attestation = {"P1": {"status": "Attested", "reason": "a | b\nc\n\nd", "domains": []}}
    section = _section(_essentials(attestation=attestation))
    row = next(line for line in section.splitlines() if line.startswith("| P1 "))
    assert row.endswith("| a \\| b c d |")


def test_malformed_pieces_never_raise() -> None:
    """Odd shapes in finding_actions, actions and attestation are skipped without raising."""
    bad_entries: list[Any] = [
        None,
        "C1",
        {"id": 5, "actions": []},
        {"id": "C1", "actions": "nope", "omitted": "x"},
        {"id": "C2", "actions": [None, "x", {"principle_id": 3}, {"principle_id": "P1"}]},
        {
            "id": "C3",
            "actions": [
                {
                    "principle_id": "P1",
                    "domains": "x",
                    "reasons": [None, {"route": "mitre"}, {"route": "keyword", "shared": 5}, {"route": "zzz"}],
                }
            ],
        },
    ]
    attestation = {"P1": "text", "P2": {"status": 5}, "P3": {"status": "Attested", "domains": "x", "reason": None}}
    section = _section(_essentials(bad_entries, attestation), [None, "x", {"id": 3}, _cluster(id="C3")])
    assert section.startswith(_SECTION_HEADING)
    assert "| P3 | Attested | — | — |" in section
    assert _section({"dataset": {"actions": 5}, "finding_actions": 5, "attestation": 5}, "bad")  # type: ignore[arg-type]
    assert _section(None) == ""
    assert _section({"dataset": []}) == ""


# --- Glossary ---------------------------------------------------------------------------


def test_glossary_entries_only_with_section(tmp_path: Path) -> None:
    """Essentials glossary terms appear only when the section is present."""
    without = _report(tmp_path)
    assert "**ASD Essentials**" not in without
    assert "**Priority phase**" not in without
    with_section = _report(tmp_path, _essentials())
    assert "**ASD Essentials**" in with_section
    assert "**Principle and action**" in with_section
    assert "**Priority phase**" in with_section
    assert "Australian Signals Directorate" in with_section


def test_asd_framework_glossary_entry_unaffected(tmp_path: Path) -> None:
    """The ASD glossary entry is keyed on the Framework heading, not the Essentials one."""
    only_essentials = _report(tmp_path, _essentials())
    assert "- **ASD**:" not in only_essentials
    framework = "## ASD Framework\n"
    assert re.search(r"## ASD Framework", framework)
    assert not re.search(r"## ASD Framework", _SECTION_HEADING)
    pattern = next(p for t, _m, p in reporter._GLOSSARY if t == "ASD")
    assert pattern == r"## ASD Framework"


def test_section_follows_asd_framework_and_precedes_trends(tmp_path: Path) -> None:
    """The section sits after the ASD Framework block and before trends."""
    text = _report(tmp_path, _essentials(), trends="## Trends\n\nstuff", asd_data={})
    assert text.index("## ASD Framework") < text.index(_SECTION_HEADING) < text.index("## Trends")
    assert text.index("## Trends") < text.index("## Recommendations")


# --- JSON -------------------------------------------------------------------------------


def _load(path: Path) -> dict[str, Any]:
    """Read the JSON file that sits beside a markdown report path."""
    return json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))


def test_json_essentials_null_when_absent(tmp_path: Path) -> None:
    """The essentials key is always present and null without a usable block."""
    rep = _reporter(tmp_path)
    data = {"summary": "s", "findings": []}
    for value in (None, {}, {"dataset": {}}):
        payload = _load(rep.generate(data, essentials=value))
        assert "essentials" in payload
        assert payload["essentials"] is None
        assert payload["schema_version"] == 2


def test_json_essentials_filled(tmp_path: Path) -> None:
    """A usable block is written with source details, actions and attestation."""
    actions = [_entry("C1", [_action("A1", "P1")])]
    attestation = {"P1": {"status": "Attested", "reason": "r", "domains": ["Dom"]}}
    path = _reporter(tmp_path).generate(
        {"summary": "s", "findings": [_cluster(id="C1")]},
        essentials=_essentials(actions, attestation),
    )
    block = _load(path)["essentials"]
    assert block["attribution"] == "© Commonwealth of Australia 2026"
    assert block["licence"] == "CC BY 4.0"
    assert block["notice"] == "UNOFFICIAL test notice."
    assert block["dataset_schema_version"] == 1
    assert block["finding_actions"] == actions
    assert block["attestation"] == attestation
    assert "attestation" not in _load(path)
    assert _SECTION_HEADING in path.read_text(encoding="utf-8")


def test_json_essentials_wrong_types_use_empty_values() -> None:
    """Wrong-typed finding_actions and attestation become [] and {}."""
    block = reporter._json_essentials(
        {"dataset": _dataset(), "finding_actions": "x", "attestation": []}
    )
    assert block is not None
    assert block["finding_actions"] == []
    assert block["attestation"] == {}


def test_existing_e8_attestation_key_unchanged(tmp_path: Path) -> None:
    """The E8 attestation key keeps its place beside the essentials key."""
    path = _reporter(tmp_path).generate(
        {"summary": "s", "findings": []},
        attestation={"Patch applications": {"status": "Attested", "level": 2, "reason": "r"}},
        essentials=_essentials(),
    )
    payload = _load(path)
    assert payload["attestation"]["Patch applications"]["level"] == 2
    assert payload["essentials"]["attestation"] == {}


# --- Constants and source block ---------------------------------------------------------


def test_constants_match_committed_dataset() -> None:
    """The fallback constants equal the committed dataset's source values."""
    source = json.loads(_DATASET_PATH.read_text(encoding="utf-8"))["source"]
    assert reporter.ESSENTIALS_ATTRIBUTION == source["attribution"]
    assert reporter.ESSENTIALS_LICENCE == source["licence"]
    assert reporter.ESSENTIALS_NOTICE == source["notice"]


@pytest.mark.parametrize(
    "dataset",
    [
        {},
        {"source": None},
        {"source": {}},
        {"source": {"attribution": 5, "licence": ["x"], "notice": "  "}},
        None,
        "text",
    ],
)
def test_essentials_source_falls_back_to_constants(dataset: Any) -> None:
    """A missing or non-str source value falls back to the constants."""
    assert reporter._essentials_source(dataset) == {
        "attribution": reporter.ESSENTIALS_ATTRIBUTION,
        "licence": reporter.ESSENTIALS_LICENCE,
        "notice": reporter.ESSENTIALS_NOTICE,
    }


def test_essentials_source_uses_dataset_values() -> None:
    """Valid str values in the source block win over the constants."""
    dataset = {"source": {"attribution": "A", "licence": "L", "notice": "N"}}
    assert reporter._essentials_source(dataset) == {
        "attribution": "A",
        "licence": "L",
        "notice": "N",
    }


# --- End to end with the committed dataset ----------------------------------------------


def test_end_to_end_with_committed_dataset(tmp_path: Path) -> None:
    """The real dataset, a tiny technique map and an attestation give a full section."""
    dataset = essentials_scorer.load_essentials(str(_DATASET_PATH))
    assert dataset
    finding = _cluster(id="C1", mitre_ids=["T1562.001"])
    names = {"T1562": "Impair Defenses", "T1562.001": "Disable or Modify Tools"}
    finding_actions = essentials_scorer.map_findings_to_actions([finding], dataset, names)
    attest_file = tmp_path / "attest.json"
    attest_file.write_text(
        json.dumps({"DET-01": {"status": "Partially effective", "reason": "Quarterly review"}}),
        encoding="utf-8",
    )
    attestation = essentials_scorer.load_essentials_attestation(str(attest_file), dataset)
    essentials = {
        "dataset": dataset,
        "finding_actions": finding_actions,
        "attestation": attestation,
    }
    path = _reporter(tmp_path / "out").generate(
        {"summary": "s", "findings": [finding]}, essentials=essentials
    )
    text = path.read_text(encoding="utf-8")
    assert _SECTION_HEADING in text
    assert "IT.DET-01.1" in text
    assert "DET-01" in text
    assert "Phase" in text
    assert "Quarterly review" in text
    payload = _load(path)
    assert payload["essentials"]["attestation"]["DET-01"]["status"] == "Partially effective"
    assert payload["essentials"]["dataset_schema_version"] == dataset.get("schema_version")
