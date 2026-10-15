"""
Tests for dict-aware report rendering (Build 1b).

No network — reports are built in-memory via Reporter._build_report.
"""

import re
from pathlib import Path
from typing import Any

import pytest

from ravensight import reporter
from ravensight.evidence import truncate_words
from ravensight.reporter import REPORT_MAX_CVES, Reporter


def _cluster(**overrides: Any) -> dict[str, Any]:
    """Build a cluster finding dict with sensible defaults."""
    finding: dict[str, Any] = {
        "id": "C3",
        "type": "rule",
        "description": "SSHD brute force attempts",
        "rule_ids": ["5710"],
        "hosts": ["host-1", "host-2"],
        "count": 174,
        "max_level": 12,
        "severity": "High",
        "first_seen": "2026-09-24T08:15:00.000Z",
        "last_seen": "2026-09-24T10:30:00.000Z",
        "cves": [],
        "package": None,
        "narrative": "Repeated password guessing from external addresses.",
        "recommendation": "Enforce key-only authentication.",
    }
    finding.update(overrides)
    return finding


def _make_reporter(tmp_path: Path) -> Reporter:
    return Reporter({"output_dir": str(tmp_path)})


def test_dict_finding_renders_data_fields(tmp_path: Path) -> None:
    """Dict findings render severity, id, count, hosts and trimmed timestamps."""
    rep = _make_reporter(tmp_path)
    report = rep._build_report({"summary": "s", "findings": [_cluster()]})
    assert "- **[C3] High** — SSHD brute force attempts — 174 alerts" in report
    assert "on host-1, host-2 (2026-09-24 08:15 → 2026-09-24 10:30 UTC)" in report
    assert "  - Repeated password guessing from external addresses." in report
    # no Python repr artefacts
    assert "{' '" not in report
    assert '"}' not in report
    assert "'host-1'" not in report


def test_legacy_string_finding_unchanged(tmp_path: Path) -> None:
    """String findings render exactly as the private helper renders them today."""
    rep = _make_reporter(tmp_path)
    report = rep._build_report({"summary": "s", "findings": ["Plain string finding"]})
    assert reporter._format_finding("Plain string finding") == ["- Plain string finding"]
    assert "- Plain string finding" in report


def test_recommendations_derive_from_dict_findings(tmp_path: Path) -> None:
    """Recommendations carry the same [Cx] prefix as the finding lines."""
    rep = _make_reporter(tmp_path)
    data = {
        "summary": "s",
        "findings": [
            _cluster(id="C1"),
            _cluster(id="C2", recommendation="Patch the service."),
        ],
        "recommendations": ["ignored when dict findings present"],
    }
    report = rep._build_report(data)
    assert "- [C1] Enforce key-only authentication." in report
    assert "- [C2] Patch the service." in report
    assert "ignored when dict findings present" not in report


def test_unattached_recommendation_has_no_prefix(tmp_path: Path) -> None:
    """Unattached findings' recommendations render with no [Cx] prefix."""
    rep = _make_reporter(tmp_path)
    unattached = {
        "type": "unattached",
        "description": "Loose LLM note",
        "count": 0,
        "hosts": [],
        "severity": "",
        "narrative": "",
        "recommendation": "General hygiene advice",
    }
    report = rep._build_report({"summary": "s", "findings": [unattached]})
    assert "- General hygiene advice" in report
    assert "- [C" not in report.split("## Recommendations")[-1]


def test_unattached_label_rendered(tmp_path: Path) -> None:
    """Unattached findings use the explicit not-linked label."""
    rep = _make_reporter(tmp_path)
    unattached = _cluster(type="unattached", description="Loose LLM note")
    report = rep._build_report({"summary": "s", "findings": [unattached]})
    assert "- *LLM note, not linked to alert data:* Loose LLM note" in report


def test_full_report_smoke(tmp_path: Path) -> None:
    """A single dict finding plus recommendations builds a complete report."""
    rep = _make_reporter(tmp_path)
    data = {
        "summary": "2 alerts in 1 clusters across 1 hosts",
        "findings": [_cluster()],
        "recommendations": ["Enforce key-only authentication."],
    }
    report = rep._build_report(data)
    assert "# Security Report" in report
    assert "## Summary" in report
    assert "## Findings" in report
    assert "## Recommendations" in report
    assert "- **[C3] High**" in report
    assert "- [C3] Enforce key-only authentication." in report


def test_no_recommendations_placeholder(tmp_path: Path) -> None:
    """Empty recommendations render the placeholder."""
    finding = _cluster(recommendation="")
    rep = _make_reporter(tmp_path)
    report = rep._build_report({"summary": "s", "findings": [finding]})
    assert "*No recommendations*" in report


def test_cve_cap_in_report(tmp_path: Path) -> None:
    """CVE lists cap at REPORT_MAX_CVES with a (+N more) tail."""
    cves = [f"CVE-2026-{1000 + i}" for i in range(15)]
    finding = _cluster(type="vulnerability", cves=cves, package="openssl")
    rep = _make_reporter(tmp_path)
    report = rep._build_report({"summary": "s", "findings": [finding]})

    cve_line = next(
        line for line in report.splitlines() if line.strip().startswith("- CVEs:")
    )
    listed = cve_line.count("CVE-2026-")
    assert listed == REPORT_MAX_CVES == 10
    assert "(+5 more)" in cve_line


def test_no_time_clause_when_timestamps_missing() -> None:
    """Clusters with no timestamps omit the time clause entirely."""
    finding = _cluster(first_seen="", last_seen="")
    lines = reporter._format_finding(finding)
    assert "→" not in lines[0]
    assert "( → )" not in lines[0]
    assert "UTC" not in lines[0]


@pytest.mark.parametrize(
    ("first", "last", "clause"),
    [
        ("2026-09-24T08:15:00Z", "2026-09-24T10:30:00Z",
         "(2026-09-24 08:15 → 2026-09-24 10:30 UTC)"),
        ("2026-09-24T08:15:00+0000", "2026-09-24T10:30:00+0000",
         "(2026-09-24 08:15 → 2026-09-24 10:30 UTC)"),
        ("2026-09-24T08:15:00+00:00", "2026-09-24T10:30:00+00:00",
         "(2026-09-24 08:15 → 2026-09-24 10:30 UTC)"),
        ("2026-09-24T08:15:00Z", "2026-09-24T08:15:30Z",
         "(2026-09-24 08:15 UTC)"),
        ("2026-09-24T08:15:00+0000", "2026-09-24T08:15:30+0000",
         "(2026-09-24 08:15 UTC)"),
        ("2026-09-24T08:15:00+00:00", "2026-09-24T08:15:30+00:00",
         "(2026-09-24 08:15 UTC)"),
        ("2026-09-24T08:15:00Z", "", "(2026-09-24 08:15 →  UTC)"),
        ("", "2026-09-24T10:30:00Z", "( → 2026-09-24 10:30 UTC)"),
        ("2026-09-24T08:15:00+1030", "2026-09-24T10:30:00+1030",
         "(2026-09-24 08:15 → 2026-09-24 10:30)"),
        ("2026-09-24T08:15:00", "2026-09-24T10:30:00",
         "(2026-09-24 08:15 → 2026-09-24 10:30)"),
        ("2026-09-24T08:15:00Z", "2026-09-24T10:30:00+1030",
         "(2026-09-24 08:15 → 2026-09-24 10:30)"),
        ("2026-09-24T08:15:00+0000", "2026-09-24T10:30:00",
         "(2026-09-24 08:15 → 2026-09-24 10:30)"),
        ("2026-09-24T08:15:00-0000", "2026-09-24T10:30:00-00:00",
         "(2026-09-24 08:15 → 2026-09-24 10:30)"),
    ],
)
def test_utc_label_only_when_all_timestamps_utc(
    first: str, last: str, clause: str
) -> None:
    """The UTC label appears only when every non-empty raw timestamp is UTC."""
    lines = reporter._format_finding(_cluster(first_seen=first, last_seen=last))
    assert f"on host-1, host-2 {clause}" in lines[0]


def test_no_clause_and_no_utc_when_both_empty() -> None:
    """Both timestamps empty gives no time clause and no UTC label."""
    lines = reporter._format_finding(_cluster(first_seen="", last_seen=""))
    assert lines[0].endswith("on host-1, host-2")
    assert "UTC" not in lines[0]


@pytest.mark.parametrize(("count", "word"), [(1, "alert"), (2, "alerts")])
def test_singular_plural_alert_wording(
    tmp_path: Path, count: int, word: str
) -> None:
    """A count of one renders 'alert'; any other count renders 'alerts'."""
    rep = _make_reporter(tmp_path)
    report = rep._build_report({"summary": "s", "findings": [_cluster(count=count)]})
    assert f"— {count} {word} on host-1, host-2" in report


def test_single_timestamp_rendered_once(tmp_path: Path) -> None:
    """Equal first/last timestamps render once, without the arrow."""
    finding = _cluster(
        first_seen="2026-09-24T08:15:00.000Z",
        last_seen="2026-09-24T08:15:30.000Z",
    )
    lines = reporter._format_finding(finding)
    assert "(2026-09-24 08:15 UTC)" in lines[0]
    assert "→" not in lines[0]


def test_empty_unattached_description_produces_no_bullet(tmp_path: Path) -> None:
    """An unattached finding with no description renders no Findings bullet."""
    unattached = _cluster(type="unattached", description="", recommendation="Hygiene advice")
    rep = _make_reporter(tmp_path)
    report = rep._build_report({"summary": "s", "findings": [unattached]})
    assert "*LLM note, not linked to alert data:*" not in report
    recommendations = report.split("## Recommendations")[-1]
    assert "- Hygiene advice" in recommendations
    assert "[C" not in recommendations


def test_evidence_sub_bullet_renders(tmp_path: Path) -> None:
    """A finding with evidence renders one Evidence sub-bullet after the narrative."""
    finding = _cluster(
        evidence={
            "syscheck": {
                "paths": ["/etc/resolv.conf"],
                "events": ["modified"],
                "changed": ["inode", "mtime"],
                "content": "unchanged",
            }
        }
    )
    lines = reporter._format_finding(finding)
    evidence_lines = [line for line in lines if line.strip().startswith("- Evidence:")]
    assert len(evidence_lines) == 1
    assert evidence_lines[0] == (
        "  - Evidence: content unchanged; event modified; "
        "changed inode, mtime; paths /etc/resolv.conf"
    )
    # sub-bullet sits between the narrative line and any CVEs line
    narrative_idx = lines.index(
        "  - Repeated password guessing from external addresses."
    )
    assert lines.index(evidence_lines[0]) == narrative_idx + 1


def test_evidence_sub_bullet_before_cves(tmp_path: Path) -> None:
    """For vulnerability findings the Evidence line precedes the CVEs line."""
    finding = _cluster(
        type="vulnerability",
        package="openssl",
        cves=["CVE-2026-1234"],
        evidence={"vulnerability": {"statuses": {"Solved": 1}}},
    )
    lines = reporter._format_finding(finding)
    evidence_idx = next(
        i for i, line in enumerate(lines) if line.strip().startswith("- Evidence:")
    )
    cve_idx = next(
        i for i, line in enumerate(lines) if line.strip().startswith("- CVEs:")
    )
    assert evidence_idx < cve_idx
    assert "status Solved×1" in lines[evidence_idx]


def test_evidence_newlines_and_pipes_sanitised(tmp_path: Path) -> None:
    """Newlines collapse to spaces and pipes escape as '\\|' in the Evidence line."""
    finding = _cluster(
        evidence={"generic": {"srcips": ["192.0.2.1\n192.0.2.2 | evil"]}}
    )
    lines = reporter._format_finding(finding)
    evidence_line = next(
        line for line in lines if line.strip().startswith("- Evidence:")
    )
    assert "\n" not in evidence_line
    assert "192.0.2.1 192.0.2.2 \\| evil" in evidence_line


def test_finding_without_evidence_byte_identical(tmp_path: Path) -> None:
    """Findings without evidence render byte-identically to today."""
    assert reporter._format_finding(_cluster()) == reporter._format_finding(
        _cluster(evidence={})
    )
    expected = [
        (
            "- **[C3] High** — SSHD brute force attempts — 174 alerts "
            "on host-1, host-2 (2026-09-24 08:15 → 2026-09-24 10:30 UTC)"
        ),
        "  - Repeated password guessing from external addresses.",
    ]
    assert reporter._format_finding(_cluster()) == expected


def test_finding_with_notes_renders_note_lines() -> None:
    """Notes render as Note sub-bullets after the Evidence line, in order."""
    finding = _cluster(
        notes=["alpha", "beta"],
        evidence={"generic": {"srcips": ["192.0.2.1"]}},
    )
    lines = reporter._format_finding(finding)
    assert "  - Note: alpha" in lines
    assert "  - Note: beta" in lines
    assert lines.index("  - Note: alpha") < lines.index("  - Note: beta")
    evidence_idx = next(
        i for i, line in enumerate(lines) if line.strip().startswith("- Evidence:")
    )
    assert lines.index("  - Note: alpha") > evidence_idx


def test_finding_without_notes_no_note_lines() -> None:
    """Findings without notes render no Note sub-bullets."""
    lines = reporter._format_finding(_cluster())
    assert all("  - Note:" not in line for line in lines)


def test_finding_with_flags_renders_check_line() -> None:
    """Findings with fidelity flags render one Check sub-bullet after the notes."""
    finding = _cluster(flags=["T1100", "8443"], notes=["alpha"])
    lines = reporter._format_finding(finding)
    check_line = "  - Check: not in this cluster's evidence: T1100, 8443"
    assert check_line in lines
    assert lines.index(check_line) > lines.index("  - Note: alpha")


def test_finding_without_flags_no_check_line() -> None:
    """Findings without flags render no Check sub-bullet."""
    lines = reporter._format_finding(_cluster())
    assert all("  - Check:" not in line for line in lines)


def test_blank_line_before_mitre_tags_without_similar_incidents(
    tmp_path: Path,
) -> None:
    """MITRE heading is preceded by a blank line when no similar incidents exist."""
    rep = _make_reporter(tmp_path)
    data = {
        "summary": "s",
        "findings": [_cluster()],
        "mitre_tags": [{"tactic": "Defense Evasion", "description": "foo"}],
    }
    report = rep._build_report(data)
    lines = report.splitlines()
    idx = lines.index("## MITRE ATT&CK Tags")
    assert lines[idx - 1] == ""
    bullet_idx = next(i for i, line in enumerate(lines) if line.startswith("- **[C3]"))
    assert idx - bullet_idx >= 2


# --- ASD/ISM table cell sanitisation (Build 2a) ---


def test_ism_table_sanitises_newline_pipe_and_long_description() -> None:
    """ISM table rows are single-line, pipe-escaped and description-capped."""
    description = "Line one\nLine two " + "x" * 200
    control = {
        "id": "ISM-1175",
        "category": "A | B",
        "description": description,
    }
    section = reporter._render_asd_section(
        asd_data={"ism": [control]}, matched_controls=[control]
    )
    row_lines = [
        line for line in section.splitlines() if line.startswith("| ISM-1175")
    ]
    assert len(row_lines) == 1
    row = row_lines[0]
    assert "\n" not in row
    assert "A \\| B" in row
    assert "…" in row
    desc_cell = row.rsplit("|", 2)[1].strip()
    assert len(desc_cell) <= 120


def test_ism_table_description_exactly_120_chars_unchanged() -> None:
    """A description that collapses to exactly 120 chars needs no ellipsis."""
    description = "x" * 120
    control = {
        "id": "ISM-1175",
        "category": "Patching",
        "description": description,
    }
    section = reporter._render_asd_section(
        asd_data={"ism": [control]}, matched_controls=[control]
    )
    row = next(line for line in section.splitlines() if line.startswith("| ISM-1175"))
    desc_cell = row.rsplit("|", 2)[1].strip()
    assert "…" not in desc_cell
    assert len(desc_cell) == 120


def test_truncate_words_hard_cut_when_no_space() -> None:
    """truncate_words hard-cuts at limit-1 chars when no word boundary exists."""
    text = "a" * 130
    result = truncate_words(text, 120)
    assert len(result) == 120
    assert result.endswith("…")
    assert result.startswith("a" * 119)


def test_ism_fallback_table_sanitises_cells() -> None:
    """The no-match fallback ISM table gets the same cell treatment."""
    control = {
        "id": "ISM-0917",
        "category": "A | B",
        "description": "Line one\nLine two " + "word " * 60,
    }
    section = reporter._render_asd_section(asd_data={"ism": [control]})
    row_lines = [
        line for line in section.splitlines() if line.startswith("| ISM-0917")
    ]
    assert len(row_lines) == 1
    row = row_lines[0]
    assert "A \\| B" in row
    desc_cell = row.rsplit("|", 2)[1].strip()
    assert len(desc_cell) <= 120
    assert desc_cell.endswith("word…")


def test_truncate_words_no_space_before_ellipsis() -> None:
    """A word-boundary cut drops the boundary space."""
    assert truncate_words("aaa bbb ccc ddd", 10) == "aaa bbb…"


# --- Essential Eight related-controls table (Build 2b) ---


def _make_asd_data() -> dict[str, Any]:
    """Build ASD data with two strategies for reporter tests."""
    return {
        "essential_eight": [
            {
                "strategy": "Patch applications",
                "controls": [
                    {"id": "ISM-1690", "levels": [1, 2, 3], "description": "Patch apps"},
                    {"id": "ISM-1691", "levels": [1, 2], "description": "Patch apps ml2"},
                ],
            },
            {
                "strategy": "Patch operating systems",
                "controls": [
                    {"id": "ISM-1873", "levels": [2], "description": "OS patch ml2"},
                ],
            },
        ],
        "ism": [
            {"id": "ISM-1175", "category": "Patching", "description": "A patching control."}
        ],
    }


def _make_e8_scores() -> dict[str, Any]:
    """Build E8 scores with one related finding and multiple controls."""
    return {
        "Patch applications": {
            "status": "Not assessed",
            "related_findings": ["C1", "C2"],
            "related_controls": [
                {"id": "ISM-1690", "levels": [1, 2, 3]},
                {"id": "ISM-1691", "levels": [1, 2]},
            ],
        },
        "Patch operating systems": {
            "status": "Not assessed",
            "related_findings": ["C3"],
            "related_controls": [
                {"id": "ISM-1873", "levels": [2]},
            ],
        },
    }


def test_e8_table_renders_not_assessed() -> None:
    """The E8 table renders with Not assessed status and no ticks."""
    section = reporter._render_asd_section(_make_asd_data(), e8_scores=_make_e8_scores())
    assert "### Essential Eight" in section
    assert "Not assessed" in section
    assert "✓" not in section
    assert "ML4" not in section


def test_e8_table_level_range_and_single_level() -> None:
    """Level ranges use an en dash; single levels render without a range."""
    section = reporter._render_asd_section(_make_asd_data(), e8_scores=_make_e8_scores())
    assert "ISM-1690 (ML1–ML3)" in section
    assert "ISM-1873 (ML2)" in section


def test_e8_table_em_dash_when_nothing_relates() -> None:
    """Empty related cells render an em dash."""
    section = reporter._render_asd_section(_make_asd_data(), e8_scores={})
    # Two strategies, each with empty findings and controls cells.
    assert section.count("—") >= 4


def test_e8_table_pipe_in_description_escaped() -> None:
    """A pipe in a strategy name or control id is escaped in markdown."""
    asd_data: dict[str, Any] = {
        "essential_eight": [
            {
                "strategy": "Patch | applications",
                "controls": [
                    {"id": "ISM-1690", "levels": [1], "description": "x"},
                ],
            }
        ],
        "ism": [],
    }
    section = reporter._render_asd_section(asd_data, e8_scores={})
    assert "Patch \\| applications" in section


def test_e8_table_missing_when_essential_eight_empty() -> None:
    """When essential_eight is missing, the ISM table still renders."""
    section = reporter._render_asd_section({"ism": _make_asd_data()["ism"]})
    assert "### Essential Eight" not in section
    assert "### Relevant ISM Controls" in section
    assert "ISM-1175" in section


def test_e8_table_related_findings_rendered() -> None:
    """Related findings appear comma-separated in the table."""
    section = reporter._render_asd_section(_make_asd_data(), e8_scores=_make_e8_scores())
    assert "| Patch applications | Not assessed | C1, C2 |" in section


def test_e8_row_uses_scorer_status_with_fallback() -> None:
    """The status cell comes from the scorer and falls back to Not assessed."""
    scores = {
        "Patch applications": {
            "status": "Custom",
            "related_findings": ["C1"],
            "related_controls": [],
        }
    }
    section = reporter._render_asd_section(_make_asd_data(), e8_scores=scores)
    assert "| Patch applications | Custom |" in section
    assert "| Patch operating systems | Not assessed |" in section


def test_e8_unmapped_row_labelled() -> None:
    """The Unmapped strategy renders with an explanatory label and Not assessed."""
    asd_data = _make_asd_data()
    asd_data["essential_eight"].append(
        {
            "strategy": "Unmapped",
            "controls": [{"id": "ISM-9999", "levels": [1], "description": "x"}],
        }
    )
    section = reporter._render_asd_section(asd_data, e8_scores={})
    assert (
        "| Unmapped (not an Essential Eight strategy) | Not assessed |" in section
    )


def test_e8_unmapped_sentence_only_with_unmapped_entry() -> None:
    """The Unmapped sentence appears only when an Unmapped entry exists."""
    sentence = "The \"Unmapped\" row lists controls outside the Essential Eight strategies."
    without = reporter._render_asd_section(_make_asd_data(), e8_scores={})
    assert sentence not in without
    assert "pointers for review, not gaps." in without

    asd_data = _make_asd_data()
    asd_data["essential_eight"].append(
        {
            "strategy": "Unmapped",
            "controls": [{"id": "ISM-9999", "levels": [1], "description": "x"}],
        }
    )
    with_unmapped = reporter._render_asd_section(asd_data, e8_scores={})
    assert sentence in with_unmapped


def test_build_report_empty_asd_data_notes_missing_file(tmp_path: Path) -> None:
    """An empty asd_data dict renders a note pointing at asd_sync.py."""
    rep = _make_reporter(tmp_path)
    report = rep._build_report({"summary": "s", "findings": []}, asd_data={})
    assert "## ASD Framework" in report
    assert "asd_sync.py" in report


# --- Per-finding pointer table (report clarity Phase 1) ---


def _pointer(
    finding_id: str,
    ism: list[dict[str, Any]] | None = None,
    e8: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one per-finding pointer entry."""
    return {"id": finding_id, "ism": ism or [], "e8": e8 or []}


_GATEWAY = {"id": "ISM-0634", "category": "Gateway event logging", "shared": ["firewall", "logged"]}
_PATCH = {"strategy": "Patch operating systems", "shared": ["dpkg", "patch"]}


def _pointer_section(findings: list[dict[str, Any]], pointers: list[dict[str, Any]]) -> str:
    """Render the ASD section with E8 scores empty and the given pointers."""
    return reporter._render_asd_section(
        _make_asd_data(), e8_scores={}, finding_pointers=pointers, findings=findings
    )


def test_pointer_table_shows_finding_controls_and_matched_words() -> None:
    """Each pointer row names the finding, strategy, ISM control and shared words."""
    findings = [_cluster(id="C1", description="Firewall blocks")]
    section = _pointer_section(findings, [_pointer("C1", ism=[_GATEWAY], e8=[_PATCH])])
    assert "### Findings and related controls" in section
    assert "| Finding | Essential Eight | ISM controls | Matched on |" in section
    assert (
        "| C1 Firewall blocks | Patch operating systems | "
        "ISM-0634 (Gateway event logging) | dpkg, firewall, logged, patch |"
    ) in section


def test_pointer_rows_in_natural_finding_id_order() -> None:
    """C2 is listed before C10."""
    findings = [_cluster(id="C10"), _cluster(id="C2")]
    section = _pointer_section(
        findings, [_pointer("C10", ism=[_GATEWAY]), _pointer("C2", ism=[_GATEWAY])]
    )
    assert section.index("| C2 ") < section.index("| C10 ")


def test_pointer_rows_capped_by_severity_with_hidden_line() -> None:
    """Over the cap, the highest severities stay and a line counts the rest."""
    findings = [_cluster(id=f"C{n}", severity="Low") for n in range(1, 17)]
    findings[15] = _cluster(id="C16", severity="High")
    pointers = [_pointer(f"C{n}", ism=[_GATEWAY]) for n in range(1, 17)]
    section = _pointer_section(findings, pointers)
    finding_rows = [line for line in section.splitlines() if re.match(r"\| C\d+ ", line)]
    assert len(finding_rows) == reporter.MAX_POINTER_ROWS
    assert "| C16 " in section
    assert "| C15 " not in section
    assert "1 more finding with pointers not shown (highest severity first)." in section


def test_pointer_line_names_findings_without_pointers() -> None:
    """Findings with no pointers are named in one line, not as empty rows."""
    findings = [_cluster(id="C1"), _cluster(id="C3"), _cluster(id="C2")]
    section = _pointer_section(
        findings, [_pointer("C1", ism=[_GATEWAY]), _pointer("C3"), _pointer("C2")]
    )
    assert "No pointers for: C2, C3." in section
    assert "| C3 " not in section


def test_pointer_message_when_nothing_matched() -> None:
    """When no finding has a pointer, one line says so."""
    section = _pointer_section([_cluster(id="C1")], [_pointer("C1")])
    assert "No Essential Eight or ISM pointers matched the 1 findings in this run." in section
    assert "| Finding |" not in section


def test_pointer_table_excludes_unmapped_strategy() -> None:
    """The Unmapped pseudo-strategy is not shown as an Essential Eight pointer."""
    section = _pointer_section(
        [_cluster(id="C1")],
        [_pointer("C1", e8=[{"strategy": "Unmapped", "shared": ["x"]}])],
    )
    assert "| C1 " not in section


def test_pointer_table_sanitises_cells() -> None:
    """Pipes and newlines in a description cannot break the table row."""
    findings = [_cluster(id="C1", description="A | B\nsecond line")]
    section = _pointer_section(findings, [_pointer("C1", ism=[_GATEWAY])])
    row = next(line for line in section.splitlines() if line.startswith("| C1 "))
    assert "A \\| B second line" in row


def test_how_to_read_note_shown_once_and_replaces_e8_note() -> None:
    """The new layout shows one how-to-read note instead of the E8 caveat."""
    section = _pointer_section([_cluster(id="C1")], [_pointer("C1", ism=[_GATEWAY])])
    assert section.count("How to read this") == 1
    assert "pointers for review, not gaps." not in section


def test_e8_table_collapses_when_no_strategy_matched() -> None:
    """With scores but no related findings or controls, the E8 table is one line."""
    scores = {
        "Patch applications": {"status": "Not assessed", "related_findings": [], "related_controls": []},
        "Patch operating systems": {"status": "Not assessed", "related_findings": [], "related_controls": []},
    }
    section = reporter._render_asd_section(
        _make_asd_data(), e8_scores=scores, finding_pointers=[], findings=[]
    )
    assert "No Essential Eight strategy matched a finding. All strategies: Not assessed." in section
    assert "| Strategy |" not in section


def test_e8_table_kept_when_a_strategy_matched() -> None:
    """The full E8 table stays when at least one strategy has a pointer."""
    section = reporter._render_asd_section(
        _make_asd_data(), e8_scores=_make_e8_scores(), finding_pointers=[], findings=[]
    )
    assert "| Strategy | Status | Related findings | Related controls |" in section


def test_empty_ism_match_list_shows_no_match_line_not_every_control() -> None:
    """An empty matched list says nothing matched; it does not dump the whole ISM table."""
    section = reporter._render_asd_section(_make_asd_data(), e8_scores={}, matched_controls=[])
    assert "> No ISM controls matched findings from this scan." in section
    assert "ISM-1175" not in section


# --- Plain wording and tidy-up (report clarity Phase 2) ---


def test_ism_category_shown_once_for_controls_that_share_it() -> None:
    """Controls with the same category list their IDs together, then the category once."""
    patch_1 = {"id": "ISM-0298", "category": "Patch management", "shared": ["patch"]}
    patch_2 = {"id": "ISM-1143", "category": "Patch management", "shared": ["patch"]}
    section = _pointer_section(
        [_cluster(id="C1")], [_pointer("C1", ism=[_GATEWAY, patch_1, patch_2])]
    )
    assert (
        "ISM-0634 (Gateway event logging); ISM-0298, ISM-1143 (Patch management)"
    ) in section
    assert section.count("Patch management") == 1


def test_flat_ism_list_removed_in_new_layout_but_kept_in_old() -> None:
    """The per-finding table replaces the flat ISM list; old callers still get it."""
    control = {"id": "ISM-1175", "category": "Patching", "description": "A patching control."}
    new = reporter._render_asd_section(
        _make_asd_data(), e8_scores={}, matched_controls=[control],
        finding_pointers=[], findings=[],
    )
    old = reporter._render_asd_section(_make_asd_data(), e8_scores={}, matched_controls=[control])
    assert "### Relevant ISM Controls" not in new
    assert "### Relevant ISM Controls" in old


def test_how_to_read_note_spells_out_terms_and_run_to_run_variation() -> None:
    """The note expands ASD and ISM and warns that pointers can vary between runs."""
    section = _pointer_section([_cluster(id="C1")], [_pointer("C1", ism=[_GATEWAY])])
    assert "Australian Signals Directorate (ASD)" in section
    assert "Information Security Manual (ISM)" in section
    assert "can vary a little between runs" in section


def test_e8_section_explains_ml_in_new_layout() -> None:
    """The Essential Eight section says what ML means when the table is shown."""
    section = reporter._render_asd_section(
        _make_asd_data(), e8_scores=_make_e8_scores(), finding_pointers=[], findings=[]
    )
    assert "ML means maturity level, from ML1 to ML3." in section


def test_cluster_note_explains_c_numbers_and_utc(tmp_path: Path) -> None:
    """With findings, a note under the title explains clusters, UTC and the local Generated time."""
    rep = _make_reporter(tmp_path)
    report = rep._build_report({"summary": "s", "findings": [_cluster()]})
    lines = report.splitlines()
    assert lines[0] == "# Security Report"
    assert "clusters (C1, C2…)" in report
    assert "Coordinated Universal Time" in report
    assert report.index("clusters (C1, C2…)") < report.index("## Summary")


def test_cluster_note_absent_without_findings(tmp_path: Path) -> None:
    """A report with no findings has no cluster note."""
    rep = _make_reporter(tmp_path)
    report = rep._build_report({"summary": "s", "findings": []})
    assert "clusters (C1, C2…)" not in report


def test_glossary_lists_only_terms_used_in_the_report(tmp_path: Path) -> None:
    """The glossary is at the end and holds only terms that appear in this report."""
    rep = _make_reporter(tmp_path)
    finding = _cluster(
        id="C1",
        type="vulnerability",
        cves=["CVE-2020-0001"],
        first_seen="2026-09-24T08:15:00.000Z",
        last_seen="2026-09-24T10:30:00.000Z",
    )
    report = rep._build_report({"summary": "s", "findings": [finding]})
    glossary = report.split("## Glossary")[1]
    assert report.index("## Glossary") > report.index("## Recommendations")
    assert "**Cluster (C1, C2…)**" in glossary
    assert "**UTC**" in glossary
    assert "**CVE**" in glossary
    assert "**ASD**" not in glossary
    assert "**ML**" not in glossary
    assert "**dpkg**" not in glossary


def test_glossary_includes_asd_terms_when_asd_section_present(tmp_path: Path) -> None:
    """ASD, ISM, Essential Eight and ML appear once the ASD section shows them."""
    rep = _make_reporter(tmp_path)
    report = rep._build_report(
        {"summary": "s", "findings": [_cluster(id="C1", description="Firewall blocks")]},
        asd_data=_make_asd_data(),
        e8_scores=_make_e8_scores(),
        finding_pointers=[_pointer("C1", ism=[_GATEWAY], e8=[_PATCH])],
    )
    glossary = report.split("## Glossary")[1]
    for term in ("**ASD**", "**ISM**", "**Essential Eight**", "**ML**"):
        assert term in glossary


def test_no_glossary_when_nothing_to_explain(tmp_path: Path) -> None:
    """With no findings and no ASD section there is no glossary."""
    rep = _make_reporter(tmp_path)
    assert "## Glossary" not in rep._build_report({"summary": "s", "findings": []})


def test_past_incident_dates_shown_as_plain_dates(tmp_path: Path) -> None:
    """Similar past incident timestamps lose the time and microseconds."""
    rep = _make_reporter(tmp_path)
    similar = (
        "- 2026-09-29T22:11:23.259933 (Medium): New dpkg installed.: 5 alerts\n"
        "- 2026-09-30T19:07:48.465717: Other thing: 2 alerts"
    )
    report = rep._build_report({"summary": "s", "findings": [], "similar_incidents": similar})
    assert "- 2026-09-29 (Medium): New dpkg installed.: 5 alerts" in report
    assert "- 2026-09-30: Other thing: 2 alerts" in report
    assert "22:11:23" not in report


def test_report_evidence_uses_spelled_out_firewall_labels(tmp_path: Path) -> None:
    """The report spells out src, dst, dport and the other firewall field names."""
    rep = _make_reporter(tmp_path)
    finding = _cluster(
        id="C1",
        evidence={
            "firewall": {
                "actions": ["block"],
                "directions": ["in"],
                "interfaces": ["vtnet0"],
                "protocols": ["tcp"],
                "ipversions": ["ipv4"],
                "sources": ["1.2.3.4"],
                "destinations": ["5.6.7.8"],
                "dstports": ["443"],
            }
        },
    )
    report = rep._build_report({"summary": "s", "findings": [finding]})
    evidence_line = next(line for line in report.splitlines() if "Evidence:" in line)
    for label in ("direction in", "interface vtnet0", "protocol tcp", "IP versions ipv4",
                  "source 1.2.3.4", "destination 5.6.7.8", "destination port 443"):
        assert label in evidence_line
    for short in ("dir ", "iface ", "proto ", "src ", "dst ", "dport "):
        assert short not in evidence_line


def test_asd_section_without_pointers_keeps_old_layout() -> None:
    """Callers that pass no finding_pointers see the previous layout."""
    section = reporter._render_asd_section(_make_asd_data(), e8_scores={})
    assert "How to read this" not in section
    assert "### Findings and related controls" not in section
    assert "pointers for review, not gaps." in section


def test_build_report_passes_pointers_to_asd_section(tmp_path: Path) -> None:
    """_build_report threads finding_pointers and findings into the ASD section."""
    rep = _make_reporter(tmp_path)
    data = {"summary": "s", "findings": [_cluster(id="C1", description="Firewall blocks")]}
    report = rep._build_report(
        data,
        asd_data=_make_asd_data(),
        e8_scores={},
        finding_pointers=[_pointer("C1", ism=[_GATEWAY])],
    )
    assert "| C1 Firewall blocks | — | ISM-0634 (Gateway event logging) |" in report


def test_build_report_none_asd_data_renders_nothing(tmp_path: Path) -> None:
    """A None asd_data renders no ASD section."""
    rep = _make_reporter(tmp_path)
    report = rep._build_report({"summary": "s", "findings": []}, asd_data=None)
    assert "## ASD Framework" not in report


# --- Operator E8 attestation (roadmap section 15, session 2) ---


def _att(status: str, level: int | None = None, reason: str = "") -> dict[str, Any]:
    """Build one attestation entry."""
    return {"status": status, "level": level, "reason": reason}


def _attested_section(attestation: dict[str, Any] | None, e8_scores: dict[str, Any] | None = None) -> str:
    """Render the pointer-layout ASD section with the given attestation."""
    return reporter._render_asd_section(
        _make_asd_data(),
        e8_scores=_make_e8_scores() if e8_scores is None else e8_scores,
        finding_pointers=[],
        findings=[],
        attestation=attestation,
    )


def _e8_row(section: str, strategy: str) -> str:
    """Return the E8 table row for a strategy."""
    rows = [line for line in section.splitlines() if line.startswith(f"| {strategy} |")]
    assert len(rows) == 1
    return rows[0]


def test_attested_row_shows_level_and_reason() -> None:
    """An Attested strategy shows its level and reason."""
    section = _attested_section({"Patch applications": _att("Attested", 2, "Patched monthly")})
    assert "| Patch applications | Attested at ML2 — Patched monthly |" in section


def test_attested_without_level_falls_back_to_plain() -> None:
    """Attested with no level shows plain Attested plus reason."""
    section = _attested_section({"Patch applications": _att("Attested", None, "Done")})
    assert "| Patch applications | Attested — Done |" in section
    assert "Attested at" not in section


def test_not_applicable_row_shows_reason() -> None:
    """A Not applicable strategy shows its reason."""
    section = _attested_section({"Patch applications": _att("Not applicable", None, "No apps")})
    assert "| Patch applications | Not applicable — No apps |" in section


def test_not_applicable_without_reason_has_no_dash() -> None:
    """An empty reason adds no separator."""
    section = _attested_section({"Patch applications": _att("Not applicable")})
    assert "| Patch applications | Not applicable |" in section


def test_strategy_without_entry_stays_not_assessed() -> None:
    """A strategy absent from the attestation keeps Not assessed."""
    section = _attested_section({"Patch applications": _att("Attested", 1)})
    assert "| Patch operating systems | Not assessed |" in section


def test_unmapped_row_ignores_attestation() -> None:
    """The Unmapped row keeps its label and Not assessed status."""
    asd = _make_asd_data()
    asd["essential_eight"].append({"strategy": reporter.UNMAPPED_STRATEGY, "controls": []})
    section = reporter._render_asd_section(
        asd,
        e8_scores=_make_e8_scores(),
        finding_pointers=[],
        findings=[],
        attestation={reporter.UNMAPPED_STRATEGY: _att("Attested", 3, "x")},
    )
    assert "| Unmapped (not an Essential Eight strategy) | Not assessed |" in section
    assert "Attested" not in section


def test_attestation_reason_is_sanitised() -> None:
    """A pipe and newline in the reason do not break the table row."""
    plain = _attested_section({"Patch applications": _att("Attested", 1, "ok")})
    nasty = _attested_section({"Patch applications": _att("Attested", 1, "a | b\nc")})
    row = _e8_row(nasty, "Patch applications")
    assert "\n" not in row
    assert "a \\| b c" in row
    cells = re.split(r"(?<!\\)\|", row.strip())
    assert len(cells) == len(re.split(r"(?<!\\)\|", _e8_row(plain, "Patch applications").strip()))


def test_attested_strategy_keeps_findings_and_controls() -> None:
    """Related findings and controls stay listed under an Attested strategy."""
    section = _attested_section({"Patch applications": _att("Attested", 2, "ok")})
    row = _e8_row(section, "Patch applications")
    assert "C1, C2" in row
    assert "ISM-1690 (ML1–ML3)" in row


def test_collapsed_line_skipped_when_declared() -> None:
    """A declared strategy keeps the table instead of the collapsed line."""
    empty_scores = {"Patch applications": {"status": "Not assessed", "related_findings": [], "related_controls": []}}
    declared = _attested_section({"Patch applications": _att("Attested", 1)}, e8_scores=empty_scores)
    assert "No Essential Eight strategy matched" not in declared
    assert "| Patch applications | Attested at ML1 |" in declared


def test_collapsed_line_used_when_only_not_assessed() -> None:
    """An attestation of only Not assessed entries still collapses."""
    empty_scores = {"Patch applications": {"status": "Not assessed", "related_findings": [], "related_controls": []}}
    section = _attested_section({"Patch applications": _att("Not assessed")}, e8_scores=empty_scores)
    assert "No Essential Eight strategy matched" in section


def test_how_to_read_note_default_equals_constant() -> None:
    """Without a declared attestation the note equals HOW_TO_READ_NOTE."""
    section = _attested_section(None)
    assert reporter.HOW_TO_READ_NOTE in section
    assert reporter.HOW_TO_READ_NOTE.endswith("Essential Eight strategies are always Not assessed.")


def test_how_to_read_note_changes_when_declared() -> None:
    """With a declared attestation the closing sentence changes."""
    section = _attested_section({"Patch applications": _att("Not applicable", None, "n/a")})
    assert (
        "Attested and Not applicable statuses come from your own attestation file, not from "
        "Wazuh or Ravensight, and are not checked. Strategies with no entry are Not assessed."
    ) in section
    assert "always Not assessed" not in section
    assert reporter.HOW_TO_READ_NOTE[:-len("Essential Eight strategies are always Not assessed.")] in section


@pytest.mark.parametrize(
    "empty",
    [None, {}, {"Patch applications": {"status": "Not assessed", "level": None, "reason": ""}}],
)
def test_empty_attestation_output_unchanged(empty: dict[str, Any] | None) -> None:
    """None, empty and all Not assessed attestations match the call without it."""
    base = reporter._render_asd_section(
        _make_asd_data(), e8_scores=_make_e8_scores(), finding_pointers=[], findings=[]
    )
    assert _attested_section(empty) == base
    legacy = reporter._render_asd_section(_make_asd_data(), e8_scores=_make_e8_scores())
    assert reporter._render_asd_section(_make_asd_data(), e8_scores=_make_e8_scores(), attestation=empty) == legacy


def test_build_report_forwards_attestation(tmp_path: Path) -> None:
    """The attestation reaches the ASD section through _build_report."""
    rep = _make_reporter(tmp_path)
    report = rep._build_report(
        {"summary": "s", "findings": []},
        asd_data=_make_asd_data(),
        e8_scores=_make_e8_scores(),
        attestation={"Patch applications": _att("Attested", 3, "Audited")},
    )
    assert "| Patch applications | Attested at ML3 — Audited |" in report


def test_generate_forwards_attestation(tmp_path: Path) -> None:
    """The attestation reaches the written report through generate."""
    rep = _make_reporter(tmp_path)
    path = rep.generate(
        {"summary": "s", "findings": []},
        asd_data=_make_asd_data(),
        e8_scores=_make_e8_scores(),
        attestation={"Patch applications": _att("Attested", 3, "Audited")},
    )
    assert "Attested at ML3 — Audited" in path.read_text()


def test_glossary_lists_sigma_only_when_report_uses_it(tmp_path: Path) -> None:
    """The sigma entry appears when the report text contains σ, and not otherwise."""
    rep = _make_reporter(tmp_path)
    plain = rep._build_report({"summary": "s", "findings": [_cluster(id="C1")]})
    assert "**σ (sigma)**" not in plain
    with_sigma = rep._build_report(
        {"summary": "s", "findings": [_cluster(id="C1")]},
        trends="### Anomalies\n\n- x (+2.4σ)",
    )
    assert "**σ (sigma)**" in with_sigma.split("## Glossary")[1]


_DATA = {"summary": "s", "findings": []}


def test_generate_default_writes_dated_folder(tmp_path: Path) -> None:
    """Default mode writes security_report_<time>.md inside a date folder."""
    path = _make_reporter(tmp_path).generate(_DATA)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", path.parent.name)
    assert path.parent.parent == tmp_path
    assert re.fullmatch(r"security_report_\d{2}-\d{2}-\d{2}\.md", path.name)
    assert path.read_text()


def test_generate_overwrite_uses_flat_name(tmp_path: Path) -> None:
    """Overwrite mode keeps the flat dated file name and makes no sub-folder."""
    path = Reporter({"output_dir": str(tmp_path), "overwrite": True}).generate(_DATA)
    assert path.parent == tmp_path
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}_security_report\.md", path.name)
    assert [p for p in tmp_path.iterdir() if p.is_dir()] == []


def test_generate_default_reruns_keep_both(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two same-day default runs at different seconds leave two files."""
    from datetime import datetime, timezone

    # Each generate() calls now() twice: once in _build_report, once for the file name.
    times = iter(
        [
            datetime(2026, 10, 15, 9, 0, sec, tzinfo=timezone.utc)
            for sec in (1, 1, 2, 2)
        ]
    )

    class _FakeDatetime:
        @staticmethod
        def now(tz: Any = None) -> datetime:
            return next(times)

    monkeypatch.setattr(reporter, "datetime", _FakeDatetime)
    rep = _make_reporter(tmp_path)
    first = rep.generate(_DATA)
    second = rep.generate(_DATA)
    assert first != second
    assert first.exists() and second.exists()
    assert len(list(tmp_path.rglob("security_report_*.md"))) == 2


def test_generate_overwrite_twice_leaves_one_file(tmp_path: Path) -> None:
    """Overwrite mode run twice leaves one report and no temp file."""
    rep = Reporter({"output_dir": str(tmp_path), "overwrite": True})
    rep.generate(_DATA)
    rep.generate(_DATA)
    assert len(list(tmp_path.glob("*_security_report.md"))) == 1
    assert list(tmp_path.rglob("*.tmp")) == []


def test_generate_default_leaves_no_tmp(tmp_path: Path) -> None:
    """A successful default run leaves no temp file behind."""
    _make_reporter(tmp_path).generate(_DATA)
    assert list(tmp_path.rglob("*.tmp")) == []


@pytest.mark.parametrize("bad", ["yes", 1])
def test_non_bool_overwrite_rejected(tmp_path: Path, bad: Any) -> None:
    """A non-bool overwrite value raises ValueError."""
    with pytest.raises(ValueError, match="overwrite must be true or false"):
        Reporter({"output_dir": str(tmp_path), "overwrite": bad})
