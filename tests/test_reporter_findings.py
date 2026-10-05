"""
Tests for dict-aware report rendering (Build 1b).

No network — reports are built in-memory via Reporter._build_report.
"""

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
    assert "on host-1, host-2 (2026-09-24 08:15 → 2026-09-24 10:30)" in report
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
    assert "(2026-09-24 08:15)" in lines[0]
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
            "on host-1, host-2 (2026-09-24 08:15 → 2026-09-24 10:30)"
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
