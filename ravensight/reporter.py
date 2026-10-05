"""
reporter.py — Markdown security report generation.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ravensight.evidence import render_evidence, sanitise_cell, truncate_words

logger = logging.getLogger(__name__)

REPORT_MAX_CVES = 10


def _trim_timestamp(raw: str) -> str:
    """Trim an ISO timestamp to 'YYYY-MM-DD HH:MM', returning '' when empty."""
    if not raw:
        return ""
    return raw[:16].replace("T", " ")


def _format_finding(finding: str | dict) -> list[str]:
    """Render one finding (legacy string or cluster dict) as markdown lines."""
    if isinstance(finding, str):
        return [f"- {finding}"]

    if finding.get("type") == "unattached":
        if not finding.get("description", "").strip():
            return []
        return [
            f"- *LLM note, not linked to alert data:* {finding.get('description', '')}"
        ]

    first_seen = _trim_timestamp(finding.get("first_seen", ""))
    last_seen = _trim_timestamp(finding.get("last_seen", ""))
    time_clause = ""
    if first_seen and last_seen and first_seen == last_seen:
        time_clause = f" ({first_seen})"
    elif first_seen or last_seen:
        time_clause = f" ({first_seen} → {last_seen})"

    hosts = ", ".join(finding.get("hosts", []))
    count = finding.get("count", 0)
    alert_word = "alert" if count == 1 else "alerts"
    lines = [
        (
            f"- **[{finding.get('id', '')}] {finding.get('severity', '')}** — "
            f"{finding.get('description', '')} — {count} {alert_word} "
            f"on {hosts}{time_clause}"
        )
    ]

    narrative = finding.get("narrative", "")
    if narrative:
        lines.append(f"  - {narrative}")

    evidence_text = render_evidence(finding.get("evidence"))
    if evidence_text:
        lines.append(f"  - Evidence: {evidence_text}")

    for note in finding.get("notes", []):
        lines.append(f"  - Note: {note}")

    if finding.get("flags"):
        check_label = "  - Check: not in this cluster's evidence: "
        lines.append(check_label + ", ".join(finding["flags"]))

    if finding.get("type") == "vulnerability":
        cves = finding.get("cves", [])
        if cves:
            shown = cves[:REPORT_MAX_CVES]
            cve_text = ", ".join(shown)
            if len(cves) > REPORT_MAX_CVES:
                cve_text += f" (+{len(cves) - REPORT_MAX_CVES} more)"
            lines.append(f"  - CVEs: {cve_text}")

    return lines


def _render_asd_section(
    asd_data: dict,
    e8_scores: Optional[dict] = None,
    matched_controls: Optional[list] = None,
) -> str:
    """
    Render ASD Framework section as markdown.

    Args:
        asd_data: Parsed ASD framework data dict from asd_framework.json.
        e8_scores: Optional E8 scoring results mapping strategy to level scores.
        matched_controls: Optional list of matched ISM controls.

    Returns:
        Markdown string for the ASD section, or empty string if no data.
    """
    if not asd_data:
        return ""

    lines = ["## ASD Framework", ""]

    # Essential Eight Maturity Summary
    lines.extend(["### Essential Eight Maturity Summary", "",])

    essential_eight = asd_data.get("essential_eight", [])
    strategies: dict[str, list[int]] = {}
    for entry in essential_eight:
        s = entry.get("strategy", "")
        ml = entry.get("maturity_level", 0)
        strategies.setdefault(s, []).append(ml)

    if strategies:
        header = "| Strategy | ML1 | ML2 | ML3 | ML4 |"
        separator = "|----------|-----|-----|-----|-----|"
        lines.extend([header, separator])
        for strategy, mls in strategies.items():
            row = f"| {strategy} |"
            for level in [1, 2, 3, 4]:
                if e8_scores and strategy in e8_scores:
                    score = e8_scores[strategy].get(level)
                    row += " ✓ |" if score is True else " - |"
                else:
                    row += " ✓ |" if level in mls else " - |"
            lines.append(row)
        lines.append("")

    # Relevant ISM Controls
    lines.extend(["### Relevant ISM Controls", "",])

    if matched_controls and len(matched_controls) > 0:
        lines.append(f"> Showing {len(matched_controls)} controls relevant to this scan.")
        lines.append("| Control ID | Category | Description |")
        lines.append("|------------|----------|-------------|")

        for control in matched_controls:
            control_id = sanitise_cell(control.get("id", "Unknown"))
            category = sanitise_cell(control.get("category", "Unknown"))
            description = control.get("description", "")
            collapsed_desc = " ".join(str(description).split())
            truncated_desc = truncate_words(collapsed_desc, 120)
            lines.append(f"| {control_id} | {category} | {sanitise_cell(truncated_desc)} |")

        lines.append("")
    elif matched_controls and len(matched_controls) == 0:
        lines.append("> No ISM controls matched findings from this scan.")
        lines.append("")
    else:
        ism_controls = asd_data.get("ism", [])
        if ism_controls:
            lines.append("| Control ID | Category | Description |")
            lines.append("|------------|----------|-------------|")

            for control in ism_controls:
                control_id = sanitise_cell(control.get("id", "Unknown"))
                category = sanitise_cell(control.get("category", "Unknown"))
                description = control.get("description", "")
                collapsed_desc = " ".join(str(description).split())
                truncated_desc = truncate_words(collapsed_desc, 120)
                lines.append(f"| {control_id} | {category} | {sanitise_cell(truncated_desc)} |")

            lines.append("")

    return "\n".join(lines)


class Reporter:
    """Generates markdown security reports."""

    def __init__(self, config: dict[str, Any]) -> None:
        """
        Initialise reporter.

        Args:
            config: Reports config with output_dir key.
       """
        self._output_dir = Path(config["output_dir"])
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        data: dict[str, Any],
        trends: Optional[str] = None,
        asd_data: Optional[dict[str, Any]] = None,
        e8_scores: Optional[dict] = None,
        matched_controls: Optional[list] = None,
    ) -> Path:
        """
        Generate markdown report from analysis data.

        Args:
            data: Analysis or baseline dict with summary, findings, recommendations.
            trends: Optional trending markdown to append to report.
            asd_data: Optional ASD framework data for Essential Eight and ISM controls.
            e8_scores: Optional E8 scoring results.
            matched_controls: Optional list of matched ISM controls.

        Returns:
            Path of the written report file.
        """
        report = self._build_report(
            data,
            trends=trends,
            asd_data=asd_data,
            e8_scores=e8_scores,
            matched_controls=matched_controls,
        )
        filename = self._output_dir / f"{datetime.now().strftime('%Y-%m-%d')}_security_report.md"
        with filename.open("w") as f:
            f.write(report)
        logger.info(f"Report written to {filename}")
        return filename

    def _build_report(
        self,
        data: dict[str, Any],
        trends: Optional[str] = None,
        asd_data: Optional[dict[str, Any]] = None,
        e8_scores: Optional[dict] = None,
        matched_controls: Optional[list] = None,
    ) -> str:
        """Build the full markdown report body from analysis data, optional trends, and optional ASD framework context."""
        lines = [
            "# Security Report",
            "",
            f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Summary",
            "",
            data.get("summary", "No summary available"),
            "",
            "## Findings",
            "",
        ]

        findings = data.get("findings", [])
        if findings:
            for finding in findings:
                lines.extend(_format_finding(finding))
        else:
            lines.append("*No findings*")

        # Similar past incidents — context for findings
        unavailable_note = data.get("similar_incidents_unavailable_note")
        similar = data.get("similar_incidents", "").strip()
        if unavailable_note:
            lines.extend([
                "",
                "## Similar Past Incidents",
                "",
                f"> **Note:** {unavailable_note}",
                "",
            ])
        elif similar:
            lines.extend([
                "",
                "## Similar Past Incidents",
                "",
                similar,
                "",
            ])

        # MITRE ATT&CK Tags — threat classification
        mitre_tags = data.get("mitre_tags", [])
        if mitre_tags:
            lines.extend([
                "",
                "## MITRE ATT&CK Tags",
                "",
                "| Tactic | Description |",
                "|--------|-------------|",
            ])
            for tag in mitre_tags:
                tactic = tag.get("tactic", "Unknown")
                description = tag.get("description", "No description")
                lines.append(f"| {tactic} | {description} |")
            lines.append("")

        # ASD Framework section
        if asd_data:
            lines.extend([
                "",
                _render_asd_section(asd_data, e8_scores=e8_scores, matched_controls=matched_controls),
            ])

        # Historical trends — supporting data
        if trends:
            lines.extend(["", trends])

        # Recommendations last — actions flow from all evidence above
        lines.extend([
            "",
            "## Recommendations",
            "",
        ])

        if any(isinstance(f, dict) for f in findings):
            recommendation_lines: list[str] = []
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                rec = finding.get("recommendation", "")
                if not rec:
                    continue
                if finding.get("type") == "unattached":
                    recommendation_lines.append(rec)
                else:
                    recommendation_lines.append(f"[{finding.get('id', '')}] {rec}")
            recommendations: list[str] = recommendation_lines
        else:
            recommendations = data.get("recommendations", [])
        if recommendations:
            for rec in recommendations:
                lines.append(f"- {rec}")
        else:
            lines.append("*No recommendations*")

        lines.append("")
        return "\n".join(lines)