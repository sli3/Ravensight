"""
reporter.py — Markdown security report generation.
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ravensight.evidence import render_evidence, sanitise_cell, truncate_words

logger = logging.getLogger(__name__)

REPORT_MAX_CVES = 10
UNMAPPED_STRATEGY = "Unmapped"


def _trim_timestamp(raw: str) -> str:
    """Trim an ISO timestamp to 'YYYY-MM-DD HH:MM', returning '' when empty."""
    if not raw:
        return ""
    return raw[:16].replace("T", " ")


def _is_utc(raw: str) -> bool:
    """Return True only when the raw timestamp text ends with a UTC offset."""
    return bool(raw) and raw.endswith(("Z", "+0000", "+00:00"))


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

    raw_first = finding.get("first_seen", "")
    raw_last = finding.get("last_seen", "")
    first_seen = _trim_timestamp(raw_first)
    last_seen = _trim_timestamp(raw_last)
    raw_values = [raw for raw in (raw_first, raw_last) if raw]
    utc = bool(raw_values) and all(_is_utc(raw) for raw in raw_values)
    suffix = " UTC" if utc else ""
    time_clause = ""
    if first_seen and last_seen and first_seen == last_seen:
        time_clause = f" ({first_seen}{suffix})"
    elif first_seen or last_seen:
        time_clause = f" ({first_seen} → {last_seen}{suffix})"

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

    evidence_text = render_evidence(finding.get("evidence"), plain_labels=True)
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


MAX_POINTER_ROWS = 15
MAX_MATCHED_WORDS = 8
_SEVERITY_RANK = {"High": 0, "Medium": 1, "Low": 2}

HOW_TO_READ_NOTE = (
    "> **How to read this:** The Australian Signals Directorate (ASD) publishes the "
    "Essential Eight and the Information Security Manual (ISM). Ravensight reads alerts, "
    "not system settings, so it cannot say whether a control is met. Entries below are "
    "pointers: controls worth checking because a finding shares key words with them. "
    "They are not pass or fail results. \"Matched on\" shows the shared words. Pointers "
    "use each finding's recommendation text, so they can vary a little between runs. "
    "Essential Eight strategies are always Not assessed."
)

CLUSTER_NOTE = (
    "> Findings are grouped into clusters (C1, C2…): alerts that share the same rule. "
    "The numbers apply to this report only. Finding times are in UTC (Coordinated "
    "Universal Time); the Generated time above is local."
)

# (term, meaning, regex that must match the report body for the term to be listed)
_GLOSSARY: list[tuple[str, str, str]] = [
    ("Cluster (C1, C2…)", "Alerts that share the same rule, grouped into one finding. Numbers apply to this report only.", r"\*\*\[C\d+\]"),
    ("UTC", "Coordinated Universal Time, the time zone Wazuh uses for alert times.", r"\d UTC\b"),
    ("ASD", "Australian Signals Directorate, the Australian Government cyber security agency.", r"## ASD Framework"),
    ("ISM", "Information Security Manual, the ASD's catalogue of security controls (IDs like ISM-0298).", r"\bISM\b"),
    ("Essential Eight", "The ASD's eight core mitigation strategies, such as patching and multi-factor authentication.", r"Essential Eight"),
    ("ML", "Maturity level (ML1 to ML4) of an Essential Eight control.", r"\bML\d"),
    ("CVE", "Common Vulnerabilities and Exposures, a public ID for a known software flaw.", r"CVE-\d"),
    ("dpkg", "The Debian and Ubuntu package manager.", r"(?i)\bdpkg\b"),
    ("MITRE ATT&CK", "A public catalogue of attacker tactics and techniques.", r"## MITRE ATT&CK Tags"),
    ("IPv4 and IPv6", "Internet Protocol versions 4 and 6, the two IP address formats.", r"(?i)\bipv[46]\b"),
]


def _render_glossary(report_text: str) -> list[str]:
    """Render a glossary of only the terms that appear in the given report text."""
    entries = [
        f"- **{term}**: {meaning}"
        for term, meaning, pattern in _GLOSSARY
        if re.search(pattern, report_text)
    ]
    if not entries:
        return []
    return ["", "## Glossary", "", *entries]


def _plain_incident_dates(text: str) -> str:
    """Show past-incident timestamps as plain dates (2026-09-29T22:11:23.2 becomes 2026-09-29)."""
    return re.sub(
        r"^(- \d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d+)?",
        r"\1",
        text,
        flags=re.MULTILINE,
    )


def _group_ism_controls(controls: list[dict]) -> str:
    """Join ISM controls as 'ID, ID (Category)' groups so a shared category is shown once."""
    groups: dict[str, list[str]] = {}
    for control in controls:
        groups.setdefault(str(control.get("category", "")).strip(), []).append(
            str(control.get("id", ""))
        )
    parts = [
        f"{', '.join(ids)} ({category})" if category else ", ".join(ids)
        for category, ids in groups.items()
    ]
    return "; ".join(parts)


def _finding_order_key(finding_id: str) -> tuple[str, int, str]:
    """Sort key putting C2 before C10: letters, then the number, then the full id."""
    prefix = finding_id.rstrip("0123456789")
    digits = finding_id[len(prefix):]
    return (prefix, int(digits) if digits else 0, finding_id)


def _render_finding_pointers(findings: list, finding_pointers: list[dict]) -> list[str]:
    """Render the per-finding pointer table and its summary lines as markdown lines."""
    if not finding_pointers:
        return []

    by_id = {f["id"]: f for f in findings if isinstance(f, dict) and isinstance(f.get("id"), str)}
    rows: list[dict] = []
    unmatched: list[str] = []
    for pointer in finding_pointers:
        e8 = [e for e in pointer.get("e8", []) if e.get("strategy") != UNMAPPED_STRATEGY]
        ism = pointer.get("ism", [])
        if e8 or ism:
            rows.append({"id": pointer["id"], "e8": e8, "ism": ism})
        else:
            unmatched.append(pointer["id"])

    lines = ["### Findings and related controls", ""]
    if not rows:
        lines.extend([
            f"> No Essential Eight or ISM pointers matched the {len(finding_pointers)} findings in this run.",
            "",
        ])
        return lines

    # Keep the highest-severity rows when over the cap, then show them in finding-ID order.
    def severity_key(row: dict) -> tuple[int, tuple[str, int, str]]:
        severity = str(by_id.get(row["id"], {}).get("severity", ""))
        return (_SEVERITY_RANK.get(severity, len(_SEVERITY_RANK)), _finding_order_key(row["id"]))

    kept = sorted(rows, key=severity_key)[:MAX_POINTER_ROWS]
    hidden = len(rows) - len(kept)
    kept.sort(key=lambda row: _finding_order_key(row["id"]))

    lines.extend([
        "| Finding | Essential Eight | ISM controls | Matched on |",
        "|---------|-----------------|--------------|------------|",
    ])
    for row in kept:
        description = " ".join(str(by_id.get(row["id"], {}).get("description", "")).split())
        finding_cell = sanitise_cell(f"{row['id']} {truncate_words(description, 60)}".strip())
        e8_cell = sanitise_cell(", ".join(e["strategy"] for e in row["e8"])) if row["e8"] else "—"
        ism_cell = sanitise_cell(_group_ism_controls(row["ism"])) if row["ism"] else "—"
        words = sorted({w for p in (*row["e8"], *row["ism"]) for w in p.get("shared", [])})
        matched_cell = sanitise_cell(", ".join(words[:MAX_MATCHED_WORDS])) or "—"
        lines.append(f"| {finding_cell} | {e8_cell} | {ism_cell} | {matched_cell} |")
    lines.append("")

    if hidden:
        noun = "finding" if hidden == 1 else "findings"
        lines.extend([f"{hidden} more {noun} with pointers not shown (highest severity first).", ""])
    if unmatched:
        unmatched.sort(key=_finding_order_key)
        lines.extend([f"No pointers for: {', '.join(unmatched)}.", ""])
    return lines


def _render_asd_section(
    asd_data: dict,
    e8_scores: dict | None = None,
    matched_controls: list | None = None,
    finding_pointers: list | None = None,
    findings: list | None = None,
) -> str:
    """
    Render ASD Framework section as markdown.

    Args:
        asd_data: Parsed ASD framework data dict from asd_framework.json.
        e8_scores: Optional E8 scoring results mapping strategy to level scores.
        matched_controls: Optional list of matched ISM controls.
        finding_pointers: Optional per-finding pointers from map_findings_to_controls;
            when given, a per-finding table and a single how-to-read note are shown.
        findings: Findings used for the per-finding table descriptions and severities.

    Returns:
        Markdown string for the ASD section, or empty string if no data.
    """
    if not asd_data:
        return ""

    lines = ["## ASD Framework", ""]

    if finding_pointers is not None:
        lines.extend([HOW_TO_READ_NOTE, ""])
        lines.extend(_render_finding_pointers(findings or [], finding_pointers))

    # Essential Eight
    essential_eight = asd_data.get("essential_eight", [])
    e8_has_pointers = any(
        score.get("related_findings") or score.get("related_controls")
        for score in (e8_scores or {}).values()
    )
    if essential_eight and e8_scores and not e8_has_pointers:
        lines.extend([
            "### Essential Eight",
            "",
            "> No Essential Eight strategy matched a finding. All strategies: Not assessed.",
            "",
        ])
    elif essential_eight:
        # The how-to-read note already covers the general caveat when the new layout is used.
        note_parts = []
        if finding_pointers is None:
            note_parts.append(
                "Not assessed. Ravensight reads alerts, not system configuration, so it cannot measure maturity. Related controls are pointers for review, not gaps."
            )
        else:
            note_parts.append("ML means maturity level, from ML1 to ML4.")
        if any(entry.get("strategy") == UNMAPPED_STRATEGY for entry in essential_eight):
            note_parts.append("The \"Unmapped\" row lists controls outside the Essential Eight strategies.")
        lines.extend(["### Essential Eight", ""])
        if note_parts:
            lines.extend([f"> {' '.join(note_parts)}", ""])
        lines.extend([
            "| Strategy | Status | Related findings | Related controls |",
            "|----------|--------|------------------|------------------|",
        ])

        for entry in essential_eight:
            strategy = entry.get("strategy", "")
            score = e8_scores.get(strategy) if e8_scores else None

            if score:
                finding_ids = score.get("related_findings", [])
                controls = score.get("related_controls", [])
            else:
                finding_ids = []
                controls = []

            if finding_ids:
                findings_cell = sanitise_cell(", ".join(str(fid) for fid in finding_ids))
            else:
                findings_cell = "—"

            if controls:
                control_parts = []
                for control in controls:
                    control_id = sanitise_cell(control.get("id", "Unknown"))
                    levels = control.get("levels", [])
                    if levels:
                        min_ml = min(levels)
                        max_ml = max(levels)
                        if min_ml < max_ml:
                            level_str = f"ML{min_ml}–ML{max_ml}"
                        else:
                            level_str = f"ML{min_ml}"
                        control_parts.append(f"{control_id} ({level_str})")
                    else:
                        control_parts.append(control_id)
                controls_cell = sanitise_cell(", ".join(control_parts))
            else:
                controls_cell = "—"

            status = score.get("status", "Not assessed") if score else "Not assessed"
            if strategy == UNMAPPED_STRATEGY:
                display_name = "Unmapped (not an Essential Eight strategy)"
            else:
                display_name = strategy

            lines.append(
                f"| {sanitise_cell(display_name)} | {sanitise_cell(status)} | {findings_cell} | {controls_cell} |"
            )

        lines.append("")

    # The per-finding table already lists the ISM controls, so the flat list is only for the old layout.
    if finding_pointers is not None:
        return "\n".join(lines)

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
    elif matched_controls is not None and len(matched_controls) == 0:
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
        trends: str | None = None,
        asd_data: dict[str, Any] | None = None,
        e8_scores: dict | None = None,
        matched_controls: list | None = None,
        finding_pointers: list | None = None,
    ) -> Path:
        """
        Generate markdown report from analysis data.

        Args:
            data: Analysis or baseline dict with summary, findings, recommendations.
            trends: Optional trending markdown to append to report.
            asd_data: Optional ASD framework data for Essential Eight and ISM controls.
            e8_scores: Optional E8 scoring results.
            matched_controls: Optional list of matched ISM controls.
            finding_pointers: Optional per-finding ISM and Essential Eight pointers.

        Returns:
            Path of the written report file.
        """
        report = self._build_report(
            data,
            trends=trends,
            asd_data=asd_data,
            e8_scores=e8_scores,
            matched_controls=matched_controls,
            finding_pointers=finding_pointers,
        )
        filename = self._output_dir / f"{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d')}_security_report.md"
        with filename.open("w") as f:
            f.write(report)
        logger.info(f"Report written to {filename}")
        return filename

    def _build_report(
        self,
        data: dict[str, Any],
        trends: str | None = None,
        asd_data: dict[str, Any] | None = None,
        e8_scores: dict | None = None,
        matched_controls: list | None = None,
        finding_pointers: list | None = None,
    ) -> str:
        """Build the full markdown report body from analysis data, optional trends, and optional ASD framework context.

        asd_data of None renders no ASD section; an empty dict renders a note that the data file is missing or outdated.
        """
        findings = data.get("findings", [])
        lines = [
            "# Security Report",
            "",
            f"**Generated**: {datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M')}",
            "",
        ]
        if findings:
            lines.extend([CLUSTER_NOTE, ""])
        lines.extend([
            "## Summary",
            "",
            data.get("summary", "No summary available"),
            "",
            "## Findings",
            "",
        ])

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
                _plain_incident_dates(similar),
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
        if asd_data == {}:
            lines.extend([
                "",
                "## ASD Framework",
                "",
                "> ASD framework data is missing or in an older format. Run `scripts/asd_sync.py` to regenerate it.",
                "",
            ])
        elif asd_data:
            lines.extend([
                "",
                _render_asd_section(
                    asd_data,
                    e8_scores=e8_scores,
                    matched_controls=matched_controls,
                    finding_pointers=finding_pointers,
                    findings=findings,
                ),
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

        lines.extend(_render_glossary("\n".join(lines)))
        lines.append("")
        return "\n".join(lines)