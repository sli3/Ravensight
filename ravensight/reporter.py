"""
reporter.py — Markdown security report generation.
"""

import json
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
    """Render one finding (legacy string, cluster dict or unattached LLM note) as markdown lines."""
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

    if finding.get("flags"):
        lines.append(
            "  - Check: the summary above mentions "
            + ", ".join(finding["flags"])
            + ", which are not in this cluster's evidence"
        )

    evidence_text = render_evidence(finding.get("evidence"), plain_labels=True)
    if evidence_text:
        lines.append(f"  - Evidence: {evidence_text}")

    for note in finding.get("notes", []):
        lines.append(f"  - Note: {note}")

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
# A typical Wazuh rule description is shown whole in the Finding cell
MAX_FINDING_LABEL_CHARS = 100
_SEVERITY_RANK = {"High": 0, "Medium": 1, "Low": 2}

_HOW_TO_READ_PREFIX = (
    "> **How to read this:** The Australian Signals Directorate (ASD) publishes the "
    "Essential Eight and the Information Security Manual (ISM). Ravensight reads alerts, "
    "not system settings, so it cannot say whether a control is met. Entries below are "
    "pointers: controls worth checking because a finding shares key words with them. "
    "They are not pass or fail results. \"Matched on\" shows the shared words. Pointers "
    "use each finding's recommendation text, so they can vary a little between runs. "
)
_NOTE_CLOSING_DEFAULT = "Essential Eight strategies are always Not assessed."
_NOTE_CLOSING_ATTESTED = (
    "Attested and Not applicable statuses come from your own attestation file, not from "
    "Wazuh or Ravensight, and are not checked. Strategies with no entry are Not assessed."
)
HOW_TO_READ_NOTE = _HOW_TO_READ_PREFIX + _NOTE_CLOSING_DEFAULT

CLUSTER_NOTE = (
    "> Findings are grouped into clusters (C1, C2…): alerts that share the same rule. "
    "The numbers apply to this report only. Severity comes from the Wazuh rule "
    "level: High is level 12 or above, Medium is 7 to 11, Low is 6 or below. "
    "Finding times are in UTC (Coordinated "
    "Universal Time); the Generated time above is local."
)

# (term, meaning, regex that must match the report body for the term to be listed)
_GLOSSARY: list[tuple[str, str, str]] = [
    ("Cluster (C1, C2…)", "Alerts that share the same rule, grouped into one finding. Numbers apply to this report only.", r"\*\*\[C\d+\]"),
    ("UTC", "Coordinated Universal Time, the time zone Wazuh uses for alert times.", r"\d UTC\b"),
    ("ASD", "Australian Signals Directorate, the Australian Government cyber security agency.", r"## ASD Framework"),
    ("ISM", "Information Security Manual, the ASD's catalogue of security controls (IDs like ISM-0298).", r"\bISM\b"),
    ("Essential Eight", "The ASD's eight core mitigation strategies, such as patching and multi-factor authentication.", r"Essential Eight"),
    ("ML", "Maturity level (ML1 to ML3) of an Essential Eight control.", r"\bML\d"),
    ("ASD Essentials", "The Australian Signals Directorate's framework of principles and actions for enterprise IT.", r"## ASD Essentials"),
    ("Principle and action", "A principle is an outcome to achieve; an action is something that must be done to achieve it.", r"## ASD Essentials"),
    ("Priority phase", "The order in which ASD suggests implementing the domains of the Essentials. It is not a rating.", r"## ASD Essentials"),
    ("CVE", "Common Vulnerabilities and Exposures, a public ID for a known software flaw.", r"CVE-\d"),
    ("dpkg", "The Debian and Ubuntu package manager.", r"(?i)\bdpkg\b"),
    ("MITRE ATT&CK", "A public catalogue of attacker tactics and techniques.", r"## MITRE ATT&CK Tags"),
    ("IPv4 and IPv6", "Internet Protocol versions 4 and 6, the two IP address formats.", r"(?i)\bipv[46]\b"),
    ("σ (sigma)", "Standard deviation: the usual size of day-to-day swings. +2.4σ means the latest count is 2.4 swings above the average of the previous days.", r"σ"),
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
        """Return a sort key of severity rank, then finding-ID order."""
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
        label = truncate_words(description, MAX_FINDING_LABEL_CHARS)
        finding_cell = sanitise_cell(f"{row['id']} {label}".strip())
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
    attestation: dict | None = None,
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
        attestation: Optional operator attestation mapping strategy to status, level and reason.

    Returns:
        Markdown string for the ASD section, or empty string if no data.
    """
    if not asd_data:
        return ""

    lines = ["## ASD Framework", ""]

    attestation = attestation or {}
    declared = any(
        strategy != UNMAPPED_STRATEGY
        and isinstance(entry, dict)
        and entry.get("status") != "Not assessed"
        for strategy, entry in attestation.items()
    )

    if finding_pointers is not None:
        closing = _NOTE_CLOSING_ATTESTED if declared else _NOTE_CLOSING_DEFAULT
        lines.extend([_HOW_TO_READ_PREFIX + closing, ""])
        lines.extend(_render_finding_pointers(findings or [], finding_pointers))

    # Essential Eight
    essential_eight = asd_data.get("essential_eight", [])
    e8_has_pointers = any(
        score.get("related_findings") or score.get("related_controls")
        for score in (e8_scores or {}).values()
    )
    if essential_eight and e8_scores and not e8_has_pointers and not declared:
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
            note_parts.append("ML means maturity level, from ML1 to ML3.")
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
                declared_entry = attestation.get(strategy)
                if isinstance(declared_entry, dict):
                    declared_status = declared_entry.get("status")
                    declared_level = declared_entry.get("level")
                    declared_reason = declared_entry.get("reason")
                    if declared_status == "Attested":
                        if isinstance(declared_level, int) and not isinstance(declared_level, bool):
                            status = f"Attested at ML{declared_level}"
                        else:
                            status = "Attested"
                        if declared_reason:
                            status = f"{status} — {declared_reason}"
                    elif declared_status == "Not applicable":
                        status = "Not applicable"
                        if declared_reason:
                            status = f"{status} — {declared_reason}"

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


ESSENTIALS_ATTRIBUTION = "© Commonwealth of Australia 2026"
ESSENTIALS_LICENCE = "CC BY 4.0"
ESSENTIALS_LICENCE_URL = "https://creativecommons.org/licenses/by/4.0/"
ESSENTIALS_CHANGES = (
    "Restructured from ASD's PDF and XLSX publications into JSON and checked against the "
    "three documents listed above. Where those documents differ, both versions are kept."
)
ESSENTIALS_NOTICE = (
    "UNOFFICIAL community dataset. Not produced, endorsed or supported by ASD. "
    "Check against ASD's official documents at cyber.gov.au before relying on it."
)

_ESSENTIALS_HOW_TO_READ = (
    "> **How to read this:** ASD's Essentials for enterprise IT are a set of principles and "
    "actions. Ravensight reads alerts, not system settings, so it cannot say whether an action "
    "is met. Entries below are pointers: actions worth checking because ASD's mapping of "
    "ATT&CK techniques to actions, an ISM control or shared key words link them to a finding. "
    "ASD's mapping is a guide for setting priorities, not a rating. A priority phase is ASD's "
    "suggested implementation order, not a rating. Ratings below come only from your own "
    "attestation file, not from Wazuh or Ravensight, and not from ASD, and are given per "
    "principle, a simplification of ASD's per-action, per-domain ratings. Everything else is "
    "Not assessed. Pointers can vary a little between runs."
)
_NO_PHASE = 99


def _essentials_source(dataset: Any) -> dict[str, str]:
    """Return the attribution, licence and notice from the dataset's source block, else the constants."""
    source = dataset.get("source") if isinstance(dataset, dict) else None
    source = source if isinstance(source, dict) else {}
    defaults = {
        "attribution": ESSENTIALS_ATTRIBUTION,
        "licence": ESSENTIALS_LICENCE,
        "notice": ESSENTIALS_NOTICE,
    }
    result: dict[str, str] = {}
    for key, fallback in defaults.items():
        value = source.get(key)
        result[key] = value if isinstance(value, str) and value.strip() else fallback
    return result


def _essentials_matched_on(actions: list[dict]) -> str:
    """Summarise the reasons behind a principle's matched actions as a de-duplicated, capped cell."""
    links: list[str] = []
    words: set[str] = set()
    for action in actions:
        reasons = action.get("reasons")
        for reason in reasons if isinstance(reasons, list) else []:
            if not isinstance(reason, dict):
                continue
            route = reason.get("route")
            if route == "mitre":
                name = str(reason.get("technique_name", "")).strip()
                tid = str(reason.get("technique_id", "")).strip()
                if name and tid:
                    if reason.get("via_parent") is True:
                        text = f"{name} (parent of {tid})"
                    else:
                        text = f"{name} ({tid})"
                else:
                    text = name or tid
            elif route == "ism":
                text = str(reason.get("ism_id", "")).strip()
            elif route == "keyword":
                shared = reason.get("shared")
                if isinstance(shared, list):
                    words.update(w for w in shared if isinstance(w, str))
                continue
            else:
                continue
            if text and text not in links:
                links.append(text)
    parts = links[:MAX_MATCHED_WORDS] + sorted(words)[:MAX_MATCHED_WORDS]
    return sanitise_cell(", ".join(parts)) or "—"


def _essentials_principle_rows(entry: dict) -> list[dict]:
    """Group one finding's matched actions by principle, ordered by phase then principle id."""
    groups: dict[str, dict] = {}
    actions = entry.get("actions")
    for action in actions if isinstance(actions, list) else []:
        if not isinstance(action, dict) or not isinstance(action.get("principle_id"), str):
            continue
        group = groups.setdefault(
            action["principle_id"],
            {"id": action["principle_id"], "name": action.get("principle_name"), "actions": []},
        )
        group["actions"].append(action)
    rows = []
    for group in groups.values():
        phases = [
            d["priority_phase"]
            for a in group["actions"]
            for d in (a.get("domains") if isinstance(a.get("domains"), list) else [])
            if isinstance(d, dict)
            and isinstance(d.get("priority_phase"), int)
            and not isinstance(d.get("priority_phase"), bool)
        ]
        group["phase"] = min(phases) if phases else _NO_PHASE
        rows.append(group)
    rows.sort(key=lambda g: (g["phase"], g["id"]))
    return rows


def _principle_names(dataset: dict) -> dict[str, str]:
    """Map principle ids to names using the dataset's actions."""
    names: dict[str, str] = {}
    actions = dataset.get("actions")
    for action in actions if isinstance(actions, list) else []:
        principle = action.get("principle") if isinstance(action, dict) else None
        if (
            isinstance(principle, dict)
            and isinstance(principle.get("id"), str)
            and isinstance(principle.get("name"), str)
        ):
            names.setdefault(principle["id"], principle["name"])
    return names


def _render_essentials_pointers(findings: list, finding_actions: list) -> list[str]:
    """Render the per-finding Essentials pointer table and its summary lines."""
    by_id = {f["id"]: f for f in findings if isinstance(f, dict) and isinstance(f.get("id"), str)}
    entries = [
        e for e in finding_actions if isinstance(e, dict) and isinstance(e.get("id"), str)
    ]
    rows: list[dict] = []
    unmatched: list[str] = []
    for entry in entries:
        principle_rows = _essentials_principle_rows(entry)
        if principle_rows:
            omitted = entry.get("omitted")
            rows.append({
                "id": entry["id"],
                "principles": principle_rows,
                "omitted": omitted if isinstance(omitted, int) and not isinstance(omitted, bool) else 0,
            })
        else:
            unmatched.append(entry["id"])

    lines = ["### Findings and related principles", ""]
    if not rows:
        lines.extend([
            f"> No Essentials pointers matched the {len(entries)} findings in this run.",
            "",
        ])
        return lines

    def severity_key(row: dict) -> tuple[int, tuple[str, int, str]]:
        """Return a sort key of severity rank, then finding-ID order."""
        severity = str(by_id.get(row["id"], {}).get("severity", ""))
        return (_SEVERITY_RANK.get(severity, len(_SEVERITY_RANK)), _finding_order_key(row["id"]))

    kept = sorted(rows, key=severity_key)[:MAX_POINTER_ROWS]
    hidden = len(rows) - len(kept)
    kept.sort(key=lambda row: _finding_order_key(row["id"]))

    lines.extend([
        "| Finding | Principle | Actions | Priority phase | Matched on |",
        "|---------|-----------|---------|----------------|------------|",
    ])
    for row in kept:
        description = " ".join(str(by_id.get(row["id"], {}).get("description", "")).split())
        label = truncate_words(description, MAX_FINDING_LABEL_CHARS)
        finding_cell = sanitise_cell(f"{row['id']} {label}".strip())
        last = len(row["principles"]) - 1
        for index, group in enumerate(row["principles"]):
            principle_cell = sanitise_cell(f"{group['id']} {group['name'] or ''}".strip())
            ids = [str(a.get("action_id")) for a in group["actions"] if a.get("action_id") is not None]
            actions_cell = sanitise_cell(", ".join(ids)) or "—"
            if index == last and row["omitted"] > 0:
                noun = "action" if row["omitted"] == 1 else "actions"
                actions_cell += f" (+{row['omitted']} more {noun} not shown)"
            phase_cell = "All phases" if group["phase"] == _NO_PHASE else f"Phase {group['phase']}"
            lines.append(
                f"| {finding_cell} | {principle_cell} | {actions_cell} | {phase_cell} | "
                f"{_essentials_matched_on(group['actions'])} |"
            )
    lines.append("")

    if hidden:
        noun = "finding" if hidden == 1 else "findings"
        lines.extend([f"{hidden} more {noun} with pointers not shown (highest severity first).", ""])
    if unmatched:
        unmatched.sort(key=_finding_order_key)
        lines.extend([f"No pointers for: {', '.join(unmatched)}.", ""])
    return lines


def _render_essentials_ratings(dataset: dict, attestation: Any) -> list[str]:
    """Render the operator's declared ratings, or a line saying none were declared."""
    lines = ["### Declared ratings", ""]
    if not isinstance(attestation, dict) or not attestation:
        lines.extend(["> No ratings declared. Every principle is Not assessed.", ""])
        return lines
    names = _principle_names(dataset)
    declared = [
        (pid, entry)
        for pid, entry in attestation.items()
        if isinstance(entry, dict)
        and isinstance(entry.get("status"), str)
        and entry["status"] != "Not assessed"
    ]
    if not declared:
        lines.extend([
            f"> No ratings declared. All {len(attestation)} principles are Not assessed.",
            "",
        ])
        return lines
    lines.extend([
        "These ratings are your own declarations.",
        "",
        "| Principle | Rating | Domains | Reason |",
        "|-----------|--------|---------|--------|",
    ])
    for pid, entry in declared:
        name = names.get(str(pid))
        principle_cell = sanitise_cell(f"{pid} {name}" if name else pid)
        domains = entry.get("domains")
        domain_list = [d for d in domains if isinstance(d, str)] if isinstance(domains, list) else []
        domains_cell = sanitise_cell(", ".join(domain_list)) or "—"
        reason_cell = sanitise_cell(entry.get("reason") or "") or "—"
        lines.append(
            f"| {principle_cell} | {sanitise_cell(entry['status'])} | {domains_cell} | {reason_cell} |"
        )
    lines.append("")
    return lines


def _render_essentials_section(essentials: Any, findings: list) -> str:
    """Render the ASD Essentials section as markdown, or "" when there is no usable dataset."""
    if not isinstance(essentials, dict):
        return ""
    dataset = essentials.get("dataset")
    if not isinstance(dataset, dict) or not dataset:
        return ""
    source = _essentials_source(dataset)
    finding_actions = essentials.get("finding_actions")
    lines = [
        "## ASD Essentials for enterprise IT",
        "",
        _ESSENTIALS_HOW_TO_READ,
        "",
        (
            f"Source: ASD Essentials for enterprise IT, {source['attribution']}, {source['licence']}. "
            "Restructured by Ravensight as an unofficial dataset, not produced, endorsed or "
            "supported by ASD."
        ),
        "",
    ]
    lines.extend(
        _render_essentials_pointers(
            findings if isinstance(findings, list) else [],
            finding_actions if isinstance(finding_actions, list) else [],
        )
    )
    lines.extend(_render_essentials_ratings(dataset, essentials.get("attestation")))
    return "\n".join(lines)


JSON_SCHEMA_VERSION = 4

_CLUSTER_LIST_KEYS = ("hosts", "flags", "notes", "cves")
_CLUSTER_SCALAR_KEYS = (
    "id",
    "severity",
    "description",
    "count",
    "first_seen",
    "last_seen",
    "narrative",
    "recommendation",
    "evidence",
)


def _json_finding(finding: Any) -> dict[str, Any] | None:
    """Map one finding (legacy string, cluster dict or unattached note) to a JSON-ready dict, or None to skip it."""
    if isinstance(finding, str):
        return {"type": "legacy", "text": finding}
    if not isinstance(finding, dict):
        return {"type": "legacy", "text": str(finding)}

    if finding.get("type") == "unattached":
        # Mirror the markdown, which drops unattached notes with no description.
        if not str(finding.get("description", "")).strip():
            return None
        return {
            "type": "unattached",
            "description": finding.get("description", ""),
            "recommendation": finding.get("recommendation"),
        }

    mapped: dict[str, Any] = {"type": finding.get("type") or "cluster"}
    for key in _CLUSTER_SCALAR_KEYS:
        mapped[key] = finding.get(key)
    for key in _CLUSTER_LIST_KEYS:
        mapped[key] = list(finding.get(key) or [])
    return mapped


def _json_essentials_licence_extras(dataset: Any) -> dict[str, str]:
    """Return the licence URL and changes note from the dataset's source block, else the constants."""
    source = dataset.get("source") if isinstance(dataset, dict) else None
    source = source if isinstance(source, dict) else {}
    defaults = {"licence_url": ESSENTIALS_LICENCE_URL, "changes": ESSENTIALS_CHANGES}
    result: dict[str, str] = {}
    for key, fallback in defaults.items():
        value = source.get(key)
        result[key] = value if isinstance(value, str) and value.strip() else fallback
    return result


def _json_essentials(essentials: Any) -> dict[str, Any] | None:
    """Map the Essentials block to its JSON form, or None when there is no usable dataset."""
    if not isinstance(essentials, dict):
        return None
    dataset = essentials.get("dataset")
    if not isinstance(dataset, dict) or not dataset:
        return None
    finding_actions = essentials.get("finding_actions")
    attestation = essentials.get("attestation")
    names = _principle_names(dataset)
    named_attestation: dict[Any, Any] = {}
    if isinstance(attestation, dict):
        for pid, entry in attestation.items():
            named_attestation[pid] = (
                {**entry, "name": names.get(pid, "")} if isinstance(entry, dict) else entry
            )
    return {
        **_essentials_source(dataset),
        "dataset_schema_version": dataset.get("schema_version"),
        "finding_actions": finding_actions if isinstance(finding_actions, list) else [],
        "attestation": named_attestation,
        **_json_essentials_licence_extras(dataset),
    }


def _build_json_payload(
    data: dict[str, Any],
    generated_at: datetime,
    trends: str | None,
    run_params: dict | None,
    e8_scores: dict | None,
    matched_controls: list | None,
    finding_pointers: list | None,
    attestation: dict | None,
    essentials: dict | None = None,
    trends_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the plain dict written as the JSON report (no summary, MITRE tags or similar incidents).

    essentials is the optional Essentials block; the payload's essentials key is None without a usable dataset.
    trends_data is the optional structured trend table, written under "trends".
    """
    findings = [
        mapped
        for mapped in (_json_finding(f) for f in data.get("findings", []))
        if mapped is not None
    ]
    payload: dict[str, Any] = {
        "schema_version": JSON_SCHEMA_VERSION,
        "generated_at": generated_at.astimezone(timezone.utc).isoformat(),
        "run": run_params,
        "findings": findings,
        "trends_markdown": trends or None,
        "trends": trends_data,
        "e8_status": e8_scores,
        "finding_pointers": finding_pointers,
        "matched_controls": matched_controls,
        "essentials": _json_essentials(essentials),
    }
    if attestation:
        payload["attestation"] = attestation
    return payload


class Reporter:
    """Generates markdown security reports."""

    def __init__(self, config: dict[str, Any]) -> None:
        """
        Initialise reporter.

        Args:
            config: Reports config with output_dir key and optional overwrite flag
                (bool, default False). False writes <output_dir>/<date>/security_report_<time>.md;
                True writes <output_dir>/<date>_security_report.md, replacing the same-day file.
                Optional json_output flag (bool, default True); False skips the JSON copy.

        Raises:
            ValueError: If overwrite or json_output is not a bool.
        """
        self._overwrite = config.get("overwrite", False)
        if type(self._overwrite) is not bool:
            raise ValueError(
                f"[reports].overwrite must be true or false, got {type(self._overwrite).__name__}"
            )
        self._json_output = config.get("json_output", True)
        if type(self._json_output) is not bool:
            raise ValueError(
                f"[reports].json_output must be true or false, got {type(self._json_output).__name__}"
            )
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
        attestation: dict | None = None,
        run_params: dict | None = None,
        essentials: dict | None = None,
        trends_data: dict[str, Any] | None = None,
    ) -> Path:
        """
        Generate markdown report from analysis data, plus a JSON file beside it.

        Args:
            data: Analysis or baseline dict with summary, findings, recommendations.
            trends: Optional trending markdown, placed before the Recommendations section.
            asd_data: Optional ASD framework data for Essential Eight and ISM controls.
            e8_scores: Optional E8 scoring results.
            matched_controls: Optional list of matched ISM controls.
            finding_pointers: Optional per-finding ISM and Essential Eight pointers.
            attestation: Optional operator E8 attestation shown in the Essential Eight table.
            run_params: Optional run window and filters, echoed under "run" in the JSON only.
            essentials: Optional Essentials block (dataset, finding_actions, attestation);
                adds the ASD Essentials section to the markdown and an essentials key to the JSON.
            trends_data: Optional structured trend table, shown under "trends" in the JSON only.

        Returns:
            Path of the written markdown report file. It is written to a .tmp file first,
            then renamed into place, so a failed write leaves no partial report. A JSON
            copy is written beside it with the .json suffix; a JSON failure only logs a warning.

        Raises:
            OSError: If the markdown report cannot be written.
        """
        report = self._build_report(
            data,
            trends=trends,
            asd_data=asd_data,
            e8_scores=e8_scores,
            matched_controls=matched_controls,
            finding_pointers=finding_pointers,
            attestation=attestation,
            essentials=essentials,
        )
        now = datetime.now(timezone.utc).astimezone()
        if self._overwrite:
            filename = self._output_dir / f"{now.strftime('%Y-%m-%d')}_security_report.md"
        else:
            filename = (
                self._output_dir
                / now.strftime("%Y-%m-%d")
                / f"security_report_{now.strftime('%H-%M-%S')}.md"
            )
        filename.parent.mkdir(parents=True, exist_ok=True)
        tmp = filename.with_name(filename.name + ".tmp")
        try:
            with tmp.open("w") as f:
                f.write(report)
            tmp.replace(filename)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        logger.info(f"Report written to {filename}")
        if self._json_output:
            self._write_json(
                filename.with_suffix(".json"),
                data=data,
                generated_at=now,
                trends=trends,
                run_params=run_params,
                e8_scores=e8_scores,
                matched_controls=matched_controls,
                finding_pointers=finding_pointers,
                attestation=attestation,
                essentials=essentials,
                trends_data=trends_data,
            )
        return filename

    def _write_json(
        self,
        json_path: Path,
        *,
        data: dict[str, Any],
        generated_at: datetime,
        trends: str | None,
        run_params: dict | None,
        e8_scores: dict | None,
        matched_controls: list | None,
        finding_pointers: list | None,
        attestation: dict | None,
        essentials: dict | None = None,
        trends_data: dict[str, Any] | None = None,
    ) -> None:
        """Write the JSON report beside the markdown (including any essentials block); log a warning and carry on if it fails."""
        tmp = json_path.with_name(json_path.name + ".tmp")
        try:
            payload = _build_json_payload(
                data=data,
                generated_at=generated_at,
                trends=trends,
                run_params=run_params,
                e8_scores=e8_scores,
                matched_controls=matched_controls,
                finding_pointers=finding_pointers,
                attestation=attestation,
                essentials=essentials,
                trends_data=trends_data,
            )
            text = json.dumps(payload, ensure_ascii=False, indent=2)
            tmp.write_text(text + "\n", encoding="utf-8")
            tmp.replace(json_path)
        except (OSError, TypeError, ValueError) as err:
            tmp.unlink(missing_ok=True)
            logger.warning("JSON report not written to %s: %s", json_path, err)
            return
        logger.info(f"JSON report written to {json_path}")

    def _build_report(
        self,
        data: dict[str, Any],
        trends: str | None = None,
        asd_data: dict[str, Any] | None = None,
        e8_scores: dict | None = None,
        matched_controls: list | None = None,
        finding_pointers: list | None = None,
        attestation: dict | None = None,
        essentials: dict | None = None,
    ) -> str:
        """Build the full markdown report body from analysis data, optional trends, and optional ASD framework context.

        attestation is the optional operator E8 attestation, passed on to the ASD section.

        essentials is the optional Essentials block; with a usable dataset it adds the ASD Essentials section after the ASD Framework section.

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
                    attestation=attestation,
                ),
            ])

        # ASD Essentials section
        essentials_section = _render_essentials_section(essentials, findings)
        if essentials_section:
            lines.extend(["", essentials_section])

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