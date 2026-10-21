"""
essentials_scorer.py — Load and validate the ASD Essentials for enterprise IT dataset

Also provides build_technique_names and map_findings_to_actions, which point each
finding at Essentials actions worth reading. The output is pointers only, never a
rating or an assessment of compliance.
"""
import json
import logging
import re
from pathlib import Path
from typing import Any

# Deliberate private import: both matchers share one keyword rule.
from ravensight.e8_scorer import _GENERIC_STEMS, _extract_keyword_map

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
MIN_ESSENTIALS_KEYWORD_SCORE = 3
MAX_ESSENTIALS_ACTIONS = 5
ACTION_ID_RE = re.compile(r"IT\.[A-Z]{3}-\d{2}\.\d+")
ISM_ID_RE = re.compile(r"ISM-\d{4}")
_MAX_SHOWN = 60

_DOMAIN_TYPES = {"capability", "technical"}
_IGP_KEYS = ("not_effective", "partially_effective", "fully_effective")
_REFERENCE_KEYS = ("ism_excl_e8", "e8_ism", "nist_csf_2", "nist_800_171r3", "aescsf")
_ISM_REFERENCE_KEYS = ("ism_excl_e8", "e8_ism")


def load_essentials(path: str | None) -> dict[str, Any]:
    """Load and validate the Essentials dataset, returning {} if unset or invalid."""
    if path is None or not str(path).strip():
        return {}

    try:
        with Path(path).open("r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.warning("Essentials dataset not found: %s", path)
        return {}
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse Essentials dataset %s: %s", path, e)
        return {}
    except UnicodeDecodeError as e:
        logger.warning("Essentials dataset %s is not valid UTF-8: %s", path, e)
        return {}
    except OSError as e:
        logger.warning("Failed to read Essentials dataset %s: %s", path, e)
        return {}
    except ValueError as e:
        logger.warning("Essentials dataset %s could not be loaded: %s", path, e)
        return {}

    problems = _validate(data)
    if problems:
        logger.warning(
            "Essentials dataset %s is invalid (%d problems), first: %s",
            path,
            len(problems),
            "; ".join(problems[:3]),
        )
        return {}

    return data


def _short(value: Any) -> str:
    """Return a repr of value truncated so problem messages stay short."""
    text = repr(value)
    if len(text) > _MAX_SHOWN:
        return text[:_MAX_SHOWN] + "…"
    return text


def _is_int(value: Any) -> bool:
    """Return True for an int that is not a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_str_list(value: Any) -> bool:
    """Return True for a list containing only strings."""
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _validate_domains(domains: Any) -> tuple[list[str], set[str]]:
    """Validate the domains list, returning problems and the known domain names."""
    problems: list[str] = []
    names: set[str] = set()
    if not isinstance(domains, list):
        return ["domains must be a list"], names
    for i, dom in enumerate(domains):
        if not isinstance(dom, dict):
            problems.append(f"domain[{i}] must be an object")
            continue
        name = dom.get("name")
        if not isinstance(name, str):
            problems.append(f"domain[{i}] name must be a string")
        elif name in names:
            problems.append(f"domain[{i}] duplicate name {_short(name)}")
        else:
            names.add(name)
        phase = dom.get("priority_phase")
        if phase is not None and not (_is_int(phase) and 1 <= phase <= 3):
            problems.append(f"domain[{i}] priority_phase must be 1-3 or null")
        domain_type = dom.get("domain_type")
        if not isinstance(domain_type, str) or domain_type not in _DOMAIN_TYPES:
            problems.append(f"domain[{i}] domain_type must be capability or technical")
        if not isinstance(dom.get("description"), str):
            problems.append(f"domain[{i}] description must be a string")
    return problems, names


def _validate_igp(label: str, igp: Any) -> list[str]:
    """Validate an action's igp block."""
    if not isinstance(igp, dict) or set(igp) != set(_IGP_KEYS):
        return [f"{label} igp must have exactly keys {', '.join(_IGP_KEYS)}"]
    problems: list[str] = []
    for key in _IGP_KEYS:
        items = igp[key]
        if not isinstance(items, list):
            problems.append(f"{label} igp.{key} must be a list")
            continue
        for item in items:
            if not (
                isinstance(item, dict)
                and isinstance(item.get("id"), str)
                and isinstance(item.get("text"), str)
            ):
                problems.append(f"{label} igp.{key} items need str id and text")
                break
    return problems


def _validate_references(label: str, refs: Any) -> list[str]:
    """Validate an action's references block."""
    if not isinstance(refs, dict):
        return [f"{label} references must be an object"]
    problems: list[str] = []
    for key in _REFERENCE_KEYS:
        if not _is_str_list(refs.get(key)):
            problems.append(f"{label} references.{key} must be a list of strings")
        elif key in _ISM_REFERENCE_KEYS:
            bad = [v for v in refs[key] if not ISM_ID_RE.fullmatch(v)]
            if bad:
                problems.append(f"{label} references.{key} bad ISM id {_short(bad[0])}")
    if "ism_excl_e8_note" in refs and not isinstance(refs["ism_excl_e8_note"], str):
        problems.append(f"{label} references.ism_excl_e8_note must be a string")
    return problems


def _validate_action(
    index: int, action: Any, domain_names: set[str], seen_ids: set[str]
) -> list[str]:
    """Validate one action entry."""
    if not isinstance(action, dict):
        return [f"action[{index}] must be an object"]
    action_id = action.get("id")
    if not isinstance(action_id, str) or not ACTION_ID_RE.fullmatch(action_id):
        return [f"action[{index}] has a bad id {_short(action_id)}"]
    label = f"action {action_id}"
    problems: list[str] = []
    if action_id in seen_ids:
        problems.append(f"{label} is a duplicate id")
    seen_ids.add(action_id)

    principle = action.get("principle")
    if not isinstance(principle, dict) or not all(
        isinstance(principle.get(k), str) for k in ("id", "name", "statement")
    ):
        problems.append(f"{label} principle needs str id, name and statement")
    if not isinstance(action.get("action_text"), str):
        problems.append(f"{label} action_text must be a string")
    if "action_text_chapter" in action and not isinstance(
        action["action_text_chapter"], str
    ):
        problems.append(f"{label} action_text_chapter must be a string")

    domains = action.get("domains")
    if not isinstance(domains, list) or not domains or not all(
        isinstance(d, str) for d in domains
    ):
        problems.append(f"{label} domains must be a non-empty list of strings")
    else:
        for dom in domains:
            if dom not in domain_names:
                problems.append(f"{label} has unknown domain {_short(dom)}")

    if not _is_str_list(action.get("mitre_technique_names")):
        problems.append(f"{label} mitre_technique_names must be a list of strings")
    if "mitre_technique_names_chapter" in action and not _is_str_list(
        action["mitre_technique_names_chapter"]
    ):
        problems.append(f"{label} mitre_technique_names_chapter must be a list of strings")

    problems.extend(_validate_igp(label, action.get("igp")))
    problems.extend(_validate_references(label, action.get("references")))
    return problems


def _validate(data: Any) -> list[str]:
    """Return a list of schema problems found in the dataset (empty if valid)."""
    if not isinstance(data, dict):
        return ["root must be an object"]
    problems: list[str] = []
    version = data.get("schema_version")
    if not _is_int(version) or version != SCHEMA_VERSION:
        problems.append(f"schema_version must be {SCHEMA_VERSION}")

    domain_problems, domain_names = _validate_domains(data.get("domains"))
    problems.extend(domain_problems)

    actions = data.get("actions")
    if not isinstance(actions, list) or not actions:
        problems.append("actions must be a non-empty list")
        return problems
    seen_ids: set[str] = set()
    for i, action in enumerate(actions):
        problems.extend(_validate_action(i, action, domain_names, seen_ids))
    return problems


_ROUTE_STRENGTH = {"mitre": 0, "ism": 1, "keyword": 2}


def build_technique_names(mitre_data: Any) -> dict[str, str]:
    """Map ATT&CK technique and sub-technique ids to their names, skipping malformed entries."""
    names: dict[str, str] = {}
    if not isinstance(mitre_data, dict):
        return names
    for section in ("techniques", "subtechniques"):
        entries = mitre_data.get(section)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            tid = entry.get("id")
            name = entry.get("name")
            if not isinstance(tid, str) or not tid.strip():
                continue
            if not isinstance(name, str) or not name.strip():
                continue
            names[tid] = name
    return names


def _str_items(value: Any) -> list[str]:
    """Return the str items of a list, or [] if value is not a list."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _domain_phases(essentials: dict) -> dict[str, int | None]:
    """Map domain names to priority_phase (None when absent or not an int)."""
    phases: dict[str, int | None] = {}
    domains = essentials.get("domains")
    if not isinstance(domains, list):
        return phases
    for domain in domains:
        if not isinstance(domain, dict) or not isinstance(domain.get("name"), str):
            continue
        phase = domain.get("priority_phase")
        phases[domain["name"]] = phase if _is_int(phase) else None
    return phases


def _mitre_candidates(
    finding: dict, technique_names: dict[str, str]
) -> list[tuple[str, str, bool]]:
    """Return (finding technique id, name, via_parent) for each technique name a finding implies."""
    ids = finding.get("mitre_ids", [])
    if not isinstance(ids, list):
        return []
    candidates: list[tuple[str, str, bool]] = []
    for tid in ids:
        if not isinstance(tid, str):
            continue
        name = technique_names.get(tid)
        own_name = name if isinstance(name, str) and name else None
        if own_name is not None:
            candidates.append((tid, own_name, False))
        if "." in tid:
            parent_name = technique_names.get(tid.split(".")[0])
            if not isinstance(parent_name, str) or not parent_name:
                continue
            if own_name is not None and parent_name.casefold() == own_name.casefold():
                continue
            candidates.append((tid, parent_name, True))
    return candidates


def _finding_ism_ids(finding_id: str, ism_pointers: Any) -> list[str]:
    """Return the ISM ids that ism_pointers lists for a finding id."""
    found: list[str] = []
    if not isinstance(ism_pointers, list):
        return found
    for entry in ism_pointers:
        if not isinstance(entry, dict) or entry.get("id") != finding_id:
            continue
        items = entry.get("ism")
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                found.append(item["id"])
    return found


def _action_reasons(
    action: dict,
    candidates: list[tuple[str, str, bool]],
    ism_ids: list[str],
) -> list[dict[str, Any]]:
    """Return the MITRE and ISM reasons that link a finding to one action."""
    reasons: list[dict[str, Any]] = []
    for list_name, key in (("guide", "mitre_technique_names"),
                           ("chapter", "mitre_technique_names_chapter")):
        asd_names = {n.casefold() for n in _str_items(action.get(key))}
        for tid, name, via_parent in candidates:
            if name.casefold() not in asd_names:
                continue
            reason = {
                "route": "mitre",
                "technique_id": tid,
                "technique_name": name,
                "via_parent": via_parent,
                "list": list_name,
            }
            if reason not in reasons:
                reasons.append(reason)
    references = action.get("references")
    if isinstance(references, dict):
        for field in _ISM_REFERENCE_KEYS:
            listed = set(_str_items(references.get(field)))
            for ism_id in ism_ids:
                reason = {"route": "ism", "ism_id": ism_id, "field": field}
                if ism_id in listed and reason not in reasons:
                    reasons.append(reason)
    return reasons


def _build_action_entry(
    action: dict, reasons: list[dict[str, Any]], phases: dict[str, int | None]
) -> dict[str, Any]:
    """Build the output entry for one action (identifiers and domains only)."""
    principle = action.get("principle")
    principle = principle if isinstance(principle, dict) else {}
    return {
        "action_id": action.get("id"),
        "principle_id": principle.get("id"),
        "principle_name": principle.get("name"),
        "domains": [
            {"name": name, "priority_phase": phases.get(name)}
            for name in _str_items(action.get("domains"))
        ],
        "reasons": reasons,
    }


def map_findings_to_actions(
    findings: list[dict | str],
    essentials: dict,
    technique_names: dict[str, str],
    ism_pointers: list[dict] | None = None,
) -> list[dict[str, Any]]:
    """Point each finding at Essentials actions linked by MITRE, ISM or keyword overlap.

    Returns one {"id", "actions", "omitted"} entry per dict finding with a str id.
    Matching tries MITRE technique names first, then ISM ids, and uses keywords only
    when neither found an action. Actions are listed by number of reasons, then
    strongest route, then action id, and capped at MAX_ESSENTIALS_ACTIONS. That order
    is a display order only, not a ranking of importance, and the pointers are not
    ratings. Malformed input is skipped silently; this never raises.
    """
    if not isinstance(findings, list):
        return []
    if not isinstance(essentials, dict) or not isinstance(essentials.get("actions"), list):
        return []
    actions = [a for a in essentials["actions"] if isinstance(a, dict)]
    if not actions:
        return []
    names = technique_names if isinstance(technique_names, dict) else {}
    phases = _domain_phases(essentials)

    action_stems: list[set[str]] = []
    for action in actions:
        text = action.get("action_text")
        stems = set(_extract_keyword_map(text)) if isinstance(text, str) else set()
        action_stems.append(stems - _GENERIC_STEMS)

    results: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("id"), str):
            continue
        finding_id = finding["id"]
        candidates = _mitre_candidates(finding, names)
        ism_ids = _finding_ism_ids(finding_id, ism_pointers)

        matched: list[tuple[dict, list[dict[str, Any]]]] = []
        for action in actions:
            reasons = _action_reasons(action, candidates, ism_ids)
            if reasons:
                matched.append((action, reasons))

        if not matched:
            parts = [
                finding[k] for k in ("description", "recommendation")
                if isinstance(finding.get(k), str)
            ]
            finding_words = _extract_keyword_map(" ".join(parts))
            finding_stems = set(finding_words) - _GENERIC_STEMS
            for action, stems in zip(actions, action_stems):
                shared = finding_stems & stems
                if len(shared) >= MIN_ESSENTIALS_KEYWORD_SCORE:
                    reason = {
                        "route": "keyword",
                        "shared": sorted(finding_words[s] for s in shared),
                    }
                    matched.append((action, [reason]))

        entries = sorted(
            matched,
            key=lambda m: (
                -len(m[1]),
                min(_ROUTE_STRENGTH[r["route"]] for r in m[1]),
                str(m[0].get("id")),
            ),
        )
        shown = entries[:MAX_ESSENTIALS_ACTIONS]
        results.append({
            "id": finding_id,
            "actions": [_build_action_entry(a, r, phases) for a, r in shown],
            "omitted": len(entries) - len(shown),
        })
    return results
