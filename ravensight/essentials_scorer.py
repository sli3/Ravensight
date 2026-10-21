"""
essentials_scorer.py — Load and validate the ASD Essentials for enterprise IT dataset
"""
import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
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
