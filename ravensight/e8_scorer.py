"""Essential Eight compliance scoring and ISM control matching module.

Callers should pass overrides_path from config:
overrides_path = config.get("e8", {}).get("overrides_path")
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

__all__ = ["match_ism_controls", "score_findings"]

logger = logging.getLogger(__name__)

# Stop words to exclude from keyword extraction
STOP_WORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "that", "this", "these", "those", "it",
    "its", "as", "if", "not", "no", "all", "any", "each", "which", "when",
    "their", "they", "them", "used", "using", "use", "within", "across",
}

# Minimum keyword length to include
MIN_KEYWORD_LENGTH = 4

# Minimum match score for ISM control to be included in results
MIN_ISM_MATCH_SCORE = 1

# Minimum keyword overlap for a finding to relate to an Essential Eight control
MIN_E8_MATCH_SCORE = 2

# Maximum related controls returned per strategy
MAX_E8_RELATED_CONTROLS = 3


def _load_overrides(overrides_path: str | None) -> dict[str, set[str]]:
    """Load per-strategy keyword blocklists from override file.

    Args:
        overrides_path: Path to e8_keyword_overrides.json, or None.

    Returns:
        Dict mapping casefolded strategy name to set of blocked keywords.
        Returns empty dict if path is None or file is unreadable.
    """
    if overrides_path is None:
        return {}

    try:
        path = Path(overrides_path)
        if not path.is_file():
            logger.warning("e8_keyword_overrides.json not found at %s", overrides_path)
            return {}

        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            logger.warning("e8_keyword_overrides.json root is not a JSON object")
            return {}

        blocklist = data.get("strategy_blocklist", {})
        if not isinstance(blocklist, dict):
            logger.warning("e8_keyword_overrides.json 'strategy_blocklist' is not a JSON object")
            return {}

        cleaned: dict[str, set[str]] = {}
        for k, v in blocklist.items():
            if not isinstance(k, str) or not isinstance(v, list) or not all(
                isinstance(item, str) for item in v
            ):
                logger.warning(
                    "e8_keyword_overrides.json skipping malformed strategy_blocklist entry: %r",
                    k,
                )
                continue
            cleaned[k.casefold()] = set(v)
        return cleaned

    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load e8_keyword_overrides.json: %s", e)
        return {}


def _convert_findings(findings: list[dict | str]) -> list[dict]:
    """Convert string findings to dict format for processing.

    Args:
        findings: List of strings or dicts.

    Returns:
        List of dictionaries where strings are wrapped with description, rule_group, and recommendation fields.
    """
    if not findings:
        return []

    converted = []
    for f in findings:
        if isinstance(f, dict):
            converted.append(f)
        elif isinstance(f, str):
            # Wrap string as a finding with description set to the string itself
            converted.append({
                "description": f,
                "rule_group": "",
                "recommendation": ""
            })
    return converted


def _extract_keywords(text: str) -> set[str]:
    """Extract meaningful keywords from a text string."""
    # Lowercase and split on whitespace/punctuation
    tokens = re.split(r'[\s\W]+', text.lower())

    # Filter stop words, short tokens, and pure numeric tokens
    keywords = set()
    for token in tokens:
        if not token:
            continue
        if len(token) < MIN_KEYWORD_LENGTH:
            continue
        if token.isdigit():
            continue
        if token in STOP_WORDS:
            continue
        keywords.add(token)

    return keywords


def _normalise_findings(findings: list[dict]) -> list[str]:
    """Extract all text content from findings for keyword matching."""
    combined_texts = []
    for finding in findings:
        description = finding.get("description", "")
        rule_group = finding.get("rule_group", "")
        recommendation = finding.get("recommendation", "")
        narrative = finding.get("narrative", "")
        combined = f"{description} {rule_group} {recommendation} {narrative}".strip()
        if combined:
            combined_texts.append(combined)
    return combined_texts


def _extract_finding_keywords(finding: dict) -> set[str]:
    """Extract keywords from a single finding's text fields."""
    text = " ".join(
        str(finding.get(key, ""))
        for key in ("description", "rule_group", "recommendation", "narrative")
    )
    return _extract_keywords(text)


def score_findings(
    findings: list[dict | str],
    asd_data: dict,
    overrides_path: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Score findings against Essential Eight strategies.

    Args:
        findings: List of finding dictionaries with description, rule_group, recommendation,
                 or strings that will be converted to dicts.
        asd_data: ASD framework data containing essential_eight entries.
        overrides_path: Path to e8_keyword_overrides.json for per-strategy keyword blocking.

    Returns:
        Dictionary mapping strategy names to {'status', 'related_findings', 'related_controls'}.
        Status is always 'Not assessed'. Empty dict when essential_eight is missing or empty.
    """
    converted_findings = _convert_findings(findings)
    essential_eight = asd_data.get("essential_eight", [])
    if not essential_eight:
        return {}

    overrides = _load_overrides(overrides_path)
    result: dict[str, dict[str, Any]] = {}

    for strategy_entry in essential_eight:
        strategy = strategy_entry.get("strategy", "")
        if not strategy:
            continue

        blocked = overrides.get(strategy.casefold(), set())
        strategy_controls = strategy_entry.get("controls", [])

        # Compute each control's keyword set once: strategy name + description,
        # minus that strategy's blocked keywords.
        control_keyword_sets: list[set[str]] = []
        for control in strategy_controls:
            description = control.get("description", "")
            control_keywords = _extract_keywords(f"{strategy} {description}")
            control_keywords -= blocked
            control_keyword_sets.append(control_keywords)

        scored: list[tuple[dict[str, Any], int, set[str]]] = []
        for control, control_keywords in zip(strategy_controls, control_keyword_sets):
            best_overlap = 0
            for finding in converted_findings:
                finding_keywords = _extract_finding_keywords(finding)
                best_overlap = max(best_overlap, len(control_keywords & finding_keywords))

            if best_overlap >= MIN_E8_MATCH_SCORE:
                scored.append((control, best_overlap, control_keywords))

        # Rank by best overlap descending; ties broken by catalogue order
        scored.sort(key=lambda x: (-x[1], strategy_controls.index(x[0])))
        kept = scored[:MAX_E8_RELATED_CONTROLS]
        kept_controls = [control for control, _, _ in kept]
        kept_keyword_sets = [keywords for _, _, keywords in kept]

        related_findings: list[str] = []
        seen_fids: set[str] = set()
        for finding in converted_findings:
            fid = finding.get("id")
            if not isinstance(fid, str):
                continue
            if fid in seen_fids:
                continue
            finding_keywords = _extract_finding_keywords(finding)
            if any(
                len(finding_keywords & control_keywords) >= MIN_E8_MATCH_SCORE
                for control_keywords in kept_keyword_sets
            ):
                seen_fids.add(fid)
                related_findings.append(fid)

        related_controls = [
            {"id": control["id"], "levels": control.get("levels", [])}
            for control in kept_controls
        ]

        result[strategy] = {
            "status": "Not assessed",
            "related_findings": related_findings,
            "related_controls": related_controls,
        }

    return result


def match_ism_controls(
    findings: list[dict | str],
    asd_data: dict,
    max_controls: int = 15,
    overrides_path: str | None = None,
) -> list[dict]:
    """Match ISM controls to relevant findings using keyword matching.

    Args:
        findings: List of finding dictionaries with description, rule_group, recommendation,
                 or strings that will be converted to dicts.
        asd_data: ASD framework data containing ism entries.
        max_controls: Maximum number of controls to return (default 15).
        overrides_path: Path to e8_keyword_overrides.json for global keyword blocking.

    Returns:
        List of up to max_controls ISM control dictionaries sorted by match score descending.
    """
    converted_findings = _convert_findings(findings)
    # Build findings keyword set
    normalised_text = _normalise_findings(converted_findings)
    all_keywords = set()
    for text in normalised_text:
        all_keywords.update(_extract_keywords(text))

    # Load keyword overrides for ISM matching
    overrides = _load_overrides(overrides_path)
    # Build global blocked set (union of all strategy blocklists)
    global_blocked = set().union(*overrides.values()) if overrides else set()

    # Score each ISM control
    scored_controls = []
    for control in asd_data.get("ism", []):
        keywords = _extract_keywords(control["description"] + " " + control["category"])

        # Remove globally blocked keywords from ISM matching
        control_keywords = keywords - global_blocked
        match_score = len(control_keywords & all_keywords)

        if match_score >= MIN_ISM_MATCH_SCORE:
            scored_controls.append((control, match_score))

    # Sort by match score descending and take top results
    scored_controls.sort(key=lambda x: x[1], reverse=True)
    return [c[0] for c in scored_controls[:max_controls]]
