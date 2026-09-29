"""Essential Eight compliance scoring and ISM control matching module.

Callers should pass overrides_path from config:
overrides_path = config.get("e8", {}).get("overrides_path")
"""

import json
import logging
import re
from pathlib import Path

__all__ = ["score_findings", "match_ism_controls"]

logger = logging.getLogger(__name__)

__all__ = ["score_findings", "match_ism_controls"]

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


def _load_overrides(overrides_path: str | None) -> dict[str, set[str]]:
    """
    Load per-strategy keyword blocklists from override file.

    Args:
        overrides_path: Path to e8_keyword_overrides.json, or None.

    Returns:
        Dict mapping strategy name to set of blocked keywords.
        Returns empty dict if path is None or file is unreadable.
    """
    if overrides_path is None:
        return {}

    try:
        path = Path(overrides_path)
        if not path.is_file():
            logger.warning("e8_keyword_overrides.json not found at %s", overrides_path)
            return {}

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        blocklist = data.get("strategy_blocklist", {})
        # Convert lists to sets for O(1) lookup
        return {k: set(v) for k, v in blocklist.items()}

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


def score_findings(
    findings: list[dict | str],
    asd_data: dict,
    overrides_path: str | None = None,
) -> dict[str, dict[int, bool]]:
    """Score findings against Essential Eight strategies.
    
    Args:
        findings: List of finding dictionaries with description, rule_group, recommendation,
                 or strings that will be converted to dicts.
        asd_data: ASD framework data containing essential_eight entries.
        overrides_path: Path to e8_keyword_overrides.json for per-strategy keyword blocking.
    
    Returns:
        Dictionary mapping strategy names to maturity level scores (1-4, True=passing).
    """
    findings = _convert_findings(findings)
    # Build findings keyword set
    normalised_text = _normalise_findings(findings)
    all_keywords = set()
    for text in normalised_text:
        all_keywords.update(_extract_keywords(text))
    
    # Derive unique strategies in order from asd_data
    unique_strategies = []
    seen = set()
    for entry in asd_data["essential_eight"]:
        strategy = entry["strategy"]
        if strategy not in seen:
            unique_strategies.append(strategy)
            seen.add(strategy)
    
    # Initialise all scores to True (passing)
    scores = {
        strategy: {1: True, 2: True, 3: True, 4: True}
        for strategy in unique_strategies
    }
    
    # Load keyword overrides
    overrides = _load_overrides(overrides_path)

    # Process each E8 entry and mark failures
    for entry in asd_data["essential_eight"]:
        keywords = _extract_keywords(entry["strategy"] + " " + entry["description"])

        # Remove blocked keywords for this strategy
        strategy = entry["strategy"]
        blocked = overrides.get(strategy, set())
        keywords -= blocked

        if keywords & all_keywords:  # Any overlap
            ml_level = entry["maturity_level"]

            # Mark this level and all higher levels as failing
            for level in range(ml_level, 5):
                scores[strategy][level] = False
    
    return scores


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
    findings = _convert_findings(findings)
    # Build findings keyword set
    normalised_text = _normalise_findings(findings)
    all_keywords = set()
    for text in normalised_text:
        all_keywords.update(_extract_keywords(text))
    
    # Load keyword overrides for ISM matching
    overrides = _load_overrides(overrides_path)
    # Build global blocked set (union of all strategy blocklists)
    global_blocked = set().union(*overrides.values()) if overrides else set()

    # Score each ISM control
    scored_controls = []
    for control in asd_data["ism"]:
        keywords = _extract_keywords(control["description"] + " " + control["category"])
        
        # Remove globally blocked keywords from ISM matching
        control_keywords = keywords - global_blocked
        match_score = len(control_keywords & all_keywords)
        
        if match_score >= MIN_ISM_MATCH_SCORE:
            scored_controls.append((control, match_score))
    
    # Sort by match score descending and take top results
    scored_controls.sort(key=lambda x: x[1], reverse=True)
    return [c[0] for c in scored_controls[:max_controls]]
