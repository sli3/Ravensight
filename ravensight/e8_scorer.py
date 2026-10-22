"""Points findings at Essential Eight (E8) strategies and Information Security Manual (ISM) controls.

It gives no compliance verdicts: scored strategies stay "Not assessed" unless the
operator supplies a manual attestation file (see load_attestation).

Callers should pass overrides_path from config:
overrides_path = config.get("e8", {}).get("overrides_path")
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

__all__ = [
    "load_attestation",
    "map_findings_to_controls",
    "match_ism_controls",
    "score_findings",
]

logger = logging.getLogger(__name__)

# Stop words to exclude from keyword extraction
STOP_WORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "that", "this", "these", "those", "it",
    "its", "as", "if", "not", "no", "all", "any", "each", "which", "when",
    "their", "they", "them", "used", "using", "use", "within", "across",
    "than",
}

# Minimum keyword length to include
MIN_KEYWORD_LENGTH = 4

# Minimum match score for ISM control to be included in results
MIN_ISM_MATCH_SCORE = 2

# Minimum keyword overlap for a finding to relate to an Essential Eight control
MIN_E8_MATCH_SCORE = 3

# Maximum related controls returned per strategy
MAX_E8_RELATED_CONTROLS = 3

# Maximum ISM controls and Essential Eight strategies listed per finding
MAX_FINDING_POINTERS = 3

# Generic words that carry no matching signal for pointers. They are removed
# before matching findings against both Essential Eight strategies and ISM
# controls (score_findings, match_ism_controls and map_findings_to_controls).
E8_GENERIC_WORDS = {
    "only", "required", "event", "events", "access", "content",
    "local", "service", "services", "changed", "system", "systems",
    # Boilerplate from recommendations such as "No action required; confirm ..."
    "action", "confirm", "multiple", "expected",
    # Boilerplate from the recommendation template "No action / Monitor / Investigate: the evidence shows ..."
    "evidence", "investigate", "monitor", "shows",
    # Filler in rule descriptions such as "... if there is no ..."
    "there",
}

# Endings removed by _stem, longest first. A stem keeps at least this many letters.
_STEM_SUFFIXES = ("ing", "ed", "es", "s", "e")
_MIN_STEM_LENGTH = 4


def _stem(word: str) -> str:
    """Lightly stem a lowercase word so patched/patches/patch and update/updated/updates agree."""
    for suffix in _STEM_SUFFIXES:
        if not word.endswith(suffix) or len(word) - len(suffix) < _MIN_STEM_LENGTH:
            continue
        if suffix == "s" and word.endswith("ss"):
            continue  # process, access and address keep their final letters
        return word[: -len(suffix)]
    return word


# Generic words and blocklists are compared with stemmed keywords, so stem them too.
_GENERIC_STEMS = {_stem(word) for word in E8_GENERIC_WORDS}


def _stem_all(words: set[str]) -> set[str]:
    """Return the stems of a set of words (blocklist entries are compared with stemmed keywords)."""
    return {_stem(word.lower()) for word in words}


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


_ATTESTATION_LEVELS = {"ML1": 1, "ML2": 2, "ML3": 3}


def load_attestation(
    attestation_path: str | None, asd_data: dict | None = None
) -> dict[str, dict[str, Any]]:
    """Load manual Essential Eight attestations, one entry per strategy.

    File shape: a JSON object keyed by exact (case-sensitive) strategy name, each
    value an object with "status" ("Attested" or "Not applicable"), "reason" (a
    string, may be empty) and, for "Attested" only, "level" ("ML1", "ML2" or "ML3",
    case-insensitive). For "Not applicable" any "level" is ignored and stored as None.
    An entry whose reason starts with "EXAMPLE:" (any case, leading spaces ignored) is a
    shipped placeholder and is skipped.

    Returns:
        Dict of strategy name to {"status", "level", "reason"}. Strategies without a
        valid entry, and all strategies when attestation_path is None, blank or
        unreadable, are {"status": "Not assessed", "level": None, "reason": ""}
        ("Not assessed" means no manual attestation was given).
        Returns {} if asd_data holds no strategies.
    """
    strategies = [
        item["strategy"]
        for item in (asd_data or {}).get("essential_eight", [])
        if isinstance(item, dict) and isinstance(item.get("strategy"), str)
    ]
    result: dict[str, dict[str, Any]] = {
        name: {"status": "Not assessed", "level": None, "reason": ""} for name in strategies
    }
    if not result or attestation_path is None or not attestation_path.strip():
        return result

    path = Path(attestation_path)
    try:
        if not path.is_file():
            logger.warning("e8 attestation file not found at %s", attestation_path)
            return result
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        logger.warning("Failed to load e8 attestation file: %s", e)
        return result

    if not isinstance(data, dict):
        logger.warning("e8 attestation file root is not a JSON object")
        return result

    for name, entry in data.items():
        if name not in result:
            logger.warning("e8 attestation skipping unknown strategy: %r", name)
            continue
        if not isinstance(entry, dict):
            logger.warning("e8 attestation entry for %r is not a JSON object", name)
            continue
        status = entry.get("status")
        if status not in ("Attested", "Not applicable"):
            logger.warning("e8 attestation entry for %r has invalid status: %r", name, status)
            continue
        reason = entry.get("reason")
        if not isinstance(reason, str):
            logger.warning("e8 attestation entry for %r has a non-string reason", name)
            continue
        if reason.strip().casefold().startswith("example:"):
            logger.warning(
                "e8 attestation entry for %r still has the EXAMPLE placeholder reason, skipping",
                name,
            )
            continue
        level: int | None = None
        if status == "Attested":
            raw_level = entry.get("level")
            level = (
                _ATTESTATION_LEVELS.get(raw_level.upper()) if isinstance(raw_level, str) else None
            )
            if level is None:
                logger.warning("e8 attestation entry for %r has invalid level: %r", name, raw_level)
                continue
        result[name] = {"status": status, "level": level, "reason": reason}
    return result


def _convert_findings(findings: list[dict | str]) -> list[dict]:
    """Convert string findings to dict format for processing.

    Args:
        findings: List of strings or dicts.

    Returns:
        List of dictionaries where strings are wrapped with description and recommendation fields.
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
                "recommendation": ""
            })
    return converted


def _extract_keyword_map(text: str) -> dict[str, str]:
    """Map each stemmed keyword in a text to the first original word that produced it."""
    # Lowercase and split on whitespace/punctuation
    tokens = re.split(r'[\s\W]+', text.lower())

    # Filter stop words, short tokens, and pure numeric tokens
    keywords: dict[str, str] = {}
    for token in tokens:
        if not token:
            continue
        if len(token) < MIN_KEYWORD_LENGTH:
            continue
        if token.isdigit():
            continue
        if token in STOP_WORDS:
            continue
        keywords.setdefault(_stem(token), token)

    return keywords


def _extract_keywords(text: str) -> set[str]:
    """Extract meaningful stemmed keywords from a text string."""
    return set(_extract_keyword_map(text))


def _normalise_findings(findings: list[dict]) -> list[str]:
    """Extract description and recommendation text per finding for ISM matching.

    The LLM narrative is left out: it is long, loose and different every run.
    """
    combined_texts = []
    for finding in findings:
        description = finding.get("description", "")
        recommendation = finding.get("recommendation", "")
        combined = f"{description} {recommendation}".strip()
        if combined:
            combined_texts.append(combined)
    return combined_texts


def _finding_keyword_map(finding: dict) -> dict[str, str]:
    """Map stemmed keywords to original words across a finding's text fields."""
    text = " ".join(
        str(finding.get(key, ""))
        for key in ("description", "recommendation", "narrative")
    )
    return _extract_keyword_map(text)


def _extract_finding_keywords(finding: dict) -> set[str]:
    """Extract keywords from a single finding's text fields."""
    return set(_finding_keyword_map(finding))


def _e8_control_keywords(strategy: str, control: dict, blocked: set[str]) -> set[str]:
    """Keywords for one Essential Eight control: strategy name and description, minus blocked and generic words."""
    description = control.get("description", "")
    return _extract_keywords(f"{strategy} {description}") - _stem_all(blocked) - _GENERIC_STEMS


def _ism_control_keywords(control: dict, global_blocked: set[str]) -> set[str]:
    """Keywords for one ISM control: description and category, minus blocked and generic words."""
    keywords = _extract_keywords(control["description"] + " " + control["category"])
    return keywords - _stem_all(global_blocked) - _GENERIC_STEMS


def score_findings(
    findings: list[dict | str],
    asd_data: dict,
    overrides_path: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Score findings against Essential Eight strategies.

    Args:
        findings: List of finding dictionaries with description, recommendation,
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
        # minus that strategy's blocked keywords and the generic words.
        control_keyword_sets: list[set[str]] = []
        for control in strategy_controls:
            control_keyword_sets.append(_e8_control_keywords(strategy, control, blocked))

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
        findings: List of finding dictionaries with description, recommendation,
                 or strings that will be converted to dicts.
        asd_data: ASD framework data containing ism entries.
        max_controls: Maximum number of controls to return (default 15).
        overrides_path: Path to e8_keyword_overrides.json for global keyword blocking.

    Returns:
        List of up to max_controls ISM control dictionaries sorted by match score descending.
    """
    converted_findings = _convert_findings(findings)
    # One keyword set per finding, so a control must match within a single finding
    finding_keyword_sets = [
        _extract_keywords(text) - _GENERIC_STEMS
        for text in _normalise_findings(converted_findings)
    ]

    # Load keyword overrides for ISM matching
    overrides = _load_overrides(overrides_path)
    # Build global blocked set (union of all strategy blocklists)
    global_blocked = set().union(*overrides.values()) if overrides else set()

    # Score each ISM control
    scored_controls = []
    for control in asd_data.get("ism", []):
        control_keywords = _ism_control_keywords(control, global_blocked)
        match_score = max(
            (len(control_keywords & found) for found in finding_keyword_sets),
            default=0,
        )

        if match_score >= MIN_ISM_MATCH_SCORE:
            scored_controls.append((control, match_score))

    # Sort by match score descending and take top results
    scored_controls.sort(key=lambda x: x[1], reverse=True)
    return [c[0] for c in scored_controls[:max_controls]]


def map_findings_to_controls(
    findings: list[dict | str],
    asd_data: dict,
    overrides_path: str | None = None,
) -> list[dict[str, Any]]:
    """Map each finding to the ISM controls and Essential Eight strategies it points at.

    Args:
        findings: List of finding dictionaries; findings without a string id are skipped.
        asd_data: ASD framework data containing essential_eight and ism entries.
        overrides_path: Path to e8_keyword_overrides.json for keyword blocking.

    Returns:
        One dict per finding: {"id", "ism", "e8"}. Each ism entry has id, category and
        shared (the words that matched); each e8 entry has strategy and shared. At most
        MAX_FINDING_POINTERS entries per framework, best match first.
    """
    converted_findings = [
        f for f in _convert_findings(findings) if isinstance(f.get("id"), str)
    ]
    overrides = _load_overrides(overrides_path)
    global_blocked = set().union(*overrides.values()) if overrides else set()
    scoring_input: list[dict | str] = [*converted_findings]
    e8_scores = score_findings(scoring_input, asd_data, overrides_path=overrides_path)
    e8_controls = {
        entry.get("strategy", ""): {c.get("id"): c for c in entry.get("controls", [])}
        for entry in asd_data.get("essential_eight", [])
    }

    pointers: list[dict[str, Any]] = []
    for finding in converted_findings:
        finding_id = finding["id"]

        # Matching uses stems; "shared" shows the finding's own words so the report reads naturally.
        texts = _normalise_findings([finding])
        ism_words = _extract_keyword_map(texts[0]) if texts else {}
        ism_finding_keywords = set(ism_words) - _GENERIC_STEMS
        ism_hits: list[tuple[int, str, dict, list[str]]] = []
        for control in asd_data.get("ism", []):
            shared = sorted(_ism_control_keywords(control, global_blocked) & ism_finding_keywords)
            if len(shared) >= MIN_ISM_MATCH_SCORE:
                words = sorted(ism_words[stem] for stem in shared)
                ism_hits.append((len(shared), control.get("id", ""), control, words))
        ism_hits.sort(key=lambda hit: (-hit[0], hit[1]))

        # Same word source as score_findings, so this agrees with the E8 table.
        e8_words = _finding_keyword_map(finding)
        e8_finding_keywords = set(e8_words)
        e8_hits: list[dict[str, Any]] = []
        for strategy, row in e8_scores.items():
            if finding_id not in row["related_findings"]:
                continue
            blocked = overrides.get(strategy.casefold(), set())
            shared_words: set[str] = set()
            for related in row["related_controls"]:
                control = e8_controls.get(strategy, {}).get(related["id"])
                if control is None:
                    continue
                shared = _e8_control_keywords(strategy, control, blocked) & e8_finding_keywords
                if len(shared) >= MIN_E8_MATCH_SCORE:
                    shared_words |= shared
            e8_hits.append(
                {"strategy": strategy, "shared": sorted(e8_words[stem] for stem in shared_words)}
            )
        e8_hits.sort(key=lambda hit: (-len(hit["shared"]), hit["strategy"]))

        pointers.append({
            "id": finding_id,
            "ism": [
                {"id": control.get("id", ""), "category": control.get("category", ""), "shared": shared}
                for _, _, control, shared in ism_hits[:MAX_FINDING_POINTERS]
            ],
            "e8": e8_hits[:MAX_FINDING_POINTERS],
        })

    return pointers
