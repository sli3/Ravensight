"""
analyser.py — LLM-based security alert analysis via OpenAI-compatible REST API.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from chromadb.errors import ChromaError
from openai import OpenAI
from openai import APIConnectionError, APIStatusError, APITimeoutError
from tqdm import tqdm


def _load_asd_data(asd_path: str) -> dict:
    """Load ASD framework data from local JSON file.

    Args:
        asd_path: Path to data/asd_framework.json

    Returns:
        Parsed ASD data dict, or empty dict if file absent or unreadable.
    """
    try:
        with Path(asd_path).open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"ASD framework file not found: {asd_path}")
        return {}
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse ASD framework file {asd_path}: {e}")
        return {}


def _build_asd_context(asd_data: dict) -> str:
    """Build a compact ASD control reference string for LLM prompt injection.

    Args:
        asd_data: Parsed ASD framework data from _load_asd_data().

    Returns:
        Formatted string for prompt injection, or empty string if no data.
    """
    if not asd_data:
        return ""

    lines = []

    # Section 1 — Essential Eight summary (one line per strategy showing ML range)
    essential_eight = asd_data.get("essential_eight", [])
    strategies: dict[str, list[int]] = {}
    for entry in essential_eight:
        strategy = entry.get("strategy", "")
        ml = entry.get("maturity_level", 0)
        if strategy not in strategies:
            strategies[strategy] = []
        strategies[strategy].append(ml)

    lines.append("Essential Eight Strategies:")
    for strategy, mls in strategies.items():
        min_ml = min(mls)
        max_ml = max(mls)
        ml_range = f"ML{min_ml}-ML{max_ml}" if min_ml < max_ml else f"ML{min_ml}"
        lines.append(f"- {strategy} ({ml_range})")

    # Section 2 — ISM controls grouped by category (compact format)
    ism_controls = asd_data.get("ism", [])
    if ism_controls:
        lines.append("")
        lines.append("Relevant ISM Controls:")

        # Group by category
        by_category: dict[str, list[dict]] = {}
        for control in ism_controls:
            cat = control.get("category", "Uncategorized")
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(control)

        for category, controls in by_category.items():
            lines.append(f"{category}:")
            for control in controls:
                desc = control.get("description", "")
                # Truncate to 120 characters
                truncated = desc[:120] if len(desc) > 120 else desc
                # Remove newlines for compact format and strip trailing whitespace
                truncated = " ".join(truncated.split())
                lines.append(f"  {control.get('id', 'Unknown')}: {truncated}")

    return "\n".join(lines)

logger = logging.getLogger(__name__)


def _load_mitre_tactics(path: str) -> list[dict[str, Any]]:
    """Load MITRE tactics from local JSON file."""
    try:
        with Path(path).open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("tactics", [])
    except FileNotFoundError:
        logger.warning(f"MITRE tactics file not found: {path}")
        return []


def _build_mitre_reference(tactics: list[dict[str, Any]]) -> str:
    """Build compact MITRE tactic reference for prompt."""
    parts = []
    for tactic in tactics:
        name = tactic.get("name", "Unknown")
        shortname = tactic.get("shortname", "")
        if shortname:
            parts.append(f"{name} ({shortname})")
        else:
            parts.append(name)
    return ", ".join(parts)


def _load_platform_hints(hints_path: str) -> dict:
    """Load platform false positive hints from local JSON file.

    Returns empty dict if the file is absent or malformed — run is never blocked.
    """
    try:
        with Path(hints_path).open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Platform hints file not found: {hints_path}")
        return {}
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse platform hints file {hints_path}: {e}")
        return {}


def _build_platform_context(alerts: list[dict[str, Any]], hints: dict) -> str:
    """Build platform context block for prompt injection.

    Extracts distinct agent.os.platform values from the alert batch, looks up
    matching hints for the rule IDs present, and returns a formatted context block.
    Returns an empty string if no platform matches are found — caller skips silently.
    Alerts with null _source/agent/os/platform/rule fields are skipped silently.
    """
    if not hints:
        return ""

    # Collect distinct platforms and representative agent info
    seen_platforms: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        source = alert.get("_source")
        if source is None:
            continue
        agent = source.get("agent")
        if agent is None:
            continue
        os_info = agent.get("os")
        if os_info is None:
            continue
        platform = os_info.get("platform")
        if platform is None:
            continue
        platform = platform.lower()
        if not platform:
            continue
        if platform not in seen_platforms:
            agent_name = agent.get("name")
            if agent_name is None:
                agent_name = "unknown"
            os_name = os_info.get("name", platform)
            seen_platforms[platform] = {
                "agent_name": agent_name,
                "os_name": os_name,
            }

    if not seen_platforms:
        return ""

    # Collect all rule IDs present in this alert batch
    batch_rule_ids: set[str] = set()
    for alert in alerts:
        source = alert.get("_source")
        if source is None:
            continue
        rule = source.get("rule")
        if rule is None:
            continue
        raw_rule_id = rule.get("id")
        if raw_rule_id is None:
            continue
        rule_id = str(raw_rule_id)
        if rule_id:
            batch_rule_ids.add(rule_id)

    blocks: list[str] = []
    for platform, info in seen_platforms.items():
        platform_hints = hints.get(platform)
        if not platform_hints:
            continue

        description = platform_hints.get("description", platform)
        filesystem_notes = platform_hints.get("filesystem_notes", "")
        rules = platform_hints.get("rules", {})

        # Only inject rule hints whose rule IDs appear in this batch
        matching_hints: list[str] = []
        for rule_id, rule_info in rules.items():
            if rule_id in batch_rule_ids:
                paths = rule_info.get("paths", [])
                hint = rule_info.get("hint", "")
                if hint:
                    paths_str = ", ".join(paths) if paths else "any path"
                    matching_hints.append(f"  - Rule {rule_id} on {paths_str}: {hint}")

        # Skip this platform block entirely if there's nothing useful to inject
        if not matching_hints and not filesystem_notes:
            continue

        lines = [f"- Agent: {info['agent_name']} ({platform} — {description})"]
        if filesystem_notes:
            lines.append(f"- Filesystem notes: {filesystem_notes}")
        if matching_hints:
            lines.append("- Known false positives for this platform:")
            lines.extend(matching_hints)

        blocks.append("\n".join(lines))

    if not blocks:
        return ""

    return "Platform context:\n" + "\n\n".join(blocks)


def analyse(
    alerts: list[dict[str, Any]],
    baseline: dict[str, Any],
    llm_config: dict[str, Any],
    embedder=None,
    mitre_path: str | None = None,
    platform_hints_path: str | None = None,
    asd_path: str | None = None,
    show_progress: bool = False,
    lookback_hours: int | None = None,
) -> dict[str, Any]:
    """
    Analyse security alerts using a remote LLM server.

    Args:
        alerts: List of alert dicts from wazuh_client.fetch_alerts()
        baseline: Previous baseline data from baseline.Manager.load()
        llm_config: LLM config section with base_url, api_key, model, etc.
        embedder: Optional Embedder instance for retrieving similar incidents
       mitre_path: Optional path to MITRE tactics JSON file
        platform_hints_path: Optional path to platform false positive hints JSON file;
            defaults to "data/platform_hints.json" if not supplied
        asd_path: Optional path to ASD framework JSON file
        lookback_hours: Report window in hours — similar incidents within this
            window are dropped from the prompt. None disables filtering.

    Returns:
        Analysis dict with summary, findings, and recommendations.
    """
    if not alerts:
        logger.info("No alerts to analyse")
        return {"summary": "No alerts", "findings": [], "recommendations": []}

    client = OpenAI(
        base_url=llm_config["base_url"],
        api_key=llm_config["api_key"],
        timeout=300.0,
    )

    similar_incidents = ""
    formatted: list[str] = []
    if embedder is not None and not embedder.degraded:
        query_text = _summarise_alerts(alerts)
        try:
            similar = embedder.retrieve_similar(query_text)
        except (APIConnectionError, APITimeoutError, ValueError, ChromaError, httpx.HTTPError, OSError) as e:
            logger.warning(
                f"Similarity retrieval failed ({type(e).__name__}: {e}) — "
                "similar-incident context skipped this run"
            )
            similar = None
        if similar:
            similar = filter_similar_by_window(similar, lookback_hours)
            for item in similar:
                summary = item.get("summary", "")
                timestamp = item.get("timestamp", "")
                severity = item.get("severity", "")
                if severity and severity != "unknown":
                    formatted.append(f"- {timestamp} ({severity}): {summary}")
                else:
                    formatted.append(f"- {timestamp}: {summary}")
            if formatted:
                similar_incidents = (
                    "\nSimilar past incidents (from before this report window):\n"
                    + "\n".join(formatted)
                )

    tactics = []
    if mitre_path and Path(mitre_path).exists():
        try:
            tactics = _load_mitre_tactics(mitre_path)
        except Exception as e:
            logger.warning(f"Failed to load MITRE tactics: {e}")

    hints_file = platform_hints_path or "data/platform_hints.json"
    platform_hints = _load_platform_hints(hints_file)
    platform_context = _build_platform_context(alerts, platform_hints)
    if platform_context:
        logger.debug("Platform context injected into prompt")

    asd_data = _load_asd_data(asd_path) if asd_path else {}
    asd_context = _build_asd_context(asd_data)

    prompt = _build_prompt(
        alerts,
        baseline,
        similar_incidents=similar_incidents,
        tactics=tactics,
        platform_context=platform_context,
        asd_context=asd_context,
    )

    try:
        full_text = ""
        stream = client.chat.completions.create(
            model=llm_config["model"],
            messages=[{"role": "user", "content": prompt}],
            temperature=llm_config.get("temperature", 0.3),
            max_tokens=llm_config.get("max_tokens", 8192),
            presence_penalty=0.0,
            frequency_penalty=0.0,
            stream=True,
        )
        with tqdm(
            total=None,
            desc="Analysing",
            unit=" tok",
            disable=not show_progress,
        ) as bar:
            for chunk in stream:
                content = chunk.choices[0].delta.content or ""
                full_text += content
                if content:
                    bar.update(1)
    except APIConnectionError as e:
        logger.error(f"Failed to connect to LLM server: {e}")
        raise
    except APIStatusError as e:
        logger.error(f"LLM server returned error status: {e}")
        raise

    analysis_text = full_text.strip()
    ## For debugging DO NOT REMOVE ##
    logger.debug(f"Raw API response: {full_text!r}")
    logger.debug(f"Raw LLM response: {analysis_text[:1000]}")
    ##################################

    result = _parse_analysis(analysis_text, tactics=tactics)
    if formatted:
        result["similar_incidents"] = "\n".join(formatted)
    return result


def filter_similar_by_window(
    items: list[dict[str, Any]],
    lookback_hours: int | None,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """
    Drop items whose timestamp falls within the report window.

    An item is dropped when its parsed timestamp is at or after
    ``now - lookback_hours``. Items with missing or unparseable timestamps are
    kept (and DEBUG-logged). ``lookback_hours`` of None returns the list unchanged.

    Args:
        items: List of similar-incident dicts from embedder.retrieve_similar().
            Each item exposes a ``timestamp`` field (ISO string or empty).
        lookback_hours: Window in hours. None disables filtering.
        now: Override for the current time — useful in tests. When None, the
            naive cutoff uses ``datetime.now()`` and the aware cutoff uses
            ``datetime.now(timezone.utc)``.

    Returns:
        A new list containing only items older than the window.
    """
    if lookback_hours is None:
        return items
    if not items:
        return items

    naive_now = now if now is not None else datetime.now()
    aware_now = now if (now is not None and now.tzinfo is not None) else datetime.now(timezone.utc)
    naive_cutoff = naive_now - timedelta(hours=lookback_hours)
    aware_cutoff = aware_now - timedelta(hours=lookback_hours)

    filtered: list[dict[str, Any]] = []
    for item in items:
        ts_raw = item.get("timestamp", "")
        if not ts_raw:
            logger.debug("similar-incident item missing timestamp — kept")
            filtered.append(item)
            continue
        try:
            parsed = datetime.fromisoformat(ts_raw)
        except (TypeError, ValueError):
            logger.debug(
                f"similar-incident item has unparseable timestamp {ts_raw!r} — kept"
            )
            filtered.append(item)
            continue

        try:
            if parsed.tzinfo is None:
                if parsed >= naive_cutoff:
                    continue
            else:
                if parsed >= aware_cutoff:
                    continue
        except TypeError:
            logger.debug("similar-incident item timestamp tz mismatch — kept")
            filtered.append(item)
            continue

        filtered.append(item)
    return filtered


def _build_prompt(
    alerts: list[dict[str, Any]],
    baseline: dict[str, Any],
    similar_incidents: str = "",
    tactics: list = [],
    platform_context: str = "",
    asd_context: str = "",
) -> str:
    """Build prompt with alert summary and similar incidents."""
    alert_summary = _summarise_alerts(alerts)

    mitre_reference = ""
    if tactics:
        mitre_reference = f"\nMITRE ATT&CK Tactics reference: {_build_mitre_reference(tactics)}"

    platform_block = f"\n{platform_context}\n" if platform_context else ""

    asd_block = f"\nASD Framework Context:\n{asd_context}" if asd_context else ""

    return f"""You are a security analyst. Analyse these Wazuh alerts and provide findings.
{platform_block}
Recent alerts:
{alert_summary}

{similar_incidents}
{mitre_reference}
{asd_block}

Tag each finding with the most relevant MITRE ATT&CK tactic using exact tactic names from the reference above:
<mitre_tags>
- Persistence: Rootkit installed to maintain access across reboots
- Defense Evasion: File integrity tampering to hide malicious changes
</mitre_tags>

Provide your analysis in this format:
<findings>
- Finding 1
- Finding 2
</findings>
<recommendations>
- Recommendation 1
- Recommendation 2
</recommendations>"""


def _summarise_alerts(alerts: list[dict[str, Any]]) -> str:
    """Create a summary of alerts for the LLM."""
    by_rule: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        source = alert.get("_source", {})
        rule = source.get("rule", {}).get("description", "Unknown")
        level = source.get("rule", {}).get("level", 0)
        agent = source.get("agent", {}).get("name", "Unknown")
        if rule not in by_rule:
            by_rule[rule] = {"count": 0, "level": level, "agents": set()}
        by_rule[rule]["count"] += 1
        by_rule[rule]["agents"].add(agent)

    lines = [
        f"- {rule}: {d['count']} alerts (level {d['level']}, agents: {', '.join(d['agents'])})"
        for rule, d in by_rule.items()
    ]
    return "\n".join(lines)


def extract_rule_counts(alerts: list[dict[str, Any]]) -> dict[str, int]:
    """
    Extract per-rule-group alert counts from raw alerts.

    Args:
        alerts: List of alert dicts from wazuh_client.fetch_alerts()

    Returns:
        Dict mapping rule description to alert count.
    """
    rule_counts: dict[str, int] = {}
    for alert in alerts:
        source = alert.get("_source", {})
        rule = source.get("rule", {})
        description = rule.get("description", "Unknown")
        rule_counts[description] = rule_counts.get(description, 0) + 1
    return rule_counts


def _parse_analysis(text: str, tactics: list[dict[str, Any]] = []) -> dict[str, Any]:
    """Parse LLM response into structured dict."""
    findings: list[str] = []
    recommendations: list[str] = []
    mitre_tags: list[dict[str, str]] = []

    # Build tactic lookup for parsing — maps lowercase tactic name to display name
    tactic_lookup: dict[str, str] = {}
    for t in tactics:
        name = t.get("name", "")
        shortname = t.get("shortname", "")
        if name:
            tactic_lookup[name.lower()] = name
        if shortname:
            tactic_lookup[shortname.lower()] = name

    ## For debugging DO NOT REMOVE ##
    logger.debug(f"Raw LLM response: {text[:1000]}")
    ##################################

    current_section: str | None = None
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("<findings>"):
            current_section = "findings"
        elif line.startswith("</findings>"):
            current_section = None
        elif line.startswith("<recommendations>"):
            current_section = "recommendations"
        elif line.startswith("</recommendations>"):
            current_section = None
        elif line.startswith("<mitre_tags>"):
            current_section = "mitre_tags"
        elif line.startswith("</mitre_tags>"):
            current_section = None
        elif line.startswith("- ") and current_section == "findings":
            findings.append(line[2:])
        elif line.startswith("- ") and current_section == "recommendations":
            recommendations.append(line[2:])
        elif line.startswith("- ") and current_section == "mitre_tags":
            tag_text = line[2:]
            if ":" in tag_text:
                tactic_part = tag_text.split(":", 1)[0].strip()
                description = tag_text.split(":", 1)[1].strip()
                # Look up canonical tactic name, fall back to what the LLM wrote
                matched_tactic = tactic_lookup.get(tactic_part.lower(), tactic_part)
                mitre_tags.append({"tactic": matched_tactic, "description": description})

    return {
        "summary": findings[0][:200] + "..." if findings and len(findings[0]) > 200 else findings[0] if findings else "No summary available",
        "findings": findings,
        "recommendations": recommendations,
        "mitre_tags": mitre_tags,
    }