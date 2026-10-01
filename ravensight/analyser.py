"""
analyser.py — LLM-based security alert analysis via OpenAI-compatible REST API.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from chromadb.errors import ChromaError
from openai import OpenAI
from openai import APIConnectionError, APIStatusError, APITimeoutError

from ravensight import evidence

if TYPE_CHECKING:
    from ravensight.ui import RunReporter

MAX_PROMPT_CLUSTERS = 40
MAX_PROMPT_CVES = 10
MAX_SIMILARITY_QUERY_CHARS = 4000

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_PACKAGE_FALLBACK_RE = re.compile(r"^CVE-\d{4}-\d{4,}\s+affects\s+(.+)$")
_CLUSTER_REF_RE = re.compile(r"^\**\s*\[?\s*C(\d+)\s*\]?\s*\**[\s:\-]*", re.IGNORECASE)
_STRAY_FINDING_RE = re.compile(r"^Finding\s+\d+\s*[:\-]\s*", re.IGNORECASE)

RULE_87702_IPV6_ARTEFACT_NOTE = (
    "Wazuh rule 87702 groups IPv6 filterlog by a misdecoded field — its "
    "same-source wording and T1110 tag do not describe the real sources shown "
    "in the evidence"
)

_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

_KNOWN_PROVIDERS = (
    "Cloudflare", "Google", "Amazon", "AWS", "Azure", "Microsoft",
    "Hetzner", "OVH", "DigitalOcean", "Akamai", "Fastly", "Linode",
    "Vultr", "Oracle", "Alibaba", "Tencent", "Apple", "Meta", "Facebook",
)

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_PATH_RE = re.compile(r"(?<![\w/])/(?:[\w.-]+/)+[\w.-]+")
_PORT_WORD_RE = re.compile(r"\b(?:d?ports?)\s+(\d{1,5})\b")
_PORT_PROTO_RE = re.compile(r"\b(\d{1,5})/(?:tcp|udp)\b")
_IPV4_TOKEN_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
_COUNT_CLAIM_RE = re.compile(
    r"\b(\d+)\s+(?:[A-Za-z0-9-]+\s+){0,2}"
    r"(sources?|hosts?|alerts?|attempts?|events?|files?|addresses|connections?)\b"
)


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


def _load_platform_agents(path: str | None) -> dict:
    """Load Wazuh agent-name → vendor/platform map from local JSON file.

    Defaults to 'data/platform_agents.json' when path is None. Missing or
    unreadable file = today's behaviour (no host facts block), logged once
    at DEBUG. Malformed entries (non-dict values, missing keys) are
    skipped with a DEBUG log each.
    """
    chosen = path or "data/platform_agents.json"
    try:
        with Path(chosen).open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        logger.debug(f"Platform agents file not found: {chosen}")
        return {}
    except json.JSONDecodeError as e:
        logger.debug(f"Failed to parse platform agents file {chosen}: {e}")
        return {}
    if not isinstance(raw, dict):
        logger.debug(f"Platform agents file {chosen} is not a JSON object")
        return {}
    result: dict[str, dict[str, str]] = {}
    for name, info in raw.items():
        if not isinstance(info, dict):
            logger.debug(f"Platform agents entry {name!r} is not a dict — skipped")
            continue
        platform = info.get("platform")
        vendor = info.get("vendor")
        if not isinstance(platform, str) or not isinstance(vendor, str):
            logger.debug(f"Platform agents entry {name!r} missing platform/vendor — skipped")
            continue
        key = name.casefold()
        if key in result:
            logger.warning(
                f"Duplicate platform agents key after casefolding: {name!r} — keeping first"
            )
            continue
        result[key] = {"platform": platform, "vendor": vendor}
    return result


def _build_platform_context(
    alerts: list[dict[str, Any]],
    hints: dict,
    platform_agents: dict | None = None,
) -> str:
    """Build platform context block for prompt injection.

    Extracts distinct agent.os.platform values from the alert batch, looks up
    matching hints for the rule IDs present, and returns a formatted context block.
    Returns an empty string if no platform matches are found — caller skips silently.
    Alerts with null _source/agent/os/platform/rule fields are skipped silently.
    When agent.os.platform is missing or empty, falls back to the
    platform_agents agent-name map.
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
        platform = os_info.get("platform") if isinstance(os_info, dict) else None
        if not platform and platform_agents:
            agent_name = agent.get("name")
            if isinstance(agent_name, str):
                mapped = platform_agents.get(agent_name.casefold())
                if isinstance(mapped, dict):
                    platform = mapped.get("platform")
        if platform is None:
            continue
        platform = platform.lower()
        if not platform:
            continue
        if platform not in seen_platforms:
            agent_name = agent.get("name")
            if agent_name is None:
                agent_name = "unknown"
            os_name = os_info.get("name", platform) if isinstance(os_info, dict) else platform
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


def severity_from_level(level: Any) -> str:
    """Map a Wazuh rule level to a High/Medium/Low severity label."""
    try:
        value = int(level)
    except (TypeError, ValueError):
        value = 0
    if 12 <= value <= 16:
        return "High"
    if 7 <= value <= 11:
        return "Medium"
    return "Low"


def _coerce_level(raw_level: Any) -> int:
    """Coerce a rule level to int, treating anything non-numeric as 0."""
    try:
        return int(raw_level)
    except (TypeError, ValueError):
        return 0


def extract_alert_clusters(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group raw alerts into data-built clusters for analysis.

    Vulnerability alerts group by (agent name, package); all other alerts
    group by rule description alone, so hosts merge across agents. Counts,
    hosts, severities, timestamps and CVE lists all come from alert data.

    Args:
        alerts: List of alert dicts from wazuh_client.fetch_alerts().

    Returns:
        Cluster dicts ordered by severity, then count descending, then
        description ascending, with ids assigned C1..Cn after ordering.
    """
    vuln_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    rule_by_desc: dict[str, dict[str, Any]] = {}
    dpkg_records: dict[
        tuple[str, str], list[tuple[str, str, dict[str, Any]]]
    ] = {}

    for alert in alerts:
        source = alert.get("_source") or {}
        rule = source.get("rule") or {}
        data = source.get("data")
        if not isinstance(data, dict):
            data = {}
        vuln = data.get("vulnerability")
        rule_groups = rule.get("groups") or []
        description = rule.get("description") or "Unknown"
        agent = source.get("agent") or {}
        host = agent.get("name") or "unknown"
        level = _coerce_level(rule.get("level", 0))
        timestamp = source.get("@timestamp") or source.get("timestamp") or ""
        rule_id = rule.get("id")
        rule_id_str = None if rule_id is None else str(rule_id)

        is_vulnerability = (isinstance(vuln, dict) and bool(vuln)) or (
            "vulnerability-detector" in rule_groups
        )

        cves: list[str] = []
        if is_vulnerability:
            package = None
            if isinstance(vuln, dict):
                pkg = vuln.get("package") or {}
                if isinstance(pkg, dict):
                    package = pkg.get("name")
            if not package:
                match = _PACKAGE_FALLBACK_RE.match(description)
                if match:
                    package = match.group(1).strip()
            if isinstance(vuln, dict) and vuln.get("cve"):
                cves = [str(vuln["cve"])]
            else:
                cves = _CVE_RE.findall(description)
            key = (host, package) if package else (host, description)
            cluster = vuln_by_key.get(key)
            if cluster is None:
                cluster = _new_cluster("vulnerability", description, package)
                vuln_by_key[key] = cluster
        else:
            cluster = rule_by_desc.get(description)
            if cluster is None:
                cluster = _new_cluster("rule", description, None)
                rule_by_desc[description] = cluster

        cluster["count"] += 1
        if rule_id_str:
            cluster["rule_ids"].add(rule_id_str)
        cluster["hosts"].add(host)
        cluster["max_level"] = max(cluster["max_level"], level)
        if timestamp:
            if not cluster["first_seen"] or timestamp < cluster["first_seen"]:
                cluster["first_seen"] = timestamp
            if not cluster["last_seen"] or timestamp > cluster["last_seen"]:
                cluster["last_seen"] = timestamp
        cluster["cves"].update(cves)
        evidence.accumulate(cluster["evidence_acc"], alert)
        if cluster["type"] == "rule":
            evidence.accumulate(cluster["host_accs"].setdefault(host, {}), alert)
        dpkg = evidence.dpkg_event(alert)
        if dpkg is not None and dpkg[1] in ("half-configured", "installed"):
            dpkg_records.setdefault((host, dpkg[0]), []).append(
                (timestamp, dpkg[1], cluster["evidence_acc"])
            )

    ordered = list(vuln_by_key.values()) + list(rule_by_desc.values())
    for cluster in ordered:
        if cluster["type"] == "vulnerability" and cluster["package"]:
            n_cves = len(cluster["cves"])
            if n_cves > 1:
                cluster["description"] = (
                    f"{n_cves} vulnerabilities affect {cluster['package']}"
                )

    ordered.sort(
        key=lambda c: (
            _SEVERITY_ORDER[severity_from_level(c["max_level"])],
            -c["count"],
            c["description"],
        )
    )

    clusters: list[dict[str, Any]] = []
    for index, cluster in enumerate(ordered, start=1):
        output: dict[str, Any] = {
            "id": f"C{index}",
            "type": cluster["type"],
            "description": cluster["description"],
            "rule_ids": sorted(cluster["rule_ids"]),
            "hosts": sorted(cluster["hosts"]),
            "count": cluster["count"],
            "max_level": cluster["max_level"],
            "severity": severity_from_level(cluster["max_level"]),
            "first_seen": cluster["first_seen"],
            "last_seen": cluster["last_seen"],
            "cves": sorted(cluster["cves"]),
            "package": cluster["package"],
            "narrative": "",
            "recommendation": "",
            "notes": [],
        }
        evidence_dict = evidence.project_evidence(cluster["evidence_acc"])
        if evidence_dict is not None:
            output["evidence"] = evidence_dict
            if len(cluster["hosts"]) > 1:
                per_host = {
                    h: evidence.project_evidence(cluster["host_accs"][h])
                    for h in sorted(cluster["hosts"])
                }
                per_host = {h: p for h, p in per_host.items() if p is not None}
                if per_host:
                    evidence_dict["per_host"] = per_host
        clusters.append(output)
    acc_to_output: dict[int, dict[str, Any]] = {
        id(cluster["evidence_acc"]): output
        for cluster, output in zip(ordered, clusters)
    }
    _apply_post_cluster_notes(clusters, dpkg_records, acc_to_output)
    return clusters


def _apply_post_cluster_notes(
    clusters: list[dict[str, Any]],
    dpkg_records: dict[tuple[str, str], list[tuple[str, str, dict[str, Any]]]],
    acc_to_output: dict[int, dict[str, Any]],
) -> None:
    """Attach data-built notes to clusters: dpkg upgrade pairing and rule
    87702 IPv6 artefact. Mutates the cluster dicts in place.
    """
    _pair_dpkg_clusters(clusters, dpkg_records, acc_to_output)
    _apply_rule_87702_artefact(clusters)


def _pair_dpkg_clusters(
    clusters: list[dict[str, Any]],
    dpkg_records: dict[tuple[str, str], list[tuple[str, str, dict[str, Any]]]],
    acc_to_output: dict[int, dict[str, Any]],
) -> None:
    """Pair half-configured → installed dpkg events per (host, pkg ver).

    For every half-configured event within 60 s of an installed event for the
    same (host, pkg ver), add one note to each cluster listing every paired
    pkg ver and the largest gap. Parses timestamps timezone-aware; skips
    silently when a timestamp fails to parse or is naive.
    """
    pairings: dict[tuple[int, int], tuple[set[str], float]] = {}
    for (_host, key), records in dpkg_records.items():
        parsed: list[tuple[datetime, str, dict[str, Any]]] = []
        for timestamp, status, acc in records:
            try:
                moment = datetime.fromisoformat(timestamp)
            except (TypeError, ValueError):
                continue
            if moment.tzinfo is None:
                continue
            parsed.append((moment, status, acc))
        for h_moment, h_status, h_acc in parsed:
            if h_status != "half-configured":
                continue
            for i_moment, i_status, i_acc in parsed:
                if i_status != "installed":
                    continue
                gap = abs((i_moment - h_moment).total_seconds())
                if gap > 60 or id(h_acc) == id(i_acc):
                    continue
                pair = (id(h_acc), id(i_acc))
                pkgs, largest = pairings.get(pair, (set(), 0.0))
                pkgs.add(key)
                pairings[pair] = (pkgs, max(largest, gap))

    for (h_acc_id, i_acc_id), (pkgs, largest) in pairings.items():
        half = acc_to_output.get(h_acc_id)
        installed = acc_to_output.get(i_acc_id)
        if half is None or installed is None:
            continue
        shown = sorted(pkgs)[:3]
        pkg_list = ", ".join(shown)
        if len(pkgs) > 3:
            pkg_list += f" (+{len(pkgs) - 3} more)"
        n = max(1, math.ceil(largest))
        note = (
            f"normal dpkg upgrade sequence: {pkg_list} "
            f"half-configured → installed within {n} s (see {installed['id']})"
        )
        if note not in half["notes"]:
            half["notes"].append(note)
        mirror = (
            f"normal dpkg upgrade sequence: {pkg_list} "
            f"half-configured → installed within {n} s (see {half['id']})"
        )
        if mirror not in installed["notes"]:
            installed["notes"].append(mirror)


def _apply_rule_87702_artefact(clusters: list[dict[str, Any]]) -> None:
    """Add the IPv6/87702 artefact note to clusters whose rule_ids include
    '87702' and whose firewall evidence carries an ipv6 ipversion.
    """
    for cluster in clusters:
        if "87702" not in cluster.get("rule_ids", []):
            continue
        ev = cluster.get("evidence") or {}
        fw = ev.get("firewall") or {}
        if "ipv6" not in fw.get("ipversions", []):
            continue
        if RULE_87702_IPV6_ARTEFACT_NOTE not in cluster["notes"]:
            cluster["notes"].append(RULE_87702_IPV6_ARTEFACT_NOTE)


def _new_cluster(
    cluster_type: str, description: str, package: str | None
) -> dict[str, Any]:
    """Create a mutable accumulation dict for one alert cluster."""
    return {
        "type": cluster_type,
        "description": description,
        "package": package,
        "rule_ids": set(),
        "hosts": set(),
        "count": 0,
        "max_level": 0,
        "first_seen": "",
        "last_seen": "",
        "cves": set(),
        "evidence_acc": {},
        "host_accs": {},
    }


def cluster_key(cluster: dict[str, Any]) -> str:
    """Return the stable per-cluster vector/trend key for one alert cluster.

    Vulnerability clusters with a package key on (host, package); those without
    key on (host, description); rule clusters key on description alone.
    """
    if cluster["type"] == "vulnerability":
        host = cluster["hosts"][0]
        if cluster.get("package"):
            return f"vuln|{host}|{cluster['package']}"
        return f"vuln|{host}|{cluster['description']}"
    return f"rule|{cluster['description']}"


def cluster_label(key: str) -> str:
    """Return a human-readable label for a cluster key.

    'vuln|h|p' becomes 'Vulnerabilities in p (h)'; 'rule|d' stays 'd'.
    Descriptions containing '|' survive via maxsplit.
    """
    parts = key.split("|", 2)
    if parts[0] == "vuln" and len(parts) == 3:
        return f"Vulnerabilities in {parts[2]} ({parts[1]})"
    return key.split("|", 1)[1] if parts[0] == "rule" and len(parts) > 1 else key


def _unattached_finding(description: str, recommendation: str = "") -> dict[str, Any]:
    """Build an unattached finding dict for LLM lines with no known cluster id."""
    return {
        "type": "unattached",
        "description": description,
        "count": 0,
        "hosts": [],
        "severity": "",
        "narrative": "",
        "recommendation": recommendation,
    }


def _split_cluster_ref(body: str) -> tuple[str | None, str]:
    """Split a tolerant cluster id prefix from an LLM line, returning (id, rest)."""
    match = _CLUSTER_REF_RE.match(body)
    if not match:
        return None, body
    cluster_id = f"C{int(match.group(1))}"
    return cluster_id, body[match.end():]


def _extract_timings(chunk: Any) -> tuple[int | None, float | None]:
    """Extract (predicted_n, predicted_per_second) from an LLM stream chunk.

    llama.cpp reports them under chunk.model_extra["timings"]; returns
    (None, None) when the chunk carries no timings.
    """
    extra = getattr(chunk, "model_extra", None)
    if not extra:
        return None, None
    timings = extra.get("timings")
    if not isinstance(timings, dict):
        return None, None
    return timings.get("predicted_n"), timings.get("predicted_per_second")


def analyse(
    alerts: list[dict[str, Any]],
    baseline: dict[str, Any],
    llm_config: dict[str, Any],
    embedder=None,
    mitre_path: str | None = None,
    platform_hints_path: str | None = None,
    platform_agents_path: str | None = None,
    asd_path: str | None = None,
    progress: RunReporter | None = None,
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
        platform_agents_path: Optional path to agent-name → vendor/platform JSON
            map; defaults to "data/platform_agents.json" if not supplied
        asd_path: Optional path to ASD framework JSON file
        progress: Optional RunReporter for terminal UI service/stage/LLM hooks
        lookback_hours: Report window in hours — similar incidents within this
            window are dropped from the prompt. None disables filtering.

    Returns:
        Analysis dict with summary, findings, and recommendations.
    """
    if not alerts:
        if progress is not None:
            progress.stage("Similar incidents", "done")
            progress.service("llm", "skipped")
            progress.stage("LLM analysis", "done")
        logger.info("No alerts to analyse")
        return {"summary": "No alerts", "findings": [], "recommendations": []}

    client = OpenAI(
        base_url=llm_config["base_url"],
        api_key=llm_config["api_key"],
        timeout=300.0,
    )

    clusters = extract_alert_clusters(alerts)

    similar_incidents = ""
    formatted: list[str] = []
    if progress is not None:
        progress.stage("Similar incidents", "active")
    if embedder is not None and not embedder.degraded:
        query_descriptions = [c["description"] for c in clusters[:MAX_PROMPT_CLUSTERS]]
        query_text = "\n".join(query_descriptions)[:MAX_SIMILARITY_QUERY_CHARS]
        try:
            similar = embedder.retrieve_similar(query_text)
        except (APIConnectionError, APITimeoutError, APIStatusError, ValueError, ChromaError, httpx.HTTPError, OSError) as e:
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

    if progress is not None:
        progress.stage("Similar incidents", "done")

    tactics = []
    if mitre_path and Path(mitre_path).exists():
        try:
            tactics = _load_mitre_tactics(mitre_path)
        except Exception as e:
            logger.warning(f"Failed to load MITRE tactics: {e}")

    hints_file = platform_hints_path or "data/platform_hints.json"
    platform_hints = _load_platform_hints(hints_file)
    platform_agents = _load_platform_agents(platform_agents_path)
    platform_context = _build_platform_context(
        alerts, platform_hints, platform_agents=platform_agents
    )
    if platform_context:
        logger.debug("Platform context injected into prompt")

    asd_data = _load_asd_data(asd_path) if asd_path else {}
    asd_context = _build_asd_context(asd_data)

    prompt = _build_prompt(
        alerts,
        baseline,
        clusters=clusters,
        similar_incidents=similar_incidents,
        tactics=tactics,
        platform_context=platform_context,
        asd_context=asd_context,
        platform_agents=platform_agents,
    )

    try:
        if progress is not None:
            progress.stage("LLM analysis", "active")
        full_text = ""
        content_count = 0
        llm_started_at: float | None = None
        first_chunk_seen = False
        last_tokens: int | None = None
        last_tok_s: float | None = None
        last_chunk: Any = None
        stream = client.chat.completions.create(
            model=llm_config["model"],
            messages=[{"role": "user", "content": prompt}],
            temperature=llm_config.get("temperature", 0.3),
            max_tokens=llm_config.get("max_tokens", 8192),
            presence_penalty=0.0,
            frequency_penalty=0.0,
            stream=True,
        )
        for chunk in stream:
            last_chunk = chunk
            chunk_tokens, chunk_tok_s = _extract_timings(chunk)
            if chunk_tokens is not None:
                last_tokens = chunk_tokens
                last_tok_s = chunk_tok_s
            if not first_chunk_seen:
                first_chunk_seen = True
                if progress is not None:
                    progress.service("llm", "ok")
                    progress.llm_start()
                    llm_started_at = time.monotonic()
            if not chunk.choices:
                continue
            content = chunk.choices[0].delta.content or ""
            if not content:
                continue
            content_count += 1
            full_text += content
            if progress is not None:
                progress.llm_tick()
        if progress is not None:
            tokens: int | None
            tok_s: float | None
            if last_chunk is not None:
                tokens, tok_s = _extract_timings(last_chunk)
            else:
                tokens, tok_s = None, None
            if tokens is None and last_tokens is not None:
                tokens, tok_s = last_tokens, last_tok_s
            if tokens is None and llm_started_at is not None:
                elapsed = time.monotonic() - llm_started_at
                tok_s = content_count / elapsed if elapsed > 0 else 0.0
            progress.llm_done(content_count, tokens, tok_s)
            progress.stage("LLM analysis", "done")
    except APIConnectionError as e:
        if progress is not None:
            progress.service("llm", "fail", detail=str(e))
        logger.error(f"Failed to connect to LLM server: {e}")
        raise
    except APIStatusError as e:
        if progress is not None:
            progress.service("llm", "fail", detail=str(e))
        logger.error(f"LLM server returned error status: {e}")
        raise

    analysis_text = full_text.strip()
    ## For debugging DO NOT REMOVE ##
    logger.debug(f"Raw API response: {full_text!r}")
    logger.debug(f"Raw LLM response: {analysis_text[:1000]}")
    ##################################

    result = _parse_analysis(analysis_text, tactics=tactics, clusters=clusters)
    vendor_names = {info["vendor"] for info in platform_agents.values()}
    for finding in result["findings"]:
        fid = finding.get("id", "")
        if not (isinstance(fid, str) and fid.startswith("C")):
            continue
        flags = _fidelity_flags(finding, vendor_names)
        if flags:
            finding["flags"] = flags
            logger.warning(
                f"Fidelity guard: [{fid}] unsupported in analysis: "
                f"{', '.join(flags)}"
            )
    result["summary"] = _build_data_summary(alerts, clusters, lookback_hours)
    if formatted:
        result["similar_incidents"] = "\n".join(formatted)
    return result


def _build_data_summary(
    alerts: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    lookback_hours: int | None,
) -> str:
    """Build the run summary purely from alert data, never from LLM text."""
    hosts: set[str] = set()
    for cluster in clusters:
        hosts.update(cluster.get("hosts", []))
    high = sum(1 for c in clusters if c["severity"] == "High")
    medium = sum(1 for c in clusters if c["severity"] == "Medium")
    low = sum(1 for c in clusters if c["severity"] == "Low")
    window = f" (last {lookback_hours} h)" if lookback_hours is not None else ""
    return (
        f"{len(alerts)} alerts in {len(clusters)} clusters across "
        f"{len(hosts)} hosts — severity: {high} High, {medium} Medium, "
        f"{low} Low clusters{window}"
    )


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


def _build_host_facts_block(
    clusters: list[dict[str, Any]],
    platform_agents: dict[str, dict[str, str]],
) -> str:
    """Build a 'Host facts:' prompt block listing every cluster host that
    matches the agent-name map, one line per matched host. Empty when no
    host matches.
    """
    if not platform_agents:
        return ""
    seen: set[str] = set()
    lines: list[str] = []
    for cluster in clusters:
        for host in cluster.get("hosts", []):
            if host in seen:
                continue
            info = platform_agents.get(host.casefold())
            if not info:
                continue
            seen.add(host)
            lines.append(
                f"- {host}: {info['vendor']} ({info['platform']}). "
                "Rule descriptions may name a different product; use this vendor name."
            )
    if not lines:
        return ""
    return "Host facts:\n" + "\n".join(lines)


def _parse_ips(
    corpus: str,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse every IPv4/IPv6 address token found in the corpus."""
    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for token in re.findall(r"[0-9a-f:.]+", corpus):
        token = token.strip(".")
        if not token:
            continue
        try:
            ips.append(ipaddress.ip_address(token))
        except ValueError:
            continue
    return ips


def _fidelity_flags(finding: dict, vendor_names: set[str]) -> list[str]:
    """Flag narrative/recommendation tokens unsupported by the cluster's evidence.

    Read-only: never mutates the finding or anything nested inside it.
    Comparison is lowercased; flagged tokens are returned as written in the
    text, de-duplicated, in first-seen order.
    """
    corpus_parts: list[str] = [
        evidence.render_evidence(finding.get("evidence")),
        finding.get("description", "") or "",
    ]
    for key in ("notes", "rule_ids", "cves", "hosts"):
        for value in finding.get(key) or []:
            corpus_parts.append(str(value))
    if finding.get("package") is not None:
        corpus_parts.append(str(finding.get("package")))
    corpus_parts.append(str(finding.get("count", 0)))
    corpus_parts.extend(vendor_names)
    corpus_lower = " \n ".join(corpus_parts).lower()

    text = f"{finding.get('narrative', '')} {finding.get('recommendation', '')}"
    corpus_ips = _parse_ips(corpus_lower)
    cves_lower = {str(c).lower() for c in finding.get("cves") or []}
    vendors_lower = {v.lower() for v in vendor_names}
    description_lower = str(finding.get("description", "") or "").lower()
    count_str = str(finding.get("count", 0))
    host_count_str = str(len(finding.get("hosts") or []))

    flagged: list[str] = []
    seen: set[str] = set()

    def _flag(token: str) -> None:
        if token not in seen:
            seen.add(token)
            flagged.append(token)

    # a) MITRE technique ids — allowed only when the cluster's own notes,
    #    description or evidence already name them (e.g. the 87702 note).
    for token in _TECHNIQUE_RE.findall(text):
        if token.lower() not in corpus_lower:
            _flag(token)

    # b) CVE ids — allowed only when already known for this cluster.
    for token in _CVE_RE.findall(text):
        lowered = token.lower()
        if lowered not in cves_lower and lowered not in description_lower:
            _flag(token)

    # c) Absolute paths — allowed only when present in the evidence corpus.
    for token in _PATH_RE.findall(text):
        cleaned = token.rstrip(".,;:)]}'\\ ").lower()
        if cleaned not in corpus_lower:
            _flag(token)

    # d) Port numbers — allowed only as whole tokens in the evidence corpus.
    for pattern in (_PORT_WORD_RE, _PORT_PROTO_RE):
        for number in pattern.findall(text):
            if not re.search(rf"\b{re.escape(number)}\b", corpus_lower):
                _flag(number)

    # e) IP addresses and networks — allowed when the exact token, or any
    #    corpus address inside the network, appears in the evidence corpus.
    for raw_token in text.split():
        token = raw_token.strip("(.,;)]}{'\" ")
        if not token:
            continue
        looks_ipv4 = bool(_IPV4_TOKEN_RE.match(token))
        looks_ipv6 = ":" in token and ("::" in token or token.count(":") >= 2)
        if not (looks_ipv4 or looks_ipv6):
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if token.lower() in corpus_lower:
            continue
        if any(addr in network for addr in corpus_ips):
            continue
        _flag(token)

    # f) Count claims — allowed when equal to the cluster's alert count or
    #    host count, or present as a whole token in the evidence corpus.
    for match in _COUNT_CLAIM_RE.finditer(text):
        number = match.group(1)
        if number not in (count_str, host_count_str) and not re.search(
            rf"\b{re.escape(number)}\b", corpus_lower
        ):
            _flag(number)

    # g) Cloud/provider names — allowed only when known for this cluster.
    for name in _KNOWN_PROVIDERS:
        match = re.search(rf"\b{re.escape(name)}\b", text, re.IGNORECASE)
        if (
            match
            and name.lower() not in corpus_lower
            and name.lower() not in vendors_lower
        ):
            _flag(match.group(0))

    return flagged


def _build_prompt(
    alerts: list[dict[str, Any]],
    baseline: dict[str, Any],
    clusters: list[dict[str, Any]] | None = None,
    similar_incidents: str = "",
    tactics: list = [],
    platform_context: str = "",
    asd_context: str = "",
    platform_agents: dict | None = None,
) -> str:
    """Build prompt with cluster lines and similar incidents."""
    if clusters is None:
        clusters = extract_alert_clusters(alerts)

    host_facts_block = ""
    if platform_agents:
        host_facts_block = _build_host_facts_block(clusters, platform_agents)

    cluster_lines: list[str] = []
    for cluster in clusters[:MAX_PROMPT_CLUSTERS]:
        line = (
            f"[{cluster['id']}] {cluster['severity'].upper()} — "
            f"{cluster['count']} alerts — {cluster['description']} — "
            f"hosts: {', '.join(cluster['hosts'])} — "
            f"{cluster['first_seen']} → {cluster['last_seen']}"
        )
        if cluster["type"] == "vulnerability" and cluster["cves"]:
            shown = cluster["cves"][:MAX_PROMPT_CVES]
            cve_part = ", ".join(shown)
            if len(cluster["cves"]) > MAX_PROMPT_CVES:
                cve_part += f" ... (+{len(cluster['cves']) - MAX_PROMPT_CVES} more)"
            line += f" — CVEs: {cve_part}"
        if cluster.get("evidence"):
            rendered_evidence = evidence.render_evidence(cluster["evidence"])
            if rendered_evidence:
                if len(rendered_evidence) > evidence.MAX_EVIDENCE_LINE_CHARS:
                    rendered_evidence = (
                        rendered_evidence[: evidence.MAX_EVIDENCE_LINE_CHARS - 1]
                        + "…"
                    )
                line += f" — evidence: {rendered_evidence}"
        if cluster.get("notes"):
            line += " — notes: " + "; ".join(cluster["notes"])
        cluster_lines.append(line)

    if len(clusters) > MAX_PROMPT_CLUSTERS:
        omitted = len(clusters) - MAX_PROMPT_CLUSTERS
        cluster_lines.append(
            f"(+{omitted} lower-severity clusters omitted — "
            "comment only on the clusters listed)"
        )

    if host_facts_block:
        alert_summary = host_facts_block + "\n\n" + "\n".join(cluster_lines)
    else:
        alert_summary = "\n".join(cluster_lines)

    mitre_reference = ""
    if tactics:
        mitre_reference = f"\nMITRE ATT&CK Tactics reference: {_build_mitre_reference(tactics)}"

    platform_block = f"\n{platform_context}\n" if platform_context else ""

    asd_block = f"\nASD Framework Context:\n{asd_context}" if asd_context else ""

    return f"""You are a security analyst. Analyse these Wazuh alerts and provide findings.
{platform_block}
Recent alerts (clusters built from alert data — do not restate counts, hosts,
severities or CVEs, and do not invent cluster ids):
Rules:
1. Evidence values and notes are facts taken from the raw alerts. Prefer the benign explanation that fits them.
2. Never contradict the evidence. If unsure, say less.
3. Copy ports, paths, counts, package names and versions exactly as written in the evidence, or leave them out.
4. 'content unchanged' means only metadata (such as inode or mtime) changed: treat it as low concern. 'scope internal → external' means hosts on this network were blocked going out, not an outside scan.
5. Name products and vendors as given in Host facts, not as the rule description says.
6. Recommend only what the evidence justifies. Do not suggest restoring files, forensics or isolating hosts unless the evidence shows a content change or an external source.
7. In per host evidence, the values inside a host's brackets belong to that host only. Never attribute them to another host.
{alert_summary}

{similar_incidents}
{mitre_reference}
{asd_block}

Provide your analysis in this format — one narrative line per cluster you comment on,
each prefixed with its cluster id, plus at most one recommendation line per cluster:
<findings>
- [C1] <narrative for cluster C1>
- [C2] <narrative for cluster C2>
</findings>
<recommendations>
- [C1] <recommendation for cluster C1>
</recommendations>"""


def _parse_analysis(
    text: str,
    tactics: list[dict[str, Any]] = [],
    clusters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Parse LLM response into structured dict.

    With ``clusters`` given, findings/recommendation lines attach to the
    matching cluster by id; lines with no id (or an unknown id) become
    unattached finding dicts and are logged. With ``clusters`` None the
    legacy string-based behaviour is preserved.
    """
    findings: list[Any] = []
    recommendations: list[str] = []
    mitre_tags: list[dict[str, str]] = []
    unattached: list[dict[str, Any]] = []

    by_id: dict[str, dict[str, Any]] = {}
    if clusters is not None:
        findings = [dict(c) for c in clusters]
        by_id = {c["id"]: c for c in findings}

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
        elif line.startswith("- ") and current_section == "findings":
            body = line[2:]
            if clusters is None:
                findings.append(body)
                continue
            cluster_id, rest = _split_cluster_ref(body)
            target = by_id.get(cluster_id) if cluster_id else None
            if target is not None:
                rest = _STRAY_FINDING_RE.sub("", rest, count=1)
                if target["narrative"]:
                    target["narrative"] = f"{target['narrative']} {rest}"
                else:
                    target["narrative"] = rest
            else:
                logger.warning(f"Unattached finding line (no known cluster id): {line}")
                unattached.append(_unattached_finding(body))
        elif line.startswith("- ") and current_section == "recommendations":
            body = line[2:]
            if clusters is None:
                recommendations.append(body)
                continue
            cluster_id, rest = _split_cluster_ref(body)
            target = by_id.get(cluster_id) if cluster_id else None
            if target is not None:
                rest = _STRAY_FINDING_RE.sub("", rest, count=1)
                if target["recommendation"]:
                    target["recommendation"] = f"{target['recommendation']} {rest}"
                else:
                    target["recommendation"] = rest
            else:
                logger.warning(f"Unattached recommendation line (no known cluster id): {line}")
                unattached.append(_unattached_finding("", recommendation=rest))

    if clusters is not None:
        findings.extend(unattached)
        recommendations = [
            f["recommendation"] for f in findings if f.get("recommendation")
        ]
        hosts: set[str] = set()
        for c in findings:
            hosts.update(c.get("hosts", []))
        high = sum(1 for c in findings if c.get("severity") == "High")
        medium = sum(1 for c in findings if c.get("severity") == "Medium")
        low = sum(1 for c in findings if c.get("severity") == "Low")
        summary = (
            f"{len(findings)} clusters across {len(hosts)} hosts — "
            f"severity: {high} High, {medium} Medium, {low} Low clusters"
        )
    else:
        summary = findings[0][:200] + "..." if findings and len(findings[0]) > 200 else findings[0] if findings else "No summary available"

    return {
        "summary": summary,
        "findings": findings,
        "recommendations": recommendations,
        "mitre_tags": mitre_tags,
    }