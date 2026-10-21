"""
main.py — Ravensight Security Log Analyser entry point.
"""
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import openai
import requests
import tomllib

from ravensight import (
    analyser,
    baseline,
    config_check,
    e8_scorer,
    essentials_scorer,
    reporter,
    trending,
    wazuh_client,
)
from ravensight import embedder as embedder_module
from ravensight.ui import CountingHandler, create_reporter, quiet_third_party_loggers

logger = logging.getLogger(__name__)


def _similar_incidents_note(embedder: embedder_module.Embedder | None) -> str | None:
    """Return the report availability note when the embedder is degraded, else None."""
    if embedder is None or not embedder.degraded:
        return None
    cause = getattr(embedder, "_chroma_failure", None) or "embedding server unreachable"
    return f"Similar Past Incidents: unavailable — {cause}"


def _load_technique_names(mitre_path: Any) -> dict[str, str]:
    """Return a technique id to name map from the MITRE file, or {} if unset or unreadable."""
    if not isinstance(mitre_path, str) or not mitre_path.strip():
        return {}
    try:
        with Path(mitre_path).open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        logger.warning("Could not read MITRE technique names from %s: %s", mitre_path, e)
        return {}
    return essentials_scorer.build_technique_names(data)


def _build_essentials(
    config: dict, analysis: dict, mitre_path: Any, finding_pointers: list | None
) -> dict | None:
    """Build the Essentials report block, or None when [essentials] is unset or its dataset is unusable."""
    section = config.get("essentials")
    if not isinstance(section, dict) or not section:
        return None
    path = section.get("path")
    attestation_path = section.get("attestation_path")
    dataset = essentials_scorer.load_essentials(path if isinstance(path, str) else None)
    if not dataset:
        return None
    findings = analysis.get("findings")
    return {
        "dataset": dataset,
        "finding_actions": essentials_scorer.map_findings_to_actions(
            findings if isinstance(findings, list) else [],
            dataset,
            _load_technique_names(mitre_path),
            ism_pointers=finding_pointers,
        ),
        "attestation": essentials_scorer.load_essentials_attestation(
            attestation_path if isinstance(attestation_path, str) else None, dataset
        ),
    }


def main() -> None:
    """Main entry point for Ravensight."""
    parser = argparse.ArgumentParser(description="Ravensight Security Log Analyser")
    parser.add_argument("--config", default="config.toml", help="Path to config file")
    parser.add_argument("--hours", type=int, default=baseline.DEFAULT_RUN_HOURS, help="Lookback window in hours")
    parser.add_argument("--agent", type=str, default=None, help="Wazuh agent ID")
    parser.add_argument("--level", type=int, default=baseline.DEFAULT_RUN_LEVEL, help="Minimum alert level")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Logging level")
    parser.add_argument("--report-only", action="store_true", help="Generate report from existing baseline")
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Plain output: no live panel or colours (e.g. for cron or log redirection)"
    )
    args = parser.parse_args()

    run_reporter, log_handler = create_reporter(args.no_progress)
    counter = CountingHandler()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        handlers=[log_handler, counter],
    )
    quiet_third_party_loggers(args.log_level)

    try:
        with Path(args.config).open("rb") as f:
            config = tomllib.load(f)
    except FileNotFoundError:
        logger.critical(f"Config file not found: {args.config}")
        sys.exit(1)
    except tomllib.TOMLDecodeError as e:
        logger.critical(f"Invalid config file: {e}")
        sys.exit(1)

    # Validate config before any client or Embedder is created (logs + exits 1 on problems).
    config_check.validate(config, report_only=args.report_only)
    run_reporter.stage("Config", "done")

    # Read the optional [embeddings] section; create the Embedder only when it is present and non-empty.
    embedder_config = config.get("embeddings")
    embedder = embedder_module.Embedder(embedder_config, progress=run_reporter) if embedder_config else None

    if embedder is None:
        run_reporter.service("embeddings", "off")
        logger.info("Embeddings disabled: no [embeddings] section — similarity and vector-store features skipped")
    else:
        run_reporter.service(
            "embeddings",
            "warn" if embedder.degraded else "ok",
            detail=str(getattr(embedder, "_chroma_failure", "") or "") if embedder.degraded else "",
        )
        logger.info(f"Embeddings enabled: endpoint {embedder._endpoint}")
    run_reporter.stage("Embeddings", "done")

    # Pass embedder to baseline.Manager constructor
    baseline_mgr = baseline.Manager(config["baseline"], embedder=embedder)
    wazuh = wazuh_client.Client(config["wazuh"], progress=run_reporter)

    platform_hints_path = config.get("platform", {}).get("hints_path") if "platform" in config else None
    platform_agents_path = config.get("platform", {}).get("agents_path") if "platform" in config else None
    vendor_aliases = analyser.load_vendor_aliases(platform_hints_path, platform_agents_path)

    if args.report_only:
        trends_output = None
        if "trending" in config:
            trend_mgr = trending.Trending(config["trending"])
            trends_output = trend_mgr.generate(baseline_mgr.load(), vendor_aliases=vendor_aliases)

        rep = reporter.Reporter(config["reports"])
        note = _similar_incidents_note(embedder)
        report_data = {**baseline_mgr.load(), "similar_incidents_unavailable_note": note}
        rep.generate(report_data, trends=trends_output)
        return

    with run_reporter.run():
        try:
            alerts = wazuh.fetch_alerts(hours=args.hours, agent=args.agent, level=args.level)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            run_reporter.stage("Fetch alerts", "fail")
            logger.critical(
                f"Wazuh Indexer unreachable ({type(e).__name__}: {e}) — "
                "check [wazuh] indexer_host and indexer_port in config.toml",
                exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
            )
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            run_reporter.stage("Fetch alerts", "fail")
            status = e.response.status_code if e.response is not None else None
            if status in (401, 403):
                msg = (
                    f"Wazuh Indexer rejected the login (HTTP {status}) — "
                    "check [wazuh] indexer_user and indexer_password in config.toml"
                )
            else:
                msg = (
                    f"Wazuh Indexer returned HTTP {status} — check the [wazuh] indexer settings"
                )
            logger.critical(msg, exc_info=logging.getLogger().isEnabledFor(logging.DEBUG))
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            run_reporter.stage("Fetch alerts", "fail")
            logger.critical(
                f"Wazuh Indexer request failed ({type(e).__name__}: {e}) — check the [wazuh] indexer settings",
                exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
            )
            sys.exit(1)

        mitre_path = config.get("mitre", {}).get("path") if "mitre" in config else None
        asd_path = config.get("asd", {}).get("path") if "asd" in config else None
        try:
            analysis = analyser.analyse(alerts, baseline_mgr.load(), config["llm"], embedder=embedder, mitre_path=mitre_path, asd_path=asd_path, platform_hints_path=platform_hints_path, platform_agents_path=platform_agents_path, progress=run_reporter, lookback_hours=args.hours)
        except openai.APIConnectionError as e:
            run_reporter.stage("LLM analysis", "fail")
            logger.critical(
                f"LLM server unreachable ({type(e).__name__}: {e}) — check [llm] base_url in config.toml",
                exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
            )
            sys.exit(1)
        except openai.APIStatusError as e:
            run_reporter.stage("LLM analysis", "fail")
            status = e.status_code if hasattr(e, "status_code") else None
            logger.critical(
                f"LLM server returned HTTP {status} — check [llm] base_url, api_key and model",
                exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
            )
            sys.exit(1)
        except openai.APIError as e:
            run_reporter.stage("LLM analysis", "fail")
            logger.critical(
                f"LLM request failed ({type(e).__name__}: {e}) — check the [llm] settings",
                exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
            )
            sys.exit(1)
        clusters = analyser.extract_alert_clusters(alerts)
        run_params = {"hours": args.hours, "agent": args.agent, "level": args.level}
        count = (
            len(clusters)
            if embedder is not None
            and not embedder.degraded
            and baseline.is_default_run(run_params)
            else 0
        )
        run_reporter.stage("Baseline update", "active", total=count or None)
        baseline_mgr.update(analysis, clusters=clusters, run_params=run_params)
        run_reporter.stage("Baseline update", "done")

        trends_output = None
        if "trending" in config:
            run_reporter.stage("Trends", "active")
            trend_mgr = trending.Trending(config["trending"])
            trends_output = trend_mgr.generate(baseline_mgr.load(), vendor_aliases=vendor_aliases)
            run_reporter.stage("Trends", "done")

        asd_data = analyser._load_asd_data(asd_path) if asd_path else None
        overrides_path = config.get("e8", {}).get("overrides_path") if "e8" in config else None
        attestation_path = config.get("e8", {}).get("attestation_path") if "e8" in config else None
        run_reporter.stage("E8/ISM scoring", "active")
        e8_scores = e8_scorer.score_findings(analysis.get("findings", []), asd_data, overrides_path=overrides_path) if asd_data else {}
        matched_controls = e8_scorer.match_ism_controls(analysis.get("findings", []), asd_data, overrides_path=overrides_path) if asd_data else []
        finding_pointers = e8_scorer.map_findings_to_controls(analysis.get("findings", []), asd_data, overrides_path=overrides_path) if asd_data else None
        attestation = e8_scorer.load_attestation(attestation_path, asd_data) if asd_data else {}
        run_reporter.stage("E8/ISM scoring", "done")
        essentials = _build_essentials(config, analysis, mitre_path, finding_pointers)
        analysis["similar_incidents_unavailable_note"] = _similar_incidents_note(embedder)
        rep = reporter.Reporter(config["reports"])
        run_reporter.stage("Report", "active")
        report_path = rep.generate(analysis, trends=trends_output, asd_data=asd_data, e8_scores=e8_scores, matched_controls=matched_controls, finding_pointers=finding_pointers, attestation=attestation, run_params=run_params, essentials=essentials)
        run_reporter.stage("Report", "done")

    run_reporter.finish(analysis, report_path, counter.warnings, counter.errors)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)