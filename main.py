"""
main.py — Ravensight Security Log Analyser entry point.
"""
import argparse
import logging
import sys
import tomllib
from pathlib import Path

import openai
import requests
from ravensight import wazuh_client, analyser, reporter, baseline, trending, e8_scorer, config_check, embedder as embedder_module
from ravensight.ui import CountingHandler, create_reporter, quiet_third_party_loggers

logger = logging.getLogger(__name__)


def _similar_incidents_note(embedder: embedder_module.Embedder | None) -> str | None:
    """Return the report availability note when the embedder is degraded, else None."""
    if embedder is None or not embedder.degraded:
        return None
    cause = getattr(embedder, "_chroma_failure", None) or "embedding server unreachable"
    return f"Similar Past Incidents: unavailable — {cause}"


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
        logging.critical(f"Config file not found: {args.config}")
        sys.exit(1)
    except tomllib.TOMLDecodeError as e:
        logging.critical(f"Invalid config file: {e}")
        sys.exit(1)

    # Validate config before any client or Embedder is created (logs + exits 1 on problems).
    config_check.validate(config, report_only=args.report_only)
    run_reporter.stage("Config", "done")

    # NEW: Load embeddings config section (optional) and instantiate Embedder
    embedder_config = config.get("embeddings")
    embedder = embedder_module.Embedder(embedder_config, progress=run_reporter) if embedder_config else None

    if embedder is None:
        run_reporter.service("embeddings", "off")
        logging.info("Embeddings disabled: no [embeddings] section — similarity and vector-store features skipped")
    else:
        run_reporter.service(
            "embeddings",
            "warn" if embedder.degraded else "ok",
            detail=str(getattr(embedder, "_chroma_failure", "") or "") if embedder.degraded else "",
        )
        logging.info(f"Embeddings enabled: endpoint {embedder._endpoint}")
    run_reporter.stage("Embeddings", "done")

    # Pass embedder to baseline.Manager constructor
    baseline_mgr = baseline.Manager(config["baseline"], embedder=embedder)
    wazuh = wazuh_client.Client(config["wazuh"], progress=run_reporter)

    if args.report_only:
        trends_output = None
        if "trending" in config:
            trend_mgr = trending.Trending(config["trending"])
            trends_output = trend_mgr.generate(baseline_mgr.load())

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
            logging.critical(
                f"Wazuh Indexer unreachable ({type(e).__name__}: {e}) — "
                "check [wazuh] indexer_host and indexer_port in config.toml (or .env with Docker)",
                exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
            )
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            run_reporter.stage("Fetch alerts", "fail")
            status = e.response.status_code if e.response is not None else None
            if status in (401, 403):
                msg = (
                    f"Wazuh Indexer rejected the login (HTTP {status}) — "
                    "check [wazuh] indexer_user and indexer_password in config.toml (or .env with Docker)"
                )
            else:
                msg = (
                    f"Wazuh Indexer returned HTTP {status} — check the [wazuh] indexer settings"
                )
            logging.critical(msg, exc_info=logging.getLogger().isEnabledFor(logging.DEBUG))
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            run_reporter.stage("Fetch alerts", "fail")
            logging.critical(
                f"Wazuh Indexer request failed ({type(e).__name__}: {e}) — check the [wazuh] indexer settings",
                exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
            )
            sys.exit(1)

        mitre_path = config.get("mitre", {}).get("path") if "mitre" in config else None
        asd_path = config.get("asd", {}).get("path") if "asd" in config else None
        platform_hints_path = config.get("platform", {}).get("hints_path") if "platform" in config else None
        platform_agents_path = config.get("platform", {}).get("agents_path") if "platform" in config else None
        try:
            analysis = analyser.analyse(alerts, baseline_mgr.load(), config["llm"], embedder=embedder, mitre_path=mitre_path, asd_path=asd_path, platform_hints_path=platform_hints_path, platform_agents_path=platform_agents_path, progress=run_reporter, lookback_hours=args.hours)
        except openai.APIConnectionError as e:
            run_reporter.stage("LLM analysis", "fail")
            logging.critical(
                f"LLM server unreachable ({type(e).__name__}: {e}) — check [llm] base_url in config.toml (or .env with Docker)",
                exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
            )
            sys.exit(1)
        except openai.APIStatusError as e:
            run_reporter.stage("LLM analysis", "fail")
            status = e.status_code if hasattr(e, "status_code") else None
            logging.critical(
                f"LLM server returned HTTP {status} — check [llm] base_url, api_key and model",
                exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
            )
            sys.exit(1)
        except openai.APIError as e:
            run_reporter.stage("LLM analysis", "fail")
            logging.critical(
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
            trends_output = trend_mgr.generate(baseline_mgr.load())
            run_reporter.stage("Trends", "done")

        asd_data = analyser._load_asd_data(asd_path) if asd_path else {}
        overrides_path = config.get("e8", {}).get("overrides_path") if "e8" in config else None
        run_reporter.stage("E8/ISM scoring", "active")
        e8_scores = e8_scorer.score_findings(analysis.get("findings", []), asd_data, overrides_path=overrides_path) if asd_data else {}
        matched_controls = e8_scorer.match_ism_controls(analysis.get("findings", []), asd_data, overrides_path=overrides_path) if asd_data else []
        run_reporter.stage("E8/ISM scoring", "done")
        analysis["similar_incidents_unavailable_note"] = _similar_incidents_note(embedder)
        rep = reporter.Reporter(config["reports"])
        run_reporter.stage("Report", "active")
        report_path = rep.generate(analysis, trends=trends_output, asd_data=asd_data, e8_scores=e8_scores, matched_controls=matched_controls)
        run_reporter.stage("Report", "done")

    run_reporter.finish(analysis, report_path, counter.warnings, counter.errors)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        sys.exit(0)