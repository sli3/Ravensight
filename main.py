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
from tqdm import tqdm
from ravensight import wazuh_client, analyser, reporter, baseline, trending, e8_scorer, config_check, embedder as embedder_module

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
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours")
    parser.add_argument("--agent", type=str, default=None, help="Wazuh agent ID")
    parser.add_argument("--level", type=int, default=7, help="Minimum alert level")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Logging level")
    parser.add_argument("--report-only", action="store_true", help="Generate report from existing baseline")
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable tqdm progress bars (e.g. for cron or log redirection)"
    )
    args = parser.parse_args()

    show_progress = not args.no_progress and sys.stdout.isatty()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

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

    # NEW: Load embeddings config section (optional) and instantiate Embedder
    embedder_config = config.get("embeddings")
    embedder = embedder_module.Embedder(embedder_config, show_progress=show_progress) if embedder_config else None

    if embedder is None:
        logging.info("Embeddings disabled: no [embeddings] section — similarity and vector-store features skipped")
    else:
        logging.info(f"Embeddings enabled: endpoint {embedder._endpoint}")

    # Pass embedder to baseline.Manager constructor  
    baseline_mgr = baseline.Manager(config["baseline"], embedder=embedder)
    wazuh = wazuh_client.Client(config["wazuh"], show_progress=show_progress)

    # Migrate baseline embeddings (runs on every invocation; no migration marker exists)
    if embedder is not None:
        migrated = embedder.migrate_baseline(baseline_mgr.load())
        if migrated > 0:
            logging.info(f"Migrated {migrated} entries to vector store")

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

    try:
        alerts = wazuh.fetch_alerts(hours=args.hours, agent=args.agent, level=args.level)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        logging.critical(
            f"Wazuh Indexer unreachable ({type(e).__name__}: {e}) — "
            "check [wazuh] indexer_host and indexer_port in config.toml (or .env with Docker)",
            exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
        )
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
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
        logging.critical(
            f"Wazuh Indexer request failed ({type(e).__name__}: {e}) — check the [wazuh] indexer settings",
            exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
        )
        sys.exit(1)

    mitre_path = config.get("mitre", {}).get("path") if "mitre" in config else None
    asd_path = config.get("asd", {}).get("path") if "asd" in config else None
    platform_hints_path = config.get("platform", {}).get("hints_path") if "platform" in config else None
    try:
        analysis = analyser.analyse(alerts, baseline_mgr.load(), config["llm"], embedder=embedder, mitre_path=mitre_path, asd_path=asd_path, platform_hints_path=platform_hints_path, show_progress=show_progress)
    except openai.APIConnectionError as e:
        logging.critical(
            f"LLM server unreachable ({type(e).__name__}: {e}) — check [llm] base_url in config.toml (or .env with Docker)",
            exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
        )
        sys.exit(1)
    except openai.APIStatusError as e:
        status = e.status_code if hasattr(e, "status_code") else None
        logging.critical(
            f"LLM server returned HTTP {status} — check [llm] base_url, api_key and model",
            exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
        )
        sys.exit(1)
    except openai.APIError as e:
        logging.critical(
            f"LLM request failed ({type(e).__name__}: {e}) — check the [llm] settings",
            exc_info=logging.getLogger().isEnabledFor(logging.DEBUG),
        )
        sys.exit(1)
    baseline_mgr.update(analysis, rule_counts=analyser.extract_rule_counts(alerts))

    trends_output = None
    if "trending" in config:
        trend_mgr = trending.Trending(config["trending"])
        trends_output = trend_mgr.generate(baseline_mgr.load())

    asd_data = analyser._load_asd_data(asd_path) if asd_path else {}
    overrides_path = config.get("e8", {}).get("overrides_path") if "e8" in config else None
    e8_scores = e8_scorer.score_findings(analysis.get("findings", []), asd_data, overrides_path=overrides_path) if asd_data else {}
    matched_controls = e8_scorer.match_ism_controls(analysis.get("findings", []), asd_data, overrides_path=overrides_path) if asd_data else []
    analysis["similar_incidents_unavailable_note"] = _similar_incidents_note(embedder)
    rep = reporter.Reporter(config["reports"])
    rep.generate(analysis, trends=trends_output, asd_data=asd_data, e8_scores=e8_scores, matched_controls=matched_controls)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Interrupted by user")
        sys.exit(0)