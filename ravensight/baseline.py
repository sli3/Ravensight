"""
baseline.py — Baseline memory persistence for security analysis.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ravensight.embedder import Embedder

import httpx
from chromadb.errors import ChromaError
from openai import APIConnectionError, APITimeoutError

from ravensight import analyser

logger = logging.getLogger(__name__)

DEFAULT_RUN_HOURS = 24
DEFAULT_RUN_LEVEL = 7
SCAN_HISTORY_MAX_DAYS = 90


def is_default_run(params: dict[str, Any] | None) -> bool:
    """Return True when the run matches the default daily-run parameters.

    A default run looks back DEFAULT_RUN_HOURS hours, has no agent filter and
    uses the DEFAULT_RUN_LEVEL minimum level. Missing keys are not default.
    """
    if params is None:
        return False
    return (
        params.get("hours") == DEFAULT_RUN_HOURS
        and params.get("agent") is None
        and params.get("level") == DEFAULT_RUN_LEVEL
    )


class Manager:
    """Manages baseline memory persistence."""

    def __init__(self, config: dict[str, Any], embedder: Embedder | None = None) -> None:
        """
        Initialise baseline manager.

        Args:
            config: Baseline config with path key.
            embedder: Optional Embedder instance for vector store updates.
        """
        self._path = Path(config["path"])
        self._embedder = embedder
        self._load()

    def _load(self) -> None:
        """Load baseline from disk."""
        if self._path.exists():
            try:
                with self._path.open("r") as f:
                    self._baseline = json.load(f)
                logger.info(f"Loaded baseline from {self._path}")
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to decode baseline, starting fresh: {e}")
                self._baseline = {"findings": [], "recommendations": [], "scan_history": []}
        else:
            self._baseline = {"findings": [], "recommendations": [], "scan_history": []}

    def load(self) -> dict[str, Any]:
        """
        Return current baseline dict.

        Returns:
            Baseline dict with findings and recommendations.
        """
        return self._baseline

    def update(
        self,
        analysis: dict[str, Any],
        clusters: list[dict[str, Any]] | None = None,
        run_params: dict[str, Any] | None = None,
    ) -> None:
        """
        Update baseline with new analysis results.

        Args:
            analysis: Analysis dict from analyser.analyse().
            clusters: Optional list of alert clusters from
                analyser.extract_alert_clusters(); appended to scan history and,
                on default runs, embedded into the vector store.
            run_params: Optional run parameters (hours, agent, level) used to
                decide whether this run feeds trends and vector writes.
        """
        findings = analysis.get("findings", [])
        recommendations = analysis.get("recommendations", [])

        if findings:
            self._baseline["findings"] = findings
            self._baseline["updated_at"] = datetime.now().isoformat()

        if recommendations:
            self._baseline["recommendations"] = recommendations

        summary = analysis.get("summary")
        if summary:
            self._baseline["summary"] = summary

        # Embed one vector per cluster on default runs only
        if self._embedder is not None and clusters and is_default_run(run_params):
            for cluster in clusters:
                if self._embedder.degraded:
                    cause = getattr(self._embedder, "_chroma_failure", None) or "embedding server unreachable"
                    formatted = cause[:1].upper() + cause[1:]
                    logger.warning(f"{formatted} — cluster vector-store writes skipped for this run")
                    break
                text = self._cluster_vector_text(cluster)
                metadata = {
                    "timestamp": datetime.now().isoformat(),
                    "rule_group": analyser.cluster_key(cluster),
                    "severity": cluster["severity"],
                    "summary": self._cluster_summary(cluster),
                }
                doc_id = "alert-" + sha256(
                    f"{analyser.cluster_key(cluster)}|{datetime.now().strftime('%Y-%m-%d')}".encode()
                ).hexdigest()[:32]
                try:
                    self._embedder.add_embedding(text, metadata, doc_id=doc_id)
                except (APIConnectionError, APITimeoutError, ValueError, ChromaError, httpx.HTTPError, OSError) as e:
                    logger.warning(
                        f"Vector-store write failed ({type(e).__name__}: {e}) — "
                        "skipping remaining cluster writes this run"
                    )
                    break

        if clusters is not None:
            snapshot = {
                "timestamp": datetime.now().isoformat(),
                "hours": (run_params or {}).get("hours"),
                "agent": (run_params or {}).get("agent"),
                "level": (run_params or {}).get("level"),
                "cluster_counts": {
                    analyser.cluster_key(c): c.get("count", 0) for c in clusters
                },
            }
            self._baseline.setdefault("scan_history", []).append(snapshot)
            self._prune_scan_history()

        self._save()
        logger.info(f"Updated baseline with {len(findings)} findings")

    @staticmethod
    def _cluster_vector_text(cluster: dict[str, Any]) -> str:
        """Return the embedding text for one cluster — no counts, ever."""
        if cluster["type"] == "vulnerability":
            host = cluster["hosts"][0]
            if cluster.get("package"):
                return f"Vulnerabilities affect {cluster['package']} on host {host}"
            return f"{cluster['description']} on host {host}"
        return cluster["description"]

    @staticmethod
    def _cluster_summary(cluster: dict[str, Any]) -> str:
        """Return the display summary for one cluster vector's metadata."""
        count = cluster.get("count", 0)
        noun = "alert" if count == 1 else "alerts"
        summary = f"{cluster['description']}: {count} {noun}"
        if cluster["type"] == "vulnerability":
            summary += f" on {cluster['hosts'][0]}"
        return summary

    def _prune_scan_history(self) -> None:
        """Drop scan history entries older than SCAN_HISTORY_MAX_DAYS, keeping unparseable ones."""
        cutoff = datetime.now() - timedelta(days=SCAN_HISTORY_MAX_DAYS)
        kept: list[dict[str, Any]] = []
        for entry in self._baseline.get("scan_history", []):
            ts = entry.get("timestamp", "")
            try:
                parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except ValueError:
                logger.debug(f"scan_history entry has unparseable timestamp {ts!r} — kept")
                kept.append(entry)
                continue
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone().replace(tzinfo=None)
            if parsed >= cutoff:
                kept.append(entry)
        self._baseline["scan_history"] = kept

    def _save(self) -> None:
        """Save baseline to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("w") as f:
            json.dump(self._baseline, f, indent=2)