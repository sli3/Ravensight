"""
wazuh_client.py — Wazuh Indexer (OpenSearch) REST API client.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import requests
import urllib3
from requests.auth import HTTPBasicAuth

if TYPE_CHECKING:
    from ravensight.ui import RunReporter

logger = logging.getLogger(__name__)


class Client:
    """Wazuh Indexer client for fetching security alerts."""

    def __init__(self, config: dict[str, Any], progress: RunReporter | None = None) -> None:
        """Initialise with wazuh config section."""
        self._progress = progress
        # Wazuh host (the default Indexer host)
        self.host = config["host"]

        # Indexer config (OpenSearch)
        self.indexer_host = config.get("indexer_host", self.host)
        self.indexer_port = config.get("indexer_port", 9200)
        self.indexer_user = config.get("indexer_user", "admin")
        self.indexer_password = config.get("indexer_password", "")
        self.indexer_url = f"https://{self.indexer_host}:{self.indexer_port}"

        # TLS verification for the Indexer: a CA path wins, else the boolean flag
        verify_tls = config.get("indexer_verify_tls", False)
        ca_path = config.get("indexer_ca_path", "")
        self.indexer_verify: bool | str
        if isinstance(ca_path, str) and ca_path.strip():
            self.indexer_verify = ca_path.strip()
        else:
            self.indexer_verify = verify_tls is True
        if self.indexer_verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        target = f"{self.indexer_host}:{self.indexer_port}"
        if isinstance(self.indexer_verify, str):
            logger.info(
                f"Wazuh Indexer {target}: HTTPS, certificate verified against "
                f"CA file {self.indexer_verify}"
            )
        elif self.indexer_verify is True:
            logger.info(
                f"Wazuh Indexer {target}: HTTPS, certificate verified against "
                "the bundled public CA list"
            )
        else:
            logger.info(
                f"Wazuh Indexer {target}: HTTPS, encrypted but certificate not "
                "verified (indexer_verify_tls = false)"
            )

    @staticmethod
    def _matched_total(hits: Any) -> int | None:
        """Return hits.total as an int from dict or int form, else None."""
        if not isinstance(hits, dict):
            return None
        total = hits.get("total")
        if isinstance(total, dict):
            total = total.get("value")
        if isinstance(total, int) and not isinstance(total, bool):
            return total
        return None

    def fetch_alerts(
        self, hours: int = 24, agent: str | None = None, level: int = 7
    ) -> list[dict[str, Any]]:
        """Fetch up to 10,000 alerts from the Wazuh Indexer (OpenSearch store), newest first.

        Returns alerts from the last `hours` hours at or above rule `level`, optionally for
        one agent name. Logs a warning if the matched total exceeds the 10,000 returned.
        Logs and re-raises requests ConnectionError, Timeout and HTTPError;
        other errors propagate unchanged.
        """
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        query: dict[str, Any] = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": since}}},
                        {"range": {"rule.level": {"gte": level}}},
                    ]
                }
            },
            "size": 10000,
            "track_total_hits": True,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        if agent:
            query["query"]["bool"]["must"].append(
                {"match": {"agent.name": agent}}
            )

        auth = HTTPBasicAuth(self.indexer_user, self.indexer_password)

        if self._progress is not None:
            self._progress.service("wazuh", "active")
            self._progress.stage("Fetch alerts", "active")
        try:
            response = requests.post(
                f"{self.indexer_url}/wazuh-alerts-4.x-*/_search",
                json=query,
                auth=auth,
                verify=self.indexer_verify,
                timeout=30,
            )
            response.raise_for_status()
        except requests.exceptions.ConnectionError as e:
            if self._progress is not None:
                self._progress.service("wazuh", "fail", detail=str(e))
                self._progress.stage("Fetch alerts", "fail")
            logger.error(f"Failed to connect to Wazuh Indexer: {e}")
            raise
        except requests.exceptions.Timeout as e:
            if self._progress is not None:
                self._progress.service("wazuh", "fail", detail=str(e))
                self._progress.stage("Fetch alerts", "fail")
            logger.error(f"Timeout connecting to Wazuh Indexer: {e}")
            raise
        except requests.exceptions.HTTPError as e:
            if self._progress is not None:
                self._progress.service("wazuh", "fail", detail=str(e))
                self._progress.stage("Fetch alerts", "fail")
            logger.error(f"HTTP error from Wazuh Indexer: {e}")
            raise

        data = response.json()
        alerts = data["hits"]["hits"]
        total = self._matched_total(data["hits"])
        if total is not None and total > len(alerts):
            logger.warning(
                "Wazuh Indexer matched %d alerts but only %d were fetched; the oldest "
                "alerts were dropped. Narrow --hours or --agent, or raise --level.",
                total,
                len(alerts),
            )
        if self._progress is not None:
            self._progress.service("wazuh", "ok")
            self._progress.stage("Fetch alerts", "done")
        logger.info(f"Fetched {len(alerts)} alerts from Wazuh Indexer")

        return alerts