"""
wazuh_client.py — Wazuh Indexer and Manager REST API client.
"""
from __future__ import annotations

import logging
import urllib3
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import requests
from requests.auth import HTTPBasicAuth

if TYPE_CHECKING:
    from ravensight.ui import RunReporter

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Client:
    """Wazuh REST API client for fetching security alerts."""

    def __init__(self, config: dict[str, Any], progress: RunReporter | None = None) -> None:
        """Initialise with wazuh config section."""
        self._progress = progress
        # Manager API config
        self.host = config["host"]
        self.port = config.get("port", 55000)
        self.user = config["user"]
        self.password = config["password"]
        self.base_url = f"https://{self.host}:{self.port}"

        # Indexer config (OpenSearch)
        self.indexer_host = config.get("indexer_host", self.host)
        self.indexer_port = config.get("indexer_port", 9200)
        self.indexer_user = config.get("indexer_user", "admin")
        self.indexer_password = config.get("indexer_password", "admin")
        self.indexer_url = f"https://{self.indexer_host}:{self.indexer_port}"

        self._token: str | None = None
        self._token_expiry: datetime | None = None

    def _authenticate(self) -> None:
        """Authenticate with Wazuh manager API and obtain an access token."""
        auth_url = f"{self.base_url}/security/user/authenticate"
        response = requests.post(
            auth_url,
            auth=(self.user, self.password),
            verify=False,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        self._token = data["data"]["token"]
        self._token_expiry = datetime.now() + timedelta(seconds=900)
        logger.debug("Wazuh manager authentication successful")

    def _ensure_authenticated(self) -> None:
        """Refresh token if expired or not set."""
        if self._token is None or (
            self._token_expiry is not None and datetime.now() >= self._token_expiry
        ):
            self._authenticate()

    def fetch_alerts(
        self, hours: int = 24, agent: str | None = None, level: int = 7
    ) -> list[dict[str, Any]]:
        """Fetch alerts from Wazuh Indexer matching the given criteria."""
        since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

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
                verify=False,
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
        if self._progress is not None:
            self._progress.service("wazuh", "ok")
            self._progress.stage("Fetch alerts", "done")
        logger.info(f"Fetched {len(alerts)} alerts from Wazuh Indexer")

        return alerts