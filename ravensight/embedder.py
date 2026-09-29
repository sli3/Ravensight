"""
embedder.py — ChromaDB vector store and Qwen3-Embedding-0.6B embedding client.

Provides semantic memory for alert retrieval by:
- Connecting to llama.cpp embeddings endpoint (port 8081)
- Managing ChromaDB collection with SQLite (embedded) or HTTP (networked) backend
- Migrating existing baseline_state.json entries on every run
"""

import json
import logging
from hashlib import sha256
from pathlib import Path
from typing import Any

from tqdm import tqdm

import chromadb
from chromadb.errors import ChromaError
import httpx
from openai import OpenAI, APIConnectionError, APITimeoutError

logger = logging.getLogger(__name__)


def _format_cause(e: Exception) -> str:
    """Return a short human-readable label for a Chroma connection failure."""
    if isinstance(e, httpx.ConnectError) and "Name or service not known" in str(e):
        return "DNS failure"
    return f"{type(e).__name__}: {e}"


def finding_text(finding: Any) -> str:
    """Return the text used for embedding a finding.

    Strings are returned unchanged. Dicts use '{description}: {narrative}' when
    narrative is non-empty, else just description. No counts or timestamps,
    deterministic, JSON-safe.
    """
    if isinstance(finding, dict):
        description = str(finding.get("description", ""))
        narrative = str(finding.get("narrative", ""))
        if narrative:
            return f"{description}: {narrative}"
        return description
    return str(finding)


class Embedder:
    """Manages embedding and vector retrieval for semantic memory."""

    def __init__(self, config: dict[str, Any], show_progress: bool = False) -> None:
        """
        Initialise embedder client.

        Args:
            config: Embedding config with endpoint, model, chroma_db_path, top_k keys, plus
                optional chroma_host and chroma_port for networked (server) mode.
        """
        self.show_progress = show_progress
        self._endpoint = config.get("endpoint", "http://localhost:8081/v1/embeddings")
        self._model = config.get("model", "Qwen3-Embedding-0.6B")
        self._chroma_path = Path(config.get("chroma_db_path", "data/chroma/embedded"))
        self._top_k = config.get("top_k", 5)
        self._degraded = False
        self._chroma_failure: str | None = None
        self._collection: Any | None = None

        # Create embedding client for llama.cpp endpoint
        self._embedding_client = OpenAI(
            base_url=self._endpoint,
            api_key="not-needed",  # Not used for local llama.cpp
        )

        # Client construction is NOT lazy: HttpClient/PersistentClient can raise at
        # construction time, so the whole connect + collection path is guarded here.
        try:
            self._connect_chroma(config)
            self._ensure_collection()
        except (ValueError, httpx.HTTPError, ChromaError, OSError, KeyError) as e:
            self._degraded = True
            self._collection = None
            self._chroma_failure = _format_cause(e)
            logger.warning(
                f"ChromaDB unreachable ({type(e).__name__}: {e}) — "
                "similarity retrieval and vector-store updates are skipped this run"
            )

    @property
    def degraded(self) -> bool:
        """Whether the embedding server has failed and should be treated as unavailable."""
        return self._degraded

    def _connect_chroma(self, config: dict[str, Any]) -> None:
        """Connect to ChromaDB in embedded mode or networked server mode."""
        self._chroma_host: str | None = config.get("chroma_host")
        if self._chroma_host:
            port = config.get("chroma_port", 8000)
            logger.info(f"Connecting to ChromaDB server at {self._chroma_host}:{port}")
            # Construction performs a connectivity probe and raises when the server is down
            self._client = chromadb.HttpClient(host=self._chroma_host, port=port)
            return

        logger.info(f"Using embedded ChromaDB at {self._chroma_path}")
        self._chroma_path.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(self._chroma_path))

    def _ensure_collection(self) -> None:
        """Create the ChromaDB collection; the caller guards against Chroma being unreachable."""
        self._collection = self._client.get_or_create_collection(
            name="alerts",
            metadata={"hnsw:space": "cosine"},
        )
        if self._chroma_host:
            self._check_server_version()

    def _check_server_version(self) -> None:
        """Log a warning when the ChromaDB server major.minor version differs from the client's."""
        server_version = str(self._client.get_version())
        client_version = chromadb.__version__
        if server_version.split(".")[:2] != client_version.split(".")[:2]:
            logger.warning(
                f"ChromaDB version mismatch: client {client_version}, server {server_version}"
            )

    def encode(self, text: str) -> list[float]:
        """
        Encode text into embedding vector.

        Args:
            text: Text to encode (e.g., alert cluster summary).

        Returns:
            List of floats representing the embedding vector.
        """
        try:
            response = self._embedding_client.embeddings.create(
                model=self._model,
                input=text,
            )
            return response.model_dump()["data"][0]["embedding"]
        except (APIConnectionError, APITimeoutError, ValueError) as e:
            self._degraded = True
            logger.error(f"Failed to encode text: {e}")
            raise

    def add_embedding(self, text: str, metadata: dict[str, Any]) -> None:
        """
        Add embedding to vector store.

        Args:
            text: Text to embed (alert cluster summary).
            metadata: Dict with timestamp, rule_group, severity, summary keys.
        """
        if self.degraded:
            logger.warning("Embedder degraded — vector-store add skipped")
            return

        embedding = self.encode(text)

        # Convert numpy arrays to lists if needed
        if isinstance(embedding, list):
            embedding_list = embedding
        else:
            embedding_list = embedding.tolist()

        # Deterministic id: identical text overwrites itself instead of duplicating
        content_hash_id = "alert-" + sha256(text.encode("utf-8")).hexdigest()[:32]
        try:
            self._collection.upsert(
                ids=[content_hash_id],
                embeddings=[embedding_list],
                documents=[text],
                metadatas=[metadata],
            )
        except (ChromaError, httpx.HTTPError, OSError) as e:
            self._degraded = True
            self._chroma_failure = _format_cause(e)
            logger.warning(
                f"ChromaDB unreachable mid-run ({type(e).__name__}: {e}) — "
                "vector-store writes skipped for the remainder of this run"
            )
            raise

    def query_similar(self, query_text: str, top_k: int | None = None) -> list[dict[str, Any]]:
        """
        Retrieve most similar past incidents by cosine similarity.

        Args:
            query_text: Text to embed for retrieval (current alert cluster summary).
            top_k: Number of results to return (uses config default if not specified).

        Returns:
            List of dicts with id, score, metadata (timestamp, rule_group, severity, summary).
        """
        k = top_k if top_k is not None else self._top_k

        try:
            with tqdm(total=None, desc="Retrieving similar", unit="", disable=not self.show_progress) as bar:
                query_embedding = self.encode(query_text)
                bar.update(1)

            # Convert numpy array to list if needed
            if isinstance(query_embedding, list):
                query_embedding_list = query_embedding
            else:
                query_embedding_list = query_embedding.tolist()

            try:
                results = self._collection.query(
                    query_embeddings=[query_embedding_list],
                    n_results=k,
                )
            except (ChromaError, httpx.HTTPError, OSError) as e:
                self._degraded = True
                self._chroma_failure = _format_cause(e)
                raise

            # Convert ChromaDB response to list of dicts
            retrieved: list[dict[str, Any]] = []
            num_results = len(results.get("ids", [[]])[0])
            for i in range(num_results):
                item = {
                    "id": results["ids"][0][i],
                    "score": results["distances"][0][i],
                }

                # Extract metadata fields with safe defaults
                # ChromaDB returns nested structure: metadatas[[{results...}], ...]
                meta_list = results.get("metadatas", [[]])[0]
                meta = meta_list[i] if i < len(meta_list) else {}
                item["timestamp"] = meta.get("timestamp", "")
                item["rule_group"] = meta.get("rule_group", "")
                item["severity"] = meta.get("severity", "")
                item["summary"] = meta.get("summary", "")

                retrieved.append(item)

            return retrieved
        except Exception as e:
            logger.error(f"Failed to query embeddings: {e}")
            raise

    def migrate_baseline(self, baseline_data: dict[str, Any]) -> int:
        """
        Migrate existing baseline_state.json entries into vector store.

        Args:
            baseline_data: Dict with findings and recommendations keys from baseline.Manager.load().

        Returns:
            Number of entries migrated.
        """
        count = 0

        # Drift policy: clear last run's baseline vectors before re-inserting
        if not self.degraded and self._collection is not None:
            try:
                self._collection.delete(where={"rule_group": "baseline_finding"})
            except (ChromaError, httpx.HTTPError, ValueError, OSError, KeyError) as e:
                logger.warning(f"Failed to clear baseline findings from vector store: {e}")

        # Migrate findings
        for finding in tqdm(
            baseline_data.get("findings", []),
            desc="Embedding migration",
            unit=" entry",
            disable=not self.show_progress,
        ):
            text = finding_text(finding)
            severity = finding.get("severity") if isinstance(finding, dict) else None
            if not isinstance(severity, str) or not severity:
                severity = "unknown"
            metadata = {
                "timestamp": baseline_data.get("updated_at", ""),
                "rule_group": "baseline_finding",
                "severity": severity,
                "summary": text,
            }

            try:
                self.add_embedding(text, metadata)
                count += 1
            except (APIConnectionError, APITimeoutError, ValueError, ChromaError, httpx.HTTPError, OSError) as e:
                logger.warning(f"Failed to migrate finding: {e}")
                break

        if not self.degraded and self._collection is not None:
            try:
                self._collection.delete(where={"rule_group": "baseline_recommendation"})
            except (ChromaError, httpx.HTTPError, ValueError, OSError, KeyError) as e:
                logger.warning(f"Failed to clear baseline recommendations from vector store: {e}")

        # Migrate recommendations
        for rec in baseline_data.get("recommendations", []):
            if self.degraded:
                break

            metadata = {
                "timestamp": baseline_data.get("updated_at", ""),
                "rule_group": "baseline_recommendation",
                "severity": "unknown",
                "summary": str(rec),
            }

            try:
                self.add_embedding(str(rec), metadata)
                count += 1
            except (APIConnectionError, APITimeoutError, ValueError, ChromaError, httpx.HTTPError, OSError) as e:
                logger.warning(f"Failed to migrate recommendation: {e}")
                break

        logger.info(f"Migrated {count} entries from baseline to vector store")
        return count
    # Alias for analyser.py compatibility
    retrieve_similar = query_similar

def load_baseline_embeddings(baseline_path: str) -> dict[str, Any] | None:
    """
    Load baseline_state.json for migration.

    Args:
        baseline_path: Path to baseline_state.json file.

    Returns:
        Baseline data dict or None if file doesn't exist.
    """
    baseline_path = Path(baseline_path)
    if not baseline_path.exists():
        logger.debug(f"Baseline file not found: {baseline_path}")
        return None

    try:
        with baseline_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to decode baseline JSON: {e}")
        return None
