"""
Tests for the bounded similarity query text (Build 1b-fix).

No network — the OpenAI client is monkeypatched and a capturing
stand-in embedder records what analyse() sends to retrieve_similar().
"""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ravensight import analyser
from ravensight.analyser import MAX_SIMILARITY_QUERY_CHARS

LLM_CONFIG = {
    "base_url": "http://llm.invalid/v1",
    "api_key": "local",
    "model": "test-model",
}


class _CapturingEmbedder:
    """Stand-in embedder that records the query text and returns nothing."""

    degraded = False
    _chroma_failure = None

    def __init__(self) -> None:
        self.queries: list[str] = []

    def retrieve_similar(self, query_text: str) -> list[dict[str, Any]]:
        """Record the query and answer with no similar incidents."""
        self.queries.append(query_text)
        return []


class _FakeStream:
    """Single-chunk streaming response carrying no content."""

    def __iter__(self) -> "_FakeStream":
        self._yielded = False
        return self

    def __next__(self) -> Any:
        if self._yielded:
            raise StopIteration
        self._yielded = True
        return SimpleNamespace(
            choices=[SimpleNamespace(delta=SimpleNamespace(content=""))]
        )


class _FakeOpenAI:
    """Stand-in OpenAI client returning an empty stream."""

    def __init__(self, **kwargs: Any) -> None:
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=lambda **kw: _FakeStream())
        )


def _long_desc_vuln_alert(index: int) -> dict[str, Any]:
    """Build one vulnerability alert with a long distinct description."""
    package = f"lib{'x' * 100}{index:05d}"
    return {
        "_source": {
            "agent": {"name": "host-1"},
            "rule": {
                "id": "23503",
                "description": f"CVE-2026-{10000 + index} affects {package}",
                "level": 10,
            },
            "data": {
                "vulnerability": {
                    "cve": f"CVE-2026-{10000 + index}",
                    "package": {"name": package},
                }
            },
            "@timestamp": "2026-09-24T10:00:00.000Z",
        }
    }


def test_similarity_query_bounded_for_5000_cves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """5000 distinct vulnerability alerts yield a query within the char bound."""
    monkeypatch.setattr(analyser, "OpenAI", _FakeOpenAI)
    embedder = _CapturingEmbedder()

    alerts = [_long_desc_vuln_alert(i) for i in range(5000)]
    result = analyser.analyse(
        alerts,
        {},
        LLM_CONFIG,
        embedder=embedder,
        platform_hints_path=str(tmp_path / "missing_hints.json"),
    )

    assert len(embedder.queries) == 1
    assert len(embedder.queries[0]) <= MAX_SIMILARITY_QUERY_CHARS
    assert result["findings"]
