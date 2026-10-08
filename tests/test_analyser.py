"""
Tests for platform-aware alert context reaching the LLM prompt.

These tests do not touch the network, ChromaDB or the LLM. The OpenAI client
is monkeypatched via the ``captured_prompt`` fixture.
"""
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ravensight import analyser
from ravensight.analyser import _build_prompt, analyse

HINT_TEXT = "ESP vfat mtime churn is expected and benign"

PLATFORM_CONTEXT = (
    "Platform context:\n"
    f"- Known false positives on FreeBSD: {HINT_TEXT}"
)

LLM_TEXT = (
    "<findings>\n- Finding A\n</findings>\n"
    "<recommendations>\n- Rec A\n</recommendations>"
)

LLM_CONFIG = {
    "base_url": "http://llm.invalid/v1",
    "api_key": "local",
    "model": "test-model",
    "max_tokens": 512,
    "temperature": 0.0,
}


class _FakeEmbedder:
    """Embedder stub that returns no similar incidents."""

    def __init__(self) -> None:
        self.degraded = False

    def retrieve_similar(self, query_text: str) -> list[dict[str, Any]]:
        """Return an empty list of similar incidents."""
        return []


def _make_fake_stream(text: str) -> Any:
    """Build a streaming response whose only chunk contains ``text``."""
    class _FakeStream:
        def __iter__(self) -> "_FakeStream":
            self._yielded = False
            return self

        def __next__(self) -> Any:
            if self._yielded:
                raise StopIteration
            self._yielded = True
            return SimpleNamespace(
                choices=[SimpleNamespace(delta=SimpleNamespace(content=text))]
            )

    return _FakeStream()


@pytest.fixture()
def captured_prompt(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Replace analyser.OpenAI with a fake that records the prompt."""
    sink: dict[str, Any] = {}

    class _Chat:
        def __init__(self) -> None:
            self.completions = self

        def create(self, **kwargs: Any) -> Any:
            sink["messages"] = kwargs.get("messages", [])
            return _make_fake_stream(LLM_TEXT)

    class _Client:
        def __init__(self) -> None:
            self.chat = _Chat()

    monkeypatch.setattr(analyser, "OpenAI", lambda **kw: _Client())
    return sink


def test_build_prompt_includes_platform_context() -> None:
    """A non-empty platform_context string is injected into the prompt."""
    prompt = _build_prompt(
        alerts=[], baseline={}, clusters=[], platform_context=PLATFORM_CONTEXT
    )
    assert PLATFORM_CONTEXT in prompt


def test_build_prompt_omits_empty_platform_context() -> None:
    """An empty platform_context yields the same prompt as the default."""
    empty = _build_prompt(
        alerts=[], baseline={}, clusters=[], platform_context=""
    )
    default = _build_prompt(alerts=[], baseline={}, clusters=[])
    with_context = _build_prompt(
        alerts=[], baseline={}, clusters=[], platform_context=PLATFORM_CONTEXT
    )
    assert empty == default
    assert with_context != empty


def test_analyse_passes_hint_text_to_llm(
    tmp_path: Path, captured_prompt: dict[str, Any]
) -> None:
    """A hints file matching platform and rule puts the hint in the LLM prompt."""
    hints_path = tmp_path / "platform_hints.json"
    hints_path.write_text(
        json.dumps(
            {
                "freebsd": {
                    "description": "FreeBSD host",
                    "rules": {
                        "510": {"paths": ["/boot/efi"], "hint": HINT_TEXT},
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    alert = {
        "_source": {
            "agent": {
                "name": "fbsd-1",
                "os": {"platform": "freebsd", "name": "FreeBSD"},
            },
            "rule": {
                "id": "510",
                "description": "Host-based anomaly detection event (rootcheck).",
                "level": 7,
            },
        }
    }
    analyse(
        alerts=[alert],
        baseline={},
        llm_config=LLM_CONFIG,
        embedder=_FakeEmbedder(),
        mitre_path=None,
        platform_hints_path=str(hints_path),
        asd_path=None,
        lookback_hours=24,
    )
    prompt_text = captured_prompt["messages"][0]["content"]
    assert HINT_TEXT in prompt_text
    assert "/boot/efi" in prompt_text
