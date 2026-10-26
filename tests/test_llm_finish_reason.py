"""Tests for logging the LLM stream finish reason."""

import logging
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest

from ravensight import analyser

LLM_TEXT = "<findings>\n- [C1] SSHD authentication succeeded.\n</findings>"


def _chunk(content: str | None, **choice_fields: Any) -> SimpleNamespace:
    """Build a stream chunk with optional choice attributes."""
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                delta=SimpleNamespace(content=content), **choice_fields
            )
        ]
    )


def _run_analyse(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    chunks: list[SimpleNamespace],
    max_tokens: int = 321,
) -> dict[str, Any]:
    """Run analyse with a fake stream and return the captured request."""
    request: dict[str, Any] = {}

    def create(**kwargs: Any) -> Iterator[SimpleNamespace]:
        """Capture the request and stream the supplied fake chunks."""
        request.update(kwargs)
        return iter(chunks)

    def client(**kwargs: Any) -> SimpleNamespace:
        """Build a fake OpenAI client exposing streaming completions."""
        return SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        )

    monkeypatch.setattr(analyser, "OpenAI", client)
    caplog.set_level(logging.INFO, logger=analyser.__name__)
    analyser.analyse(
        alerts=[
            {
                "_source": {
                    "agent": {"name": "host-1"},
                    "rule": {
                        "id": "5715",
                        "description": "SSHD authentication success.",
                        "level": 3,
                    },
                }
            }
        ],
        baseline={},
        llm_config={
            "base_url": "http://llm.invalid/v1",
            "api_key": "local",
            "model": "test-model",
            "max_tokens": max_tokens,
            "temperature": 0.0,
        },
        embedder=None,
        mitre_path=None,
        platform_hints_path=None,
        asd_path=None,
        lookback_hours=24,
    )
    return request


def test_stop_logs_info_without_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A normal stop logs its reason at INFO without a warning."""
    _run_analyse(monkeypatch, caplog, [_chunk(LLM_TEXT, finish_reason="stop")])

    assert (analyser.__name__, logging.INFO, "LLM finish reason: stop") in (
        caplog.record_tuples
    )
    assert not any(
        record.levelno >= logging.WARNING
        and "stopped at max_tokens" in record.getMessage()
        for record in caplog.records
    )


@pytest.mark.parametrize("max_tokens", [321, 777])
def test_length_warns_with_configured_max_tokens(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    max_tokens: int,
) -> None:
    """A token limit warning names the actual configured request limit."""
    request = _run_analyse(
        monkeypatch, caplog, [_chunk(LLM_TEXT, finish_reason="length")],
        max_tokens=max_tokens,
    )

    assert request["max_tokens"] == max_tokens
    assert (analyser.__name__, logging.INFO, "LLM finish reason: length") in (
        caplog.record_tuples
    )
    assert (
        analyser.__name__,
        logging.WARNING,
        (
            f"LLM reply stopped at max_tokens ({max_tokens}), "
            "so the analysis may be cut off. Raise max_tokens in the llm "
            "settings if findings are missing."
        ),
    ) in caplog.record_tuples


def test_missing_finish_reason_logs_not_reported(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Shared-style chunks without a finish reason log not reported safely."""
    _run_analyse(monkeypatch, caplog, [_chunk(LLM_TEXT)])

    assert (
        analyser.__name__, logging.INFO, "LLM finish reason: not reported"
    ) in caplog.record_tuples
    assert not any(
        record.levelno >= logging.WARNING
        and "stopped at max_tokens" in record.getMessage()
        for record in caplog.records
    )


@pytest.mark.parametrize("content", ["", None])
def test_empty_content_preserves_finish_reason(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    content: str | None,
) -> None:
    """A final chunk with empty content still supplies its finish reason."""
    _run_analyse(
        monkeypatch, caplog,
        [_chunk(LLM_TEXT), _chunk(content, finish_reason="stop")],
    )

    assert (analyser.__name__, logging.INFO, "LLM finish reason: stop") in (
        caplog.record_tuples
    )


def test_empty_choices_timings_preserve_finish_reason(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A trailing timings chunk cannot erase an already reported reason."""
    timings_chunk = SimpleNamespace(
        choices=[],
        model_extra={"timings": {"predicted_n": 5, "predicted_per_second": 1.0}},
    )
    _run_analyse(
        monkeypatch, caplog,
        [_chunk(LLM_TEXT, finish_reason="stop"), timings_chunk],
    )

    assert (analyser.__name__, logging.INFO, "LLM finish reason: stop") in (
        caplog.record_tuples
    )
