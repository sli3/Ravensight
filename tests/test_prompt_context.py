"""
Tests that confirm:
- Baseline findings no longer leak into the LLM prompt.
- Similar-incident header goes to the prompt only; result["similar_incidents"]
  contains bullet lines only.
- 'unknown' / empty severity is omitted from the bullet line; real severity
  retains parentheses.

These tests do not touch the network, ChromaDB or the LLM. The OpenAI client
is monkeypatched via the ``captured_prompt`` fixture.
"""
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from ravensight import analyser
from ravensight.analyser import analyse


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


def _alert() -> dict[str, Any]:
    return {
        "_source": {
            "agent": {"name": "host-1", "os": {"platform": "linux", "name": "Linux"}},
            "rule": {"id": "5715", "description": "SSHD authentication success.", "level": 3},
        }
    }


def _item(ts: str, severity: str, summary: str) -> dict[str, Any]:
    return {"id": "x", "score": 0.1, "timestamp": ts, "severity": severity, "summary": summary}


class _FakeEmbedder:
    def __init__(self, items: list[dict[str, Any]]) -> None:
        self._items = items
        self.degraded = False

    def retrieve_similar(self, query_text: str) -> list[dict[str, Any]]:
        return list(self._items)


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


def _run_analyse(
    items: list[dict[str, Any]], baseline: dict[str, Any]
) -> dict[str, Any]:
    """Run analyse() with the given embedder items and baseline."""
    return analyse(
        alerts=[_alert()],
        baseline=baseline,
        llm_config=LLM_CONFIG,
        embedder=_FakeEmbedder(items),
        mitre_path=None,
        platform_hints_path=None,
        asd_path=None,
        show_progress=False,
        lookback_hours=24,
    )


def test_baseline_findings_not_in_prompt(captured_prompt: dict[str, Any]) -> None:
    """A baseline carrying old findings must not push them into the prompt."""
    baseline = {
        "findings": ["STALE: kernel CVE 2026-9999 must not appear"],
        "recommendations": ["patch everything"],
        "updated_at": "2026-09-20T00:00:00",
    }
    _run_analyse([], baseline)
    prompt_text = captured_prompt["messages"][0]["content"]
    assert "STALE: kernel CVE 2026-9999" not in prompt_text
    assert "Previous baseline findings" not in prompt_text


def test_cluster_line_appears_and_stale_baseline_absent(
    captured_prompt: dict[str, Any],
) -> None:
    """Cluster-based prompts list the alert cluster and exclude stale baseline text."""
    baseline = {
        "findings": ["STALE BASELINE FINDING TEXT FROM LAST WEEK"],
        "recommendations": ["STALE BASELINE RECOMMENDATION"],
        "updated_at": "2026-09-20T00:00:00",
    }
    _run_analyse([], baseline)
    prompt_text = captured_prompt["messages"][0]["content"]
    assert "STALE BASELINE FINDING TEXT" not in prompt_text
    assert "STALE BASELINE RECOMMENDATION" not in prompt_text
    assert "[C1]" in prompt_text
    assert "SSHD authentication success." in prompt_text


def test_similar_incident_header_in_prompt_not_in_result(
    captured_prompt: dict[str, Any],
) -> None:
    """Prompt gets the header; result['similar_incidents'] does not."""
    old_ts = (datetime.now() - timedelta(hours=48)).isoformat()
    result = _run_analyse(
        [_item(old_ts, "High", "Old SSH brute force")],
        {"findings": [], "recommendations": []},
    )
    prompt_text = captured_prompt["messages"][0]["content"]
    assert "Similar past incidents (from before this report window):" in prompt_text
    assert "Old SSH brute force" in prompt_text
    assert result["similar_incidents"] == f"- {old_ts} (High): Old SSH brute force"
    assert "Similar past incidents" not in result["similar_incidents"]


def test_unknown_severity_not_rendered(captured_prompt: dict[str, Any]) -> None:
    """Empty or 'unknown' severity is omitted from the bullet line."""
    old = (datetime.now() - timedelta(hours=48)).isoformat()
    result = _run_analyse(
        [
            _item(old, "unknown", "Unknown-sev entry"),
            _item(old, "", "Empty-sev entry"),
            _item(old, "High", "High-sev entry"),
        ],
        {"findings": [], "recommendations": []},
    )
    stored = result["similar_incidents"]
    assert f"- {old}: Unknown-sev entry" in stored
    assert f"- {old}: Empty-sev entry" in stored
    assert f"- {old} (High): High-sev entry" in stored
    assert "(unknown)" not in stored
    assert "(): " not in stored
