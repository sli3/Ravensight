"""Shared pytest fixtures and helpers for prompt-capture tests."""
from types import SimpleNamespace
from typing import Any

import pytest

from ravensight import analyser

LLM_TEXT = (
    "<findings>\n- Finding A\n</findings>\n"
    "<recommendations>\n- Rec A\n</recommendations>"
)


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
