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
        """Iterator that yields a single chunk holding the given text."""

        def __iter__(self) -> "_FakeStream":
            """Reset the yielded flag and return the iterator itself."""
            self._yielded = False
            return self

        def __next__(self) -> Any:
            """Return the single chunk once, then stop."""
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
        """Fake chat namespace whose completions attribute is itself."""

        def __init__(self) -> None:
            """Point the completions attribute at this instance."""
            self.completions = self

        def create(self, **kwargs: Any) -> Any:
            """Record the messages in the sink and return a fake stream."""
            sink["messages"] = kwargs.get("messages", [])
            return _make_fake_stream(LLM_TEXT)

    class _Client:
        """Fake OpenAI client exposing a fake chat namespace."""

        def __init__(self) -> None:
            """Set up the fake chat namespace."""
            self.chat = _Chat()

    monkeypatch.setattr(analyser, "OpenAI", lambda **kw: _Client())
    return sink
