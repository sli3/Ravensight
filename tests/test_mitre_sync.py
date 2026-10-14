"""Tests for scripts/mitre_sync.py fetch_stix_bundle retry behaviour.

No network: requests.get and time.sleep are monkeypatched.
"""

from typing import Any

import pytest
import requests

from scripts import mitre_sync


class _Response:
    """Minimal stand-in for a successful requests.Response."""

    def __init__(self, payload: dict[str, Any]) -> None:
        """Store the JSON payload."""
        self._payload = payload

    def raise_for_status(self) -> None:
        """Do nothing, as for a 200 response."""

    def json(self) -> dict[str, Any]:
        """Return the stored payload."""
        return self._payload


def test_fetch_succeeds_first_try(monkeypatch: pytest.MonkeyPatch) -> None:
    """A first-call success returns the JSON with no sleep."""
    sleeps: list[int] = []
    monkeypatch.setattr(mitre_sync.requests, "get", lambda url, timeout: _Response({"ok": 1}))
    monkeypatch.setattr(mitre_sync.time, "sleep", sleeps.append)

    assert mitre_sync.fetch_stix_bundle("http://x") == {"ok": 1}
    assert sleeps == []


def test_fetch_retries_once_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """One failure then success returns the JSON after a single 30 s sleep."""
    sleeps: list[int] = []
    calls: list[int] = []

    def fake_get(url: str, timeout: int) -> _Response:
        """Fail on the first call, succeed on the second."""
        calls.append(1)
        if len(calls) == 1:
            raise requests.ConnectionError("boom")
        return _Response({"ok": 2})

    monkeypatch.setattr(mitre_sync.requests, "get", fake_get)
    monkeypatch.setattr(mitre_sync.time, "sleep", sleeps.append)

    assert mitre_sync.fetch_stix_bundle("http://x") == {"ok": 2}
    assert sleeps == [30]


def test_fetch_raises_after_three_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Three failures raise RequestException with sleeps of 30 s and 60 s."""
    sleeps: list[int] = []

    def fake_get(url: str, timeout: int) -> _Response:
        """Always fail."""
        raise requests.ConnectionError("boom")

    monkeypatch.setattr(mitre_sync.requests, "get", fake_get)
    monkeypatch.setattr(mitre_sync.time, "sleep", sleeps.append)

    with pytest.raises(requests.RequestException):
        mitre_sync.fetch_stix_bundle("http://x")
    assert sleeps == [30, 60]
