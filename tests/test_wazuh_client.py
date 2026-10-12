"""
test_wazuh_client.py — fetch_alerts must build its time bound in true UTC.
"""
from __future__ import annotations

import os
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any

import pytest

from ravensight import wazuh_client

pytestmark = pytest.mark.skipif(
    not hasattr(time, "tzset"), reason="time.tzset is unavailable on this platform"
)

# Real fixed instant, captured before any patching of wazuh_client.datetime.
FROZEN_UTC = datetime(2026, 10, 12, 1, 0, 0, tzinfo=timezone.utc)
FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"

# POSIX TZ strings, so no tzdata is needed on the host.
ADELAIDE_TZ = "ACST-9:30ACDT,M10.1.0,M4.1.0/3"
UTC_TZ = "UTC0"


class _Frozen(datetime):
    """datetime subclass whose now() returns the frozen instant."""

    @classmethod
    def now(cls, tz: tzinfo | None = None) -> datetime:  # type: ignore[override]
        """Return the frozen instant, converted to tz or naive local time."""
        if tz is not None:
            return FROZEN_UTC.astimezone(tz)
        return FROZEN_UTC.astimezone().replace(tzinfo=None)


class _FakeResponse:
    """Minimal stand-in for a requests response."""

    def raise_for_status(self) -> None:
        """Do nothing, as for a successful response."""

    def json(self) -> dict[str, Any]:
        """Return an empty search result."""
        return {"hits": {"hits": []}}


@pytest.fixture
def process_tz(request: pytest.FixtureRequest) -> Iterator[str]:
    """Set the process timezone from the param and restore it afterwards."""
    tz_value: str = request.param
    original = os.environ.get("TZ")
    os.environ["TZ"] = tz_value
    time.tzset()
    try:
        yield tz_value
    finally:
        if original is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = original
        time.tzset()


@pytest.fixture
def captured_body(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Freeze the clock and capture the JSON body posted by fetch_alerts."""
    captured: dict[str, Any] = {}

    def fake_post(
        url: str,
        json: dict[str, Any] | None = None,
        auth: Any = None,
        verify: Any = None,
        timeout: Any = None,
    ) -> _FakeResponse:
        """Capture the request body and return an empty response."""
        captured["body"] = json
        return _FakeResponse()

    monkeypatch.setattr(wazuh_client, "datetime", _Frozen)
    monkeypatch.setattr(wazuh_client.requests, "post", fake_post)
    return captured


@pytest.mark.parametrize("process_tz", [ADELAIDE_TZ, UTC_TZ], indirect=True)
@pytest.mark.parametrize("hours", [24, 1])
def test_fetch_alerts_since_is_utc(
    process_tz: str, hours: int, captured_body: dict[str, Any]
) -> None:
    """The since bound equals the UTC instant minus hours, whatever the local zone."""
    if process_tz == ADELAIDE_TZ:
        assert time.localtime().tm_gmtoff != 0

    client = wazuh_client.Client(
        {"host": "example.invalid", "user": "u", "password": "p"}
    )
    client.fetch_alerts(hours=hours)

    since = captured_body["body"]["query"]["bool"]["must"][0]["range"]["@timestamp"]["gte"]
    expected = (FROZEN_UTC - timedelta(hours=hours)).strftime(FORMAT)
    assert since == expected
    if hours == 1:
        assert since <= FROZEN_UTC.strftime(FORMAT)
