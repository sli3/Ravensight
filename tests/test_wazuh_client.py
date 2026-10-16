"""
test_wazuh_client.py — fetch_alerts must build its time bound in true UTC.
"""
from __future__ import annotations

import logging
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

    def __init__(self, payload: dict[str, Any] | None = None) -> None:
        """Store the payload to return, defaulting to an empty search result."""
        self._payload = payload if payload is not None else {"hits": {"hits": []}}

    def json(self) -> dict[str, Any]:
        """Return the configured search result."""
        return self._payload


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

    client = wazuh_client.Client({"host": "example.invalid"})
    client.fetch_alerts(hours=hours)

    since = captured_body["body"]["query"]["bool"]["must"][0]["range"]["@timestamp"]["gte"]
    expected = (FROZEN_UTC - timedelta(hours=hours)).strftime(FORMAT)
    assert since == expected
    if hours == 1:
        assert since <= FROZEN_UTC.strftime(FORMAT)


def _fetch_with_payload(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any], captured: dict[str, Any]
) -> list[dict[str, Any]]:
    """Run fetch_alerts against a fake post returning payload, capturing the body."""

    def fake_post(
        url: str,
        json: dict[str, Any] | None = None,
        auth: Any = None,
        verify: Any = None,
        timeout: Any = None,
    ) -> _FakeResponse:
        """Capture the request body and return the payload."""
        captured["body"] = json
        return _FakeResponse(payload)

    monkeypatch.setattr(wazuh_client.requests, "post", fake_post)
    client = wazuh_client.Client({"host": "example.invalid"})
    return client.fetch_alerts()


def _warnings(caplog: pytest.LogCaptureFixture) -> list[Any]:
    """Return the WARNING records captured so far."""
    return [r for r in caplog.records if r.levelno == logging.WARNING]


def test_warns_when_dict_total_exceeds_fetched(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A dict total larger than the fetched count logs exactly one warning with counts."""
    hits = [{"_id": "1"}, {"_id": "2"}]
    payload = {"hits": {"total": {"value": 12345, "relation": "eq"}, "hits": hits}}
    with caplog.at_level(logging.WARNING, logger=wazuh_client.logger.name):
        _fetch_with_payload(monkeypatch, payload, {})
    records = _warnings(caplog)
    assert len(records) == 1
    message = records[0].getMessage()
    assert "12345" in message
    assert "2 were fetched" in message


def test_warns_when_int_total_exceeds_fetched(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A bare int total larger than the fetched count logs a warning."""
    payload = {"hits": {"total": 500, "hits": [{"_id": "1"}]}}
    with caplog.at_level(logging.WARNING, logger=wazuh_client.logger.name):
        _fetch_with_payload(monkeypatch, payload, {})
    records = _warnings(caplog)
    assert len(records) == 1
    assert "500" in records[0].getMessage()


def test_no_warning_when_total_equals_fetched(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """No warning is logged when the total equals the fetched count."""
    payload = {"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{"_id": "1"}]}}
    with caplog.at_level(logging.WARNING, logger=wazuh_client.logger.name):
        _fetch_with_payload(monkeypatch, payload, {})
    assert _warnings(caplog) == []


@pytest.mark.parametrize(
    "total",
    [
        pytest.param(None, id="none"),
        pytest.param("99999", id="string"),
        pytest.param({"value": "99999"}, id="dict-non-int"),
        pytest.param({"relation": "eq"}, id="dict-no-value"),
        pytest.param(True, id="bool"),
    ],
)
def test_malformed_total_does_not_warn_or_crash(
    total: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A malformed total is ignored without raising or warning."""
    payload = {"hits": {"total": total, "hits": []}}
    with caplog.at_level(logging.WARNING, logger=wazuh_client.logger.name):
        result = _fetch_with_payload(monkeypatch, payload, {})
    assert result == []
    assert _warnings(caplog) == []


def test_missing_total_does_not_warn_or_crash(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A payload with no total key is handled without a warning."""
    with caplog.at_level(logging.WARNING, logger=wazuh_client.logger.name):
        result = _fetch_with_payload(monkeypatch, {"hits": {"hits": []}}, {})
    assert result == []
    assert _warnings(caplog) == []


def test_track_total_hits_is_true_in_body(monkeypatch: pytest.MonkeyPatch) -> None:
    """The posted query body requests exact total hits."""
    captured: dict[str, Any] = {}
    _fetch_with_payload(monkeypatch, {"hits": {"hits": []}}, captured)
    assert captured["body"]["track_total_hits"] is True


def test_indexer_password_defaults_to_empty() -> None:
    """A missing indexer_password defaults to an empty string."""
    client = wazuh_client.Client({"host": "example.invalid"})
    assert client.indexer_password == ""


def test_indexer_password_is_kept_when_set() -> None:
    """An explicit indexer_password is used as given."""
    client = wazuh_client.Client(
        {
            "host": "example.invalid",
            "indexer_password": "x",
        }
    )
    assert client.indexer_password == "x"


def test_returns_posted_hits_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """fetch_alerts returns the very hits list from the response."""
    hits = [{"_id": "1"}]
    result = _fetch_with_payload(monkeypatch, {"hits": {"hits": hits}}, {})
    assert result is hits


_BASE_CONFIG: dict[str, Any] = {"host": "example.invalid"}


def test_client_constructs_with_host_only() -> None:
    """A config holding only the host constructs without error."""
    client = wazuh_client.Client({"host": "example.invalid"})
    assert client.indexer_host == "example.invalid"


def test_indexer_verify_defaults_to_false() -> None:
    """Without TLS keys, indexer_verify is False."""
    client = wazuh_client.Client(dict(_BASE_CONFIG))
    assert client.indexer_verify is False


def test_indexer_verify_tls_true_gives_true() -> None:
    """indexer_verify_tls = true resolves to True."""
    client = wazuh_client.Client({**_BASE_CONFIG, "indexer_verify_tls": True})
    assert client.indexer_verify is True


def test_indexer_ca_path_is_used_as_given() -> None:
    """A CA path is used as the exact (stripped) verify string."""
    client = wazuh_client.Client({**_BASE_CONFIG, "indexer_ca_path": " /app/data/ca.pem "})
    assert client.indexer_verify == "/app/data/ca.pem"


def test_indexer_ca_path_wins_over_verify_false() -> None:
    """A CA path wins over indexer_verify_tls = false."""
    client = wazuh_client.Client(
        {**_BASE_CONFIG, "indexer_verify_tls": False, "indexer_ca_path": "/x/ca.pem"}
    )
    assert client.indexer_verify == "/x/ca.pem"


@pytest.mark.parametrize("ca_path", ["   ", "", 5, None, ["/x"]])
def test_blank_or_non_string_ca_path_is_unset(ca_path: Any) -> None:
    """A blank or non-string CA path is treated as unset."""
    client = wazuh_client.Client({**_BASE_CONFIG, "indexer_ca_path": ca_path})
    assert client.indexer_verify is False


def _tls_info_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Return the INFO records captured from the wazuh_client logger."""
    return [
        r
        for r in caplog.records
        if r.levelno == logging.INFO and r.name == wazuh_client.logger.name
    ]


def test_logs_ca_file_mode(caplog: pytest.LogCaptureFixture) -> None:
    """A CA path logs one INFO line naming host, port and the CA file."""
    with caplog.at_level(logging.INFO, logger=wazuh_client.logger.name):
        wazuh_client.Client(
            {**_BASE_CONFIG, "indexer_port": 9201, "indexer_ca_path": "/x/ca.pem"}
        )
    records = _tls_info_records(caplog)
    assert len(records) == 1
    message = records[0].getMessage()
    assert "example.invalid" in message
    assert "9201" in message
    assert "CA file /x/ca.pem" in message


def test_logs_bundled_ca_mode(caplog: pytest.LogCaptureFixture) -> None:
    """indexer_verify_tls = true logs one INFO line naming the bundled CA list."""
    with caplog.at_level(logging.INFO, logger=wazuh_client.logger.name):
        wazuh_client.Client({**_BASE_CONFIG, "indexer_verify_tls": True})
    records = _tls_info_records(caplog)
    assert len(records) == 1
    message = records[0].getMessage()
    assert "example.invalid" in message
    assert "9200" in message
    assert "bundled public CA list" in message


def test_logs_not_verified_mode(caplog: pytest.LogCaptureFixture) -> None:
    """The default config logs one INFO line saying the certificate is not verified."""
    with caplog.at_level(logging.INFO, logger=wazuh_client.logger.name):
        wazuh_client.Client(dict(_BASE_CONFIG))
    records = _tls_info_records(caplog)
    assert len(records) == 1
    message = records[0].getMessage()
    assert "example.invalid" in message
    assert "9200" in message
    assert "not verified" in message


def test_tls_log_does_not_leak_credentials(caplog: pytest.LogCaptureFixture) -> None:
    """Neither the indexer user nor password appears in the captured log text."""
    with caplog.at_level(logging.INFO, logger=wazuh_client.logger.name):
        wazuh_client.Client(
            {
                **_BASE_CONFIG,
                "indexer_user": "testuser-xyz",
                "indexer_password": "testpass-xyz",
            }
        )
    assert "testuser-xyz" not in caplog.text
    assert "testpass-xyz" not in caplog.text


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({}, False),
        ({"indexer_verify_tls": True}, True),
        ({"indexer_ca_path": "/x/ca.pem"}, "/x/ca.pem"),
    ],
)
def test_fetch_alerts_passes_resolved_verify(
    extra: dict[str, Any], expected: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The verify value passed to requests.post equals the resolved value."""
    seen: dict[str, Any] = {}

    def fake_post(
        url: str,
        json: dict[str, Any] | None = None,
        auth: Any = None,
        verify: Any = None,
        timeout: Any = None,
    ) -> _FakeResponse:
        """Record the verify argument and return an empty response."""
        seen["verify"] = verify
        return _FakeResponse()

    monkeypatch.setattr(wazuh_client.requests, "post", fake_post)
    wazuh_client.Client({**_BASE_CONFIG, **extra}).fetch_alerts()
    assert seen["verify"] == expected
    assert type(seen["verify"]) is type(expected)
