"""
Tests for analyser.filter_similar_by_window — pure helper, no network/Chroma/LLM.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from ravensight.analyser import filter_similar_by_window


def _item(ts: str = "", severity: str = "High", summary: str = "x") -> dict[str, Any]:
    return {"timestamp": ts, "severity": severity, "summary": summary}


def test_item_inside_window_dropped() -> None:
    """Item with timestamp exactly at the cutoff (or newer) is dropped."""
    now = datetime(2026, 9, 28, 12, 0, 0)
    inside = now - timedelta(hours=1)
    outside = now - timedelta(hours=25)
    items = [_item(inside.isoformat()), _item(outside.isoformat())]
    out = filter_similar_by_window(items, 24, now=now)
    assert len(out) == 1
    assert out[0]["timestamp"] == outside.isoformat()


def test_item_older_than_window_kept() -> None:
    """Item well outside the window is kept."""
    now = datetime(2026, 9, 28, 12, 0, 0)
    items = [_item((now - timedelta(hours=48)).isoformat())]
    out = filter_similar_by_window(items, 24, now=now)
    assert out == items


def test_missing_timestamp_kept_and_logged(caplog: Any) -> None:
    """Empty timestamp is kept and DEBUG-logged."""
    caplog.set_level(logging.DEBUG, logger="ravensight.analyser")
    items = [_item("")]
    out = filter_similar_by_window(items, 24, now=datetime(2026, 9, 28, 12, 0, 0))
    assert out == items
    assert any("missing timestamp" in r.message for r in caplog.records)


def test_unparseable_timestamp_kept_and_logged(caplog: Any) -> None:
    """Garbage timestamp is kept and DEBUG-logged."""
    caplog.set_level(logging.DEBUG, logger="ravensight.analyser")
    items = [_item("not-a-date")]
    out = filter_similar_by_window(items, 24, now=datetime(2026, 9, 28, 12, 0, 0))
    assert out == items
    assert any("unparseable timestamp" in r.message for r in caplog.records)


def test_timezone_aware_timestamp_handled() -> None:
    """Aware timestamps are compared against aware cutoff (deterministic via injected now)."""
    now_aware = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
    inside_aware = now_aware - timedelta(hours=2)
    outside_aware = now_aware - timedelta(hours=48)
    items = [_item(inside_aware.isoformat()), _item(outside_aware.isoformat())]
    out = filter_similar_by_window(items, 24, now=now_aware)
    assert len(out) == 1
    assert out[0]["timestamp"] == outside_aware.isoformat()


def test_lookback_hours_none_keeps_everything() -> None:
    """None disables filtering entirely."""
    items = [_item(datetime.now(timezone.utc).isoformat()), _item(""), _item("garbage")]
    assert filter_similar_by_window(items, None) == items
