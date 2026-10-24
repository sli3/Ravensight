"""
Tests for the structured trends data (Trending.generate_data) and its wiring.

No network — fixtures build scan-history entries directly, with timestamps
computed relative to ``datetime.now()`` so the 30-day window is never flaky.
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

import main
from ravensight import analyser, reporter, wazuh_client
from ravensight.trending import Trending


def _ts(days_ago: float) -> str:
    """Return an aware UTC ISO timestamp ``days_ago`` days before now."""
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _run(
    days_ago: float,
    counts: dict[str, int],
    *,
    hours: int = 24,
    agent: str | None = None,
    level: int = 7,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build one default-run scan-history entry with the given cluster counts."""
    return {
        "timestamp": timestamp if timestamp is not None else _ts(days_ago),
        "hours": hours,
        "agent": agent,
        "level": level,
        "cluster_counts": counts,
    }


def _history(*runs: dict[str, Any]) -> dict[str, Any]:
    """Wrap run entries in a baseline dict."""
    return {"scan_history": list(runs)}


def _generate(*runs: dict[str, Any], config: dict[str, Any] | None = None) -> str:
    """Generate trending markdown from the given runs."""
    mgr = Trending(config or {})
    return mgr.generate(_history(*runs))


GOLDEN_MARKDOWN = (
    "## Historical Trends\n\n"
    "*Rolling window: 30 days · 4 daily run(s) · same-day reruns collapsed to "
    "the last run; non-default runs excluded*\n\n"
    "| Finding | Avg/day | Latest | Days seen | Direction |\n"
    "|---------|---------|--------|-----------|-----------|\n"
    "| spike | 6.5 | 20 | 4 | ↑ ⚠️ |\n"
    "| fresh | 0.2 | 1 | 4 | ★ new |\n\n"
    "*+3 more not shown*\n\n"
    "### Anomalies\n\n"
    "> σ (sigma) shows how many standard deviations the latest count is above "
    "the average of the previous days. A rise of more than 2.0σ is flagged. A "
    "count that rose from a previously flat history is flagged too. At least 3 "
    "earlier days are needed, and with few earlier days the figure is a rough "
    "guide.\n\n"
    "- **spike**: 20 latest vs 2.0/day over the previous 3 days (+22.0σ)\n\n"
    "### First seen in this window\n\n"
    "- fresh\n"
)


def test_golden_markdown_unchanged() -> None:
    """The markdown table output is pinned byte for byte."""
    output = _generate(
        _run(4, {"rule|spike": 1, "rule|a": 5, "rule|b": 4, "rule|c": 3}),
        _run(3, {"rule|spike": 2, "rule|a": 5, "rule|b": 4, "rule|c": 3}),
        _run(2, {"rule|spike": 3, "rule|a": 5, "rule|b": 4, "rule|c": 3}),
        _run(1, {"rule|spike": 20, "rule|a": 5, "rule|b": 4, "rule|c": 3,
                 "rule|fresh": 1}),
        config={"max_rows": 2},
    )
    assert output == GOLDEN_MARKDOWN


def _data(*runs: dict[str, Any], config: dict[str, Any] | None = None,
          aliases: dict[str, str] | None = None) -> dict[str, Any] | None:
    """Generate structured trend data from the given runs."""
    return Trending(config or {}).generate_data(_history(*runs), vendor_aliases=aliases)


def _day(days_ago: int) -> str:
    """Return the local calendar date ``days_ago`` days before now, as YYYY-MM-DD."""
    now = datetime.now(timezone.utc).astimezone().replace(tzinfo=None)
    return (now - timedelta(days=days_ago)).date().isoformat()


def _four_days() -> tuple[dict[str, Any], ...]:
    """Return the four-day fixture used by the golden test."""
    return (
        _run(4, {"rule|spike": 1, "rule|a": 5, "rule|b": 4, "rule|c": 3}),
        _run(3, {"rule|spike": 2, "rule|a": 5, "rule|b": 4, "rule|c": 3}),
        _run(2, {"rule|spike": 3, "rule|a": 5, "rule|b": 4, "rule|c": 3}),
        _run(1, {"rule|spike": 20, "rule|a": 5, "rule|b": 4, "rule|c": 3,
                 "rule|fresh": 1}),
    )


def test_rows_match_text_table_rows_and_order() -> None:
    """The structured rows are the same findings in the same order as the table."""
    runs = _four_days()
    data = _data(*runs)
    assert data is not None
    markdown = _generate(*runs)
    table = [
        line.split("|")[1].strip()
        for line in markdown.splitlines()
        if line.startswith("| ") and not line.startswith("| Finding")
    ]
    assert [r["label"] for r in data["rows"]] == table
    assert data["window_days"] == 30


def test_counts_align_with_days_and_absent_day_is_zero() -> None:
    """counts line up with days, and a finding absent on a run day counts 0."""
    data = _data(
        _run(3, {"rule|x": 4, "rule|y": 2}),
        _run(2, {"rule|x": 5}),
        _run(1, {"rule|x": 6, "rule|y": 1}),
    )
    assert data is not None
    assert data["days"] == [_day(3), _day(2), _day(1)]
    by_label = {r["label"]: r for r in data["rows"]}
    assert by_label["x"]["counts"] == [4, 5, 6]
    assert by_label["y"]["counts"] == [2, 0, 1]
    assert all(len(r["counts"]) == len(data["days"]) for r in data["rows"])


def test_cap_and_hidden() -> None:
    """The row cap applies and hidden counts the rest, as in the text footer."""
    data = _data(*_four_days(), config={"max_rows": 2})
    assert data is not None
    assert len(data["rows"]) == 2
    assert data["hidden"] == 3


def test_none_for_no_history_and_no_qualifying_day() -> None:
    """None is returned for no scan history and for no qualifying daily run."""
    assert Trending({}).generate_data({}) is None
    assert Trending({}).generate_data({"scan_history": []}) is None
    assert _data(_run(1, {"rule|x": 1}, hours=6)) is None


def test_vendor_aliases_applied_in_label() -> None:
    """Vendor aliases rewrite the label, matching the text table."""
    runs = (_run(2, {"rule|oldname alert": 1}), _run(1, {"rule|oldname alert": 2}))
    aliases = {"oldname": "Newname"}
    aliased = _data(*runs, aliases=aliases)
    assert aliased is not None
    assert aliased["rows"][0]["label"] == "Newname alert"
    markdown = Trending({}).generate(_history(*runs), vendor_aliases=aliases)
    assert "| Newname alert |" in markdown


def test_no_cluster_key_or_internal_fields_in_rows() -> None:
    """Rows carry exactly the documented fields and no cluster key."""
    data = _data(*_four_days())
    assert data is not None
    for row in data["rows"]:
        assert set(row) == {
            "label", "counts", "latest", "avg", "days_seen", "direction", "anomaly",
        }
        assert not row["label"].startswith("rule|")


def test_avg_is_float_rounded_to_one_decimal() -> None:
    """avg is a float with one decimal even when the mean is exact."""
    data = _data(_run(2, {"rule|x": 2}), _run(1, {"rule|x": 2}))
    assert data is not None
    avg = data["rows"][0]["avg"]
    assert isinstance(avg, float)
    assert avg == 2.0
    rounded = _data(*_four_days())
    assert rounded is not None
    fresh = next(r for r in rounded["rows"] if r["label"] == "fresh")
    assert fresh["avg"] == 0.2


def test_rows_empty_when_every_cluster_counts_empty() -> None:
    """Empty cluster_counts maps give an empty rows list while days is not empty."""
    data = _data(_run(2, {}), _run(1, {}))
    assert data is not None
    assert data["rows"] == []
    assert data["days"] == [_day(2), _day(1)]
    assert data["hidden"] == 0


_TRENDING_CONFIG = """
[reports]
output_dir = "{tmp}/reports"

[baseline]
path = "{tmp}/baseline.json"

[wazuh]
host = "x"
indexer_host = "x"
indexer_port = 9200
indexer_user = "admin"
indexer_password = "p"

[llm]
base_url = "http://example.invalid/v1"
api_key = "local"
model = "any"

[trending]
window_days = 30
"""


def _drive_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra_args: list[str]
) -> dict[str, Any]:
    """Run main.main with a fake Reporter.generate and return the kwargs it received."""
    captured: dict[str, Any] = {}

    def fake_generate(self: Any, data: Any, **kwargs: Any) -> Path:
        """Record the keyword arguments and return a report path."""
        captured.update(kwargs)
        return tmp_path / "report.md"

    sentinel = {"window_days": 30, "days": [], "hidden": 0, "rows": []}
    monkeypatch.setattr(reporter.Reporter, "generate", fake_generate)
    monkeypatch.setattr(Trending, "generate_data", lambda self, *a, **k: sentinel)
    monkeypatch.setattr(wazuh_client.Client, "fetch_alerts", lambda self, **kwargs: [])
    monkeypatch.setattr(
        analyser, "analyse",
        lambda *args, **kwargs: {"summary": "s", "findings": [], "recommendations": []},
    )
    monkeypatch.setattr(analyser, "extract_alert_clusters", lambda alerts: [])
    cfg = tmp_path / "config.toml"
    cfg.write_text(_TRENDING_CONFIG.format(tmp=tmp_path), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["main.py", "--config", str(cfg), *extra_args])
    main.main()
    assert captured["trends_data"] is sentinel
    return captured


def test_main_passes_trends_data_report_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A --report-only run hands trends_data to Reporter.generate."""
    captured = _drive_main(tmp_path, monkeypatch, ["--report-only"])
    assert "trends" in captured


def test_main_passes_trends_data_full_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full run hands trends_data to Reporter.generate."""
    captured = _drive_main(tmp_path, monkeypatch, ["--hours", "6"])
    assert "run_params" in captured
