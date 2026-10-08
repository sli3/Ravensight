"""
Tests for the rewritten trending module (per-cluster keys, default-run filter).

No network — fixtures build scan-history entries directly, with timestamps
computed relative to ``datetime.now()`` so the 30-day window is never flaky.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from ravensight import trending
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


def _row_for(output: str, label: str) -> str:
    """Return the table row whose Finding cell starts with the given label."""
    for line in output.splitlines():
        if line.startswith("| ") and label in line:
            return line
    raise AssertionError(f"no table row containing {label!r} in:\n{output}")


def test_directions_up_down_stable_new() -> None:
    """Up, down, stable and new directions all render with their symbols."""
    output = _generate(
        _run(4, {"rule|up-key": 2, "rule|down-key": 10, "rule|stable-key": 5}),
        _run(3, {"rule|up-key": 2, "rule|down-key": 10, "rule|stable-key": 5}),
        _run(2, {"rule|up-key": 2, "rule|down-key": 10, "rule|stable-key": 5}),
        _run(1, {"rule|up-key": 9, "rule|down-key": 2, "rule|stable-key": 6,
                  "rule|new-key": 1}),
    )
    # new-key first appears on the final day only
    assert "★ new" in _row_for(output, "new-key")
    # up-key: 9 vs prior mean 2, delta 7 >= max(3, 1.0) — up
    assert "↑" in _row_for(output, "up-key")
    # down-key: 2 vs prior mean 10, delta -8 <= -max(3, 5.0) — down
    assert "↓" in _row_for(output, "down-key")
    # stable-key: 6 vs prior mean 5, delta 1 < 3 — stable
    assert "→" in _row_for(output, "stable-key")


def test_small_increase_1_to_2_is_stable() -> None:
    """A 1 -> 2 rise is below the absolute threshold and stays stable."""
    output = _generate(
        _run(2, {"rule|tiny": 1}),
        _run(1, {"rule|tiny": 2}),
    )
    assert "→" in _row_for(output, "tiny")


def test_first_appearance_after_zero_days_is_new_not_up() -> None:
    """(0, 0, 0, 1) is 'new' — zero-activity days do not make it 'up'."""
    output = _generate(
        _run(4, {"rule|other": 3}),
        _run(3, {"rule|other": 3}),
        _run(2, {"rule|other": 3}),
        _run(1, {"rule|other": 3, "rule|late-key": 1}),
    )
    row = _row_for(output, "late-key")
    assert "★ new" in row
    assert "↑" not in row


def test_latest_zero_after_activity_is_down() -> None:
    """A key dropping to 0 on the latest day is 'down'."""
    output = _generate(
        _run(3, {"rule|gone": 5}),
        _run(2, {"rule|gone": 5}),
        _run(1, {"rule|gone": 0}),
    )
    assert "↓" in _row_for(output, "gone")


def test_anomaly_on_genuine_rise() -> None:
    """A sharp rise beyond 2 sigma over 3+ prior days is flagged anomalous."""
    output = _generate(
        _run(4, {"rule|spike": 1}),
        _run(3, {"rule|spike": 2}),
        _run(2, {"rule|spike": 3}),
        _run(1, {"rule|spike": 20}),
    )
    assert "⚠️" in _row_for(output, "spike")
    assert "### Anomalies" in output


def test_anomaly_on_flat_then_jump() -> None:
    """A flat prior series (pstdev 0) that jumps is anomalous."""
    output = _generate(
        _run(4, {"rule|flat-jump": 4}),
        _run(3, {"rule|flat-jump": 4}),
        _run(2, {"rule|flat-jump": 4}),
        _run(1, {"rule|flat-jump": 30}),
    )
    assert "⚠️" in _row_for(output, "flat-jump")
    assert "(previously flat)" in output


def test_no_anomaly_on_noisy_up() -> None:
    """An upward move within 2 sigma of a noisy prior is not anomalous."""
    output = _generate(
        _run(4, {"rule|noisy": 5}),
        _run(3, {"rule|noisy": 20}),
        _run(2, {"rule|noisy": 2}),
        _run(1, {"rule|noisy": 20}),
    )
    assert "⚠️" not in _row_for(output, "noisy")
    assert "### Anomalies" not in output


def test_no_anomaly_with_fewer_than_three_prior_days() -> None:
    """A huge jump with only 2 prior days is up but not anomalous."""
    output = _generate(
        _run(2, {"rule|young": 1}),
        _run(1, {"rule|young": 50}),
    )
    assert "↑" in _row_for(output, "young")
    assert "⚠️" not in _row_for(output, "young")
    assert "### Anomalies" not in output


def test_anomaly_text_has_numbers_and_no_consecutive_wording() -> None:
    """The anomaly bullet reports measured values and never says 'consecutive'."""
    output = _generate(
        _run(4, {"rule|spike": 2}),
        _run(3, {"rule|spike": 2}),
        _run(2, {"rule|spike": 2}),
        _run(1, {"rule|spike": 12}),
    )
    assert "consecutive" not in output
    assert "12 latest vs 2.0/day over the previous 3 days" in output
    assert "(previously flat)" in output


def test_sigma_spread_rendered_when_prior_not_flat() -> None:
    """A non-flat prior renders the +N.Nσ spread in the anomaly bullet."""
    output = _generate(
        _run(4, {"rule|spike": 1}),
        _run(3, {"rule|spike": 2}),
        _run(2, {"rule|spike": 3}),
        _run(1, {"rule|spike": 20}),
    )
    assert "2.0/day over the previous 3 days (+0.8σ)" in output


def test_same_day_reruns_collapse_to_last_run() -> None:
    """Two runs on one calendar day use the last run's counts."""
    today = datetime.now(timezone.utc)
    earlier = (today - timedelta(hours=2)).isoformat()
    later = (today - timedelta(hours=1)).isoformat()
    output = _generate(
        _run(0, {"rule|rerun": 5}, timestamp=earlier),
        _run(0, {"rule|rerun": 9}, timestamp=later),
    )
    row = _row_for(output, "rerun")
    assert "| 9 |" in row


def test_non_default_runs_excluded() -> None:
    """hours=168, agent-set and level!=7 entries never reach the series."""
    output = _generate(
        _run(3, {"rule|base": 2}),
        _run(2, {"rule|base": 2, "rule|weekly": 8}, hours=168),
        _run(2, {"rule|base": 2, "rule|agent-scoped": 8}, agent="001"),
        _run(2, {"rule|base": 2, "rule|low-level": 8}, level=3),
        _run(1, {"rule|base": 2}),
    )
    assert "weekly" not in output
    assert "agent-scoped" not in output
    assert "low-level" not in output


def test_entries_without_cluster_counts_ignored() -> None:
    """Legacy rule_groups-only entries are skipped silently."""
    legacy = {
        "timestamp": _ts(1),
        "hours": 24,
        "agent": None,
        "level": 7,
        "rule_groups": {"old style": 4},
    }
    output = _generate(legacy, _run(1, {"rule|fresh": 3}))
    assert "old style" not in output
    assert "fresh" in output


def test_days_without_runs_are_not_zeros() -> None:
    """A gap day contributes no 0 — the average is over run days only."""
    output = _generate(
        _run(3, {"rule|gap": 4}),
        _run(1, {"rule|gap": 4}),
    )
    row = _row_for(output, "gap")
    # mean over the two run days only: 4.0, not 4/3 rounded down
    assert "| gap | 4.0 | 4 |" in row


def test_row_cap_with_footer_and_priority_rows_bypass_cap() -> None:
    """Anomaly/new rows always show; regular rows stop at max_rows; footer counts the cut."""
    runs = [
        _run(4, {"rule|anomaly-key": 2, **{f"rule|stable-{i:02d}": 10 - i for i in range(5)}}),
        _run(3, {"rule|anomaly-key": 2, **{f"rule|stable-{i:02d}": 10 - i for i in range(5)}}),
        _run(2, {"rule|anomaly-key": 2, **{f"rule|stable-{i:02d}": 10 - i for i in range(5)}}),
        _run(1, {
            "rule|anomaly-key": 30,
            "rule|new-key": 1,
            "rule|stable-00": 10,
            "rule|stable-01": 9,
            "rule|stable-02": 8,
            "rule|stable-03": 7,
            "rule|stable-04": 6,
        }),
    ]
    output = _generate(*runs, config={"max_rows": 3})

    assert "anomaly-key" in output
    assert "★ new" in _row_for(output, "new-key")
    # 2 priority rows + 1 regular row = max_rows; 4 regular rows are cut
    assert "*+4 more not shown*" in output
    table_rows = [
        line for line in output.splitlines()
        if line.startswith("| ") and "Finding" not in line
    ]
    assert len(table_rows) == 3


def test_pipe_escaped_in_labels() -> None:
    """Descriptions containing '|' are escaped inside table cells."""
    output = _generate(
        _run(2, {"rule|user | sudo | root": 3}),
        _run(1, {"rule|user | sudo | root": 3}),
    )
    assert "user \\| sudo \\| root" in output


def test_z_suffixed_timestamps_handled() -> None:
    """Aware 'Z' timestamps are converted to naive local and kept in-window."""
    ts = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    output = _generate(_run(0, {"rule|utc-key": 6}, timestamp=ts))
    assert "utc-key" in output


def test_malformed_timestamps_skipped() -> None:
    """Unparseable timestamps are skipped without crashing the report."""
    bad = _run(1, {"rule|bad-ts": 5}, timestamp="not-a-timestamp")
    output = _generate(bad, _run(1, {"rule|good": 2}))
    assert "bad-ts" not in output
    assert "good" in output


def test_no_qualifying_runs_message() -> None:
    """History exists but no qualifying runs yields the dedicated message."""
    output = _generate(
        _run(1, {"rule|x": 1}, hours=168),
        {"timestamp": _ts(1), "rule_groups": {"legacy": 2}},
    )
    assert output == (
        "## Historical Trends\n\n*No qualifying daily runs in the window yet*\n"
    )


def test_no_scan_history_keeps_existing_empty_message() -> None:
    """An empty scan_history still yields the original empty report."""
    mgr = Trending({})
    assert mgr.generate({}) == "## Historical Trends\n\n*No scan history available*\n"


def test_note_line_counts_daily_runs() -> None:
    """The note reports the number of collapsed daily runs in the window."""
    today_noon = (
        datetime.now(timezone.utc)
        .astimezone()
        .replace(hour=12, minute=0, second=0, microsecond=0)
    )
    output = _generate(
        _run(2, {"rule|a": 1}, timestamp=(today_noon - timedelta(days=2)).isoformat()),
        _run(0, {"rule|a": 1}, timestamp=(today_noon - timedelta(hours=3)).isoformat()),
        _run(0, {"rule|a": 2}, timestamp=(today_noon - timedelta(hours=1)).isoformat()),
    )
    assert "2 daily run(s)" in output


def test_vuln_label_rendered_from_key() -> None:
    """Vulnerability keys render as 'Vulnerabilities in pkg (host)'."""
    output = _generate(
        _run(2, {"vuln|host-1|openssl": 4}),
        _run(1, {"vuln|host-1|openssl": 4}),
    )
    assert "Vulnerabilities in openssl (host-1)" in output


def test_module_constants() -> None:
    """The trend thresholds are the approved decision values."""
    assert trending.TREND_ABS == 3
    assert trending.TREND_REL == 0.5
    assert trending.ANOMALY_MIN_PRIOR == 3
    assert trending.ANOMALY_SIGMA == 2.0
    assert trending.DEFAULT_MAX_ROWS == 25
