"""
trending.py — Historical alert trend analysis.
"""

import logging
from datetime import datetime, timedelta
from statistics import mean, pstdev
from typing import Any

from ravensight import analyser, baseline

logger = logging.getLogger(__name__)

TREND_ABS = 3
TREND_REL = 0.5
ANOMALY_MIN_PRIOR = 3
ANOMALY_SIGMA = 2.0
DEFAULT_MAX_ROWS = 25

_DIRECTION_SYMBOLS = {"up": "↑", "down": "↓", "stable": "→"}


class Trending:
    """Analyses historical alert trends from baseline scan history."""

    def __init__(self, config: dict[str, Any]) -> None:
        """
        Initialise trending module.

        Args:
            config: Trending config with window_days and max_rows keys.
        """
        self._window_days = config.get("window_days", 30)
        self._max_rows = config.get("max_rows", DEFAULT_MAX_ROWS)

    def generate(self, baseline_data: dict[str, Any]) -> str:
        """
        Generate trending markdown from baseline data.

        Args:
            baseline_data: Baseline dict with scan_history.

        Returns:
            Markdown formatted trending summary.
        """
        scan_history = baseline_data.get("scan_history", [])
        if not scan_history:
            return self._empty_report()

        series = self._collect_series(scan_history)
        if not series:
            return (
                "## Historical Trends\n\n"
                "*No qualifying daily runs in the window yet*\n"
            )

        rows = self._build_rows(series)
        return self._render(rows, n_days=len(series))

    def _collect_series(self, history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter, collapse and shape scan history into per-day count maps.

        Returns a list of {date, counts} dicts, one per local calendar day that
        had a qualifying default run, sorted by day. A key absent on a day with
        a run counts as 0; days with no run are not represented at all.
        """
        cutoff = datetime.now() - timedelta(days=self._window_days)
        qualifying: list[tuple[datetime, dict[str, Any]]] = []
        for entry in history:
            counts = entry.get("cluster_counts")
            if not isinstance(counts, dict):
                continue
            ts = entry.get("timestamp", "")
            try:
                parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except ValueError:
                logger.debug(f"scan_history entry has unparseable timestamp {ts!r} — skipped")
                continue
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone().replace(tzinfo=None)
            if parsed < cutoff:
                continue
            if not baseline.is_default_run(entry):
                continue
            qualifying.append((parsed, counts))

        qualifying.sort(key=lambda item: item[0])

        # Collapse same-day reruns to the last run of that local calendar day
        by_day: dict[str, dict[str, Any]] = {}
        for parsed, counts in qualifying:
            by_day[parsed.date().isoformat()] = counts

        return [
            {"date": day, "counts": by_day[day]}
            for day in sorted(by_day)
        ]

    def _build_rows(self, series: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Compute trend and anomaly data for every key seen in the series."""
        all_keys: set[str] = set()
        for day in series:
            all_keys.update(day["counts"].keys())

        rows: list[dict[str, Any]] = []
        for key in all_keys:
            values = [day["counts"].get(key, 0) for day in series]
            latest = values[-1]
            prior = values[:-1]
            row: dict[str, Any] = {
                "key": key,
                "latest": latest,
                "avg": mean(values),
                "days_seen": len(values),
            }

            if len(values) == 1 or sum(prior) == 0:
                direction = "new"
            elif latest == 0 and sum(prior) > 0:
                direction = "down"
            else:
                prior_mean = mean(prior)
                delta = latest - prior_mean
                threshold = max(TREND_ABS, TREND_REL * prior_mean)
                if delta >= threshold:
                    direction = "up"
                elif delta <= -threshold:
                    direction = "down"
                else:
                    direction = "stable"
            row["direction"] = direction

            prior_std = pstdev(prior) if prior else 0.0
            row["anomaly"] = (
                direction == "up"
                and len(prior) >= ANOMALY_MIN_PRIOR
                and (
                    prior_std == 0
                    or latest > mean(prior) + ANOMALY_SIGMA * prior_std
                )
            )
            row["prior_mean"] = mean(prior) if prior else 0.0
            row["prior_std"] = prior_std
            row["n_prior"] = len(prior)
            rows.append(row)

        return rows

    def _render(self, rows: list[dict[str, Any]], n_days: int) -> str:
        """Render trend rows into the markdown report."""
        rows.sort(key=lambda r: (-r["latest"], -r["avg"], self._label(r["key"])))

        shown = [r for r in rows if r["anomaly"] or r["direction"] == "new"]
        regular = [r for r in rows if not (r["anomaly"] or r["direction"] == "new")]
        shown.extend(regular[: max(0, self._max_rows - len(shown))])
        hidden = len(rows) - len(shown)

        note = (
            f"*Rolling window: {self._window_days} days · {n_days} "
            "daily run(s) · same-day reruns collapsed to the last run; "
            "non-default runs excluded*"
        )

        lines = [
            "## Historical Trends",
            "",
            note,
            "",
            "| Finding | Avg/day | Latest | Days seen | Direction |",
            "|---------|---------|--------|-----------|-----------|",
        ]
        for row in shown:
            label = self._label(row["key"]).replace("|", "\\|")
            symbol = "★ new" if row["direction"] == "new" else _DIRECTION_SYMBOLS[row["direction"]]
            if row["anomaly"]:
                symbol += " ⚠️"
            lines.append(
                f"| {label} | {row['avg']:.1f} | {row['latest']} | "
                f"{row['days_seen']} | {symbol} |"
            )

        if hidden > 0:
            lines.extend(["", f"*+{hidden} more not shown*"])

        anomalies = [r for r in rows if r["anomaly"]]
        if anomalies:
            lines.extend(["", "### Anomalies", ""])
            for row in anomalies:
                label = self._label(row["key"]).replace("|", "\\|")
                if row["prior_std"] == 0:
                    spread = "(previously flat)"
                else:
                    spread = f"+{row['prior_std']:.1f}σ"
                lines.append(
                    f"- **{label}**: {row['latest']} latest vs "
                    f"{row['prior_mean']:.1f}/day over the previous {row['n_prior']} days ({spread})"
                )

        new_rows = [r for r in rows if r["direction"] == "new"]
        if new_rows:
            lines.extend(["", "### First seen in this window", ""])
            for row in new_rows:
                label = self._label(row["key"]).replace("|", "\\|")
                lines.append(f"- {label}")

        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _label(key: str) -> str:
        """Return the display label for a cluster key."""
        return analyser.cluster_label(key)

    def _empty_report(self) -> str:
        """Return empty report message."""
        return "## Historical Trends\n\n*No scan history available*\n"
