"""
trending.py — Historical alert trend analysis.
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


class Trending:
    """Analyses historical alert trends from baseline scan history."""

    def __init__(self, config: dict[str, Any]) -> None:
        """
        Initialise trending module.

        Args:
            config: Trending config with window_days and output_standalone keys.
        """
        self._window_days = config.get("window_days", 30)
        self._output_standalone = config.get("output_standalone", False)

    def generate(self, baseline: dict[str, Any]) -> str:
        """
        Generate trending markdown from baseline data.

        Args:
            baseline: Baseline dict with scan_history.

        Returns:
            Markdown formatted trending summary.
        """
        scan_history = baseline.get("scan_history", [])
        if not scan_history:
            return self._empty_report()

        trends = self._calculate_trends(scan_history, self._window_days)
        anomalies = self._detect_anomalies(trends)
        return self._build_table(trends, anomalies)

    def write_report(self, baseline: dict[str, Any]) -> None:
        """
        Write standalone trending report to disk.

        Args:
            baseline: Baseline dict with scan_history.
        """
        content = self.generate(baseline)
        output_dir = Path("reports")
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = output_dir / f"trending_{datetime.now().strftime('%Y-%m-%d')}.md"
        with filename.open("w") as f:
            f.write(content)
        logger.info(f"Trending report written to {filename}")

    def _calculate_trends(
        self, history: list[dict[str, Any]], window_days: int
    ) -> dict[str, dict[str, Any]]:
        """
        Calculate trends per rule group over window.

        Args:
            history: List of scan history entries with timestamp and rule_groups.
            window_days: Rolling window in days.

        Returns:
            Dict mapping rule group to trend data (avg, count, direction).
        """
        cutoff = datetime.now() - timedelta(days=window_days)
        recent = []
        for entry in history:
            ts = entry.get("timestamp", "")
            try:
                entry_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if entry_time.replace(tzinfo=None) >= cutoff:
                    recent.append(entry)
            except ValueError:
                continue

        if not recent:
            return {}

        all_groups: set[str] = set()
        for entry in recent:
            all_groups.update(entry.get("rule_groups", {}).keys())

        trends: dict[str, dict[str, Any]] = {}
        for group in all_groups:
            counts = []
            for entry in recent:
                counts.append(entry.get("rule_groups", {}).get(group, 0))
            avg = sum(counts) / len(counts) if counts else 0
            direction = "up" if counts[-1] > counts[0] + (avg * 0.2) else "stable"
            if len(counts) >= 3 and counts[-1] > counts[-2] > counts[-3]:
                direction = "up"
            elif len(counts) >= 3 and counts[-1] < counts[-2] < counts[-3]:
                direction = "down"
            trends[group] = {
                "avg": round(avg, 1),
                "count": len(counts),
                "direction": direction,
                "latest": counts[-1] if counts else 0,
            }

        return trends

    def _detect_anomalies(self, trends: dict[str, dict[str, Any]]) -> list[str]:
        """
        Detect rule groups with upward trend across consecutive runs.

        Args:
            trends: Dict of trend data per rule group.

        Returns:
            List of rule groups flagged as anomalies.
        """
        anomalies = []
        for group, data in trends.items():
            if data["direction"] == "up" and data["count"] >= 3:
                anomalies.append(group)
        return anomalies

    def _build_table(
        self, trends: dict[str, dict[str, Any]], anomalies: list[str]
    ) -> str:
        """Build markdown table of trends."""
        if not trends:
            return self._empty_report()

        lines = [
            "## Historical Trends",
            "",
            f"*Rolling window: {self._window_days} days*",
            "",
            "| Rule Group | Avg/run | Latest | Direction |",
            "|------------|---------|--------|------------|",
        ]

        for group, data in sorted(trends.items()):
            flag = " ⚠️" if group in anomalies else ""
            direction_symbol = {"up": "↑", "down": "↓", "stable": "→"}[
                data["direction"]
            ]
            lines.append(
                f"| {group} | {data['avg']} | {data['latest']} | {direction_symbol}{flag} |"
            )

        if anomalies:
            lines.extend(["", "### Anomalies Detected", ""])
            for group in anomalies:
                lines.append(f"- **{group}**: upward trend across {trends[group]['count']} consecutive runs")

        lines.append("")
        return "\n".join(lines)

    def _empty_report(self) -> str:
        """Return empty report message."""
        return "## Historical Trends\n\n*No scan history available*\n"