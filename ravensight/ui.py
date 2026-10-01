"""
ui.py — Terminal UI for Ravensight runs (rich-based).

This is the ONLY module that imports rich. wazuh_client, embedder and
analyser import RunReporter only under typing.TYPE_CHECKING and never call
rich at runtime.
"""
from __future__ import annotations

import logging
import sys
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    Task,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

# Today's exact non-interactive format. Kept here so the test can assert it.
_PLAIN_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"

SERVICE_NAMES = ("wazuh", "llm", "embeddings")
ServiceState = Literal["pending", "active", "ok", "warn", "fail", "off", "skipped"]
StageState = Literal["pending", "active", "done", "fail"]
StageName = Literal[
    "Config",
    "Embeddings",
    "Fetch alerts",
    "Similar incidents",
    "LLM analysis",
    "Baseline update",
    "Trends",
    "E8/ISM scoring",
    "Report",
]


def quiet_third_party_loggers(log_level: str) -> None:
    """Quiet noisy third-party loggers unless running at DEBUG level."""
    if log_level == "DEBUG":
        return
    for name in ("httpx", "httpx2", "httpcore", "chromadb", "openai"):
        logging.getLogger(name).setLevel(logging.WARNING)


class RunReporter(Protocol):
    """Reporter interface consumed by wazuh_client, embedder, analyser and main."""

    def service(self, name: str, state: ServiceState, detail: str = "") -> None: ...
    def stage(self, name: str, state: StageState, total: int | None = None) -> None: ...
    def advance(self, name: str, n: int = 1) -> None: ...
    def llm_start(self) -> None: ...
    def llm_tick(self) -> None: ...
    def llm_done(self, chunks: int, tokens: int | None, tok_s: float | None) -> None: ...
    def finish(
        self,
        analysis: dict[str, Any],
        report_path: Path | None,
        warnings: int,
        errors: int,
    ) -> None: ...

    def run(self) -> AbstractContextManager[RunReporter]: ...


class PlainReporter:
    """No-op reporter for --no-progress / piped output (D9)."""

    def service(self, name: str, state: ServiceState, detail: str = "") -> None:
        """Ignore a service state change."""

    def stage(self, name: str, state: StageState, total: int | None = None) -> None:
        """Ignore a stage state change."""

    def advance(self, name: str, n: int = 1) -> None:
        """Ignore a stage advance."""

    def llm_start(self) -> None:
        """Ignore the LLM stream start."""

    def llm_tick(self) -> None:
        """Ignore an LLM chunk."""

    def llm_done(self, chunks: int, tokens: int | None, tok_s: float | None) -> None:
        """Ignore the LLM stream completion."""

    def finish(
        self,
        analysis: dict[str, Any],
        report_path: Path | None,
        warnings: int,
        errors: int,
    ) -> None:
        """Ignore the finish-screen request."""

    @contextmanager
    def run(self) -> Iterator[PlainReporter]:
        """Yield self; a plain run has no live panel."""
        yield self


@dataclass
class _ServiceRow:
    name: str
    state: ServiceState = "pending"
    detail: str = ""


@dataclass
class _RichRunState:
    services: dict[str, _ServiceRow] = field(default_factory=dict)
    llm_info: str | None = None


_STAGE_ORDER: tuple[StageName, ...] = (
    "Config",
    "Embeddings",
    "Fetch alerts",
    "Similar incidents",
    "LLM analysis",
    "Baseline update",
    "Trends",
    "E8/ISM scoring",
    "Report",
)

_STATE_GLYPHS: dict[str, str] = {
    "ok": "[green]\u2713[/green]",       # ✓
    "active": "[blue]\u25CF[/blue]",     # ●
    "warn": "[yellow]\u26A0[/yellow]",   # ⚠
    "fail": "[red]\u2717[/red]",         # ✗
    "off": "[dim]\u00B7[/dim]",          # ·
    "skipped": "[dim]\u2014[/dim]",      # —
    "pending": "[dim]\u00B7[/dim]",      # ·
}


class _InfoColumn(ProgressColumn):
    """Render a task's info field, or a live LLM speed readout when absent."""

    def render(self, task: Task) -> Text:
        """Return the info field text, or live chunks/s for the LLM task."""
        info = task.fields.get("info")
        if info:
            return Text(str(info))
        if task.description == "Baseline update" and task.total:
            return Text(f"{int(task.completed)}/{int(task.total)} vectors")
        if task.description == "LLM analysis":
            speed = task.speed or 0.0
            return Text(f"{int(task.completed)} chunks \u00B7 {speed:.1f}/s")
        return Text("")


class RichRunReporter:
    """Rich-backed reporter: owns one shared Console and one transient Live panel."""

    def __init__(self, console: Console) -> None:
        """Initialise the reporter with the shared stderr Console."""
        self._console = console
        self._state = _RichRunState()
        for s in SERVICE_NAMES:
            self._state.services[s] = _ServiceRow(name=s)
        self._progress = Progress(
            SpinnerColumn(finished_text=_STATE_GLYPHS["ok"]),
            TextColumn("{task.description}"),
            BarColumn(bar_width=30),
            _InfoColumn(),
            TimeElapsedColumn(),
            console=console,
        )
        self._task_ids: dict[str, TaskID] = {}
        for name in _STAGE_ORDER:
            self._task_ids[name] = self._progress.add_task(
                name, visible=False, start=False, total=None
            )
        self._live: Live | None = None

    def service(self, name: str, state: ServiceState, detail: str = "") -> None:
        """Record a service state change for the panel."""
        row = self._state.services.get(name) or _ServiceRow(name=name)
        row.state = state
        if detail:
            row.detail = detail
        if name not in self._state.services:
            self._state.services[name] = row
        self._push()

    def stage(self, name: str, state: StageState, total: int | None = None) -> None:
        """Record a stage state change on the progress task."""
        task_id = self._task_ids.get(name)
        if task_id is None:
            return
        if state == "active":
            self._progress.update(task_id, visible=True)
            if total is not None:
                self._progress.update(task_id, total=total)
            self._progress.start_task(task_id)
        elif state == "done":
            # Stages can finish without ever being active (Config, Embeddings,
            # or analyse's early return), so show and start them here too.
            self._progress.update(task_id, visible=True)
            self._progress.start_task(task_id)
            self._progress.stop_task(task_id)
            completed = max(self._completed_for(task_id), 1.0)
            self._progress.update(task_id, total=completed, completed=completed)
        elif state == "fail":
            self._progress.stop_task(task_id)
            self._progress.update(task_id, description=f"[red]\u2717 {name}[/red]")
        self._push()

    def advance(self, name: str, n: int = 1) -> None:
        """Advance a named stage task by n steps; unknown names are ignored."""
        task_id = self._task_ids.get(name)
        if task_id is None:
            return
        self._progress.update(task_id, advance=n)

    def llm_start(self) -> None:
        """Make the LLM analysis task active."""
        self.stage("LLM analysis", "active")

    def llm_tick(self) -> None:
        """Advance the LLM task by one chunk; the Live auto-refresh redraws it."""
        task_id = self._task_ids["LLM analysis"]
        self._progress.update(task_id, advance=1)

    def llm_done(self, chunks: int, tokens: int | None, tok_s: float | None) -> None:
        """Record the final chunk/token counts and stop the LLM progress task."""
        if tokens is not None and tok_s is not None:
            info = f"{tokens} tokens \u00B7 {tok_s:.1f} tok/s"
        elif tok_s is not None:
            info = f"{chunks} chunks \u00B7 {tok_s:.1f} chunks/s"
        else:
            info = f"{chunks} chunks"
        self._state.llm_info = info
        task_id = self._task_ids.get("LLM analysis")
        if task_id is not None:
            self._progress.update(task_id, info=info)
        self._push()

    @contextmanager
    def run(self) -> Iterator[RichRunReporter]:
        """Run the Live panel around a full analysis run."""
        live = Live(self._render(), console=self._console, transient=True,
                    refresh_per_second=12)
        self._live = live
        with live:
            yield self
        self._live = None

    def _push(self) -> None:
        """Swap the renderable on the active Live panel (auto-refresh repaints it)."""
        if self._live is not None:
            self._live.update(self._render())

    def _completed_for(self, task_id: int) -> float:
        """Return a task's completed step count, or 0.0 when absent."""
        for task in self._progress.tasks:
            if task.id == task_id:
                return task.completed
        return 0.0

    def _render(self) -> Panel:
        """Build the panel renderable: service dots above progress bars."""
        return Panel(
            Group(self._service_line(), self._progress),
            title="Ravensight",
            border_style="grey50",
            expand=False,
        )

    def _service_line(self) -> Text:
        """Build the one-line service status text."""
        text = Text()
        for i, row in enumerate(self._state.services.values()):
            if i:
                text.append("  ")
            glyph = _STATE_GLYPHS.get(row.state, _STATE_GLYPHS["pending"])
            text.append(Text.from_markup(glyph))
            text.append(f" {row.name}")
            if row.detail and row.state in ("warn", "fail"):
                text.append(f"  \u2014 {row.detail}", style="dim")
        return text

    def finish(
        self,
        analysis: dict[str, Any],
        report_path: Path | None,
        warnings: int,
        errors: int,
    ) -> None:
        """Print the finish screen after the Live panel has closed."""
        rows, severity_counts, notes_count, unattached_count = build_finish_table(analysis)
        del notes_count  # notes are shown per-row; the aggregate stays in the table
        if rows:
            self._print_finish_table(rows, severity_counts, unattached_count,
                                     warnings, errors, report_path)
        else:
            self._print_finish_empty(severity_counts, unattached_count,
                                     warnings, errors, report_path)

    def _print_finish_table(
        self,
        rows: list[dict[str, Any]],
        severity_counts: dict[str, int],
        unattached_count: int,
        warnings: int,
        errors: int,
        report_path: Path | None,
    ) -> None:
        """Render the cluster table for the finish screen."""
        table = Table(box=box.SIMPLE_HEAD, show_lines=False, header_style="bold")
        table.add_column("ID", style="dim")
        table.add_column("Severity")
        table.add_column("Alerts", justify="right")
        table.add_column("Hosts", justify="right")
        table.add_column("Finding", max_width=60, overflow="ellipsis", no_wrap=True)
        table.add_column("Notes", justify="right")
        table.add_column("Flags", justify="right")
        sev_styles = {"High": "red", "Medium": "yellow", "Low": "blue"}
        for r in rows:
            table.add_row(
                Text(r["id"]),
                Text(r["severity"], style=sev_styles.get(r["severity"], "dim")),
                str(r["alerts"]),
                Text(r["hosts"]),
                Text(r["finding"]),
                str(r["notes"]),
                str(r["flags"]),
            )
        summary = self._summary_line(severity_counts, unattached_count,
                                     warnings, errors, report_path)
        self._print_finish_panel(Group(table, summary))

    def _print_finish_empty(
        self,
        severity_counts: dict[str, int],
        unattached_count: int,
        warnings: int,
        errors: int,
        report_path: Path | None,
    ) -> None:
        """Render the no-findings finish screen."""
        summary = self._summary_line(severity_counts, unattached_count,
                                     warnings, errors, report_path)
        self._print_finish_panel(Group(Text("No findings", style="dim"), Text(""), summary))

    def _print_finish_panel(self, body: Group) -> None:
        """Print the finish screen as one bordered box, with a gap above it."""
        self._console.print()
        self._console.print(
            Panel(body, title="Finish", border_style="grey50", expand=False)
        )

    def _summary_line(
        self,
        severity_counts: dict[str, int],
        unattached_count: int,
        warnings: int,
        errors: int,
        report_path: Path | None,
    ) -> Text:
        """Build the severity counts, warning/error totals, report path and LLM line."""
        h = severity_counts.get("High", 0)
        m = severity_counts.get("Medium", 0)
        l = severity_counts.get("Low", 0)
        line = Text()
        line.append(f"{h} High", style="red")
        line.append("  ")
        line.append(f"{m} Medium", style="yellow")
        line.append("  ")
        line.append(f"{l} Low", style="blue")
        if unattached_count:
            line.append("  ")
            line.append(f"{unattached_count} unattached notes")
        if warnings:
            line.append("  ")
            line.append(f"{warnings} warning(s)", style="yellow")
        if errors:
            line.append("  ")
            line.append(f"{errors} error(s)", style="red")
        if report_path is not None:
            line.append("  ")
            line.append(f"report: {report_path}")
        if self._state.llm_info is not None:
            line.append("  ")
            line.append(f"LLM: {self._state.llm_info}")
        return line


class CountingHandler(logging.Handler):
    """Count WARNING and ERROR-or-above records for the finish screen."""

    def __init__(self) -> None:
        """Initialise the counters."""
        super().__init__()
        self._warnings = 0
        self._errors = 0

    @property
    def warnings(self) -> int:
        """Number of WARNING records seen."""
        return self._warnings

    @property
    def errors(self) -> int:
        """Number of ERROR and CRITICAL records seen."""
        return self._errors

    def emit(self, record: logging.LogRecord) -> None:
        """Increment the counter matching the record level."""
        if record.levelno >= logging.ERROR:
            self._errors += 1
        elif record.levelno >= logging.WARNING:
            self._warnings += 1


def create_reporter(no_progress: bool) -> tuple[RunReporter, logging.Handler]:
    """Build the run reporter and its matching log handler.

    Interactive = not no_progress and console.is_interactive. All output goes
    to stderr through one shared Console; non-interactive output is
    byte-identical to the pre-rich log lines.
    """
    console = Console(stderr=True)
    interactive = not no_progress and console.is_interactive
    if interactive:
        handler: logging.Handler = RichHandler(
            console=console,
            show_path=False,
            markup=False,
            # A short time on every line keeps the left column solid instead
            # of leaving gaps wherever the time repeats.
            omit_repeated_times=False,
            log_time_format="%H:%M:%S",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        return RichRunReporter(console), handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_PLAIN_FORMAT))
    return PlainReporter(), handler


def build_finish_table(
    analysis: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, int], int, int]:
    """Build the finish-screen rows and counts from an analysis dict.

    Returns (rows, severity_counts, notes_count, unattached_count) where rows
    exclude unattached findings and severity_counts counts High/Medium/Low
    cluster findings only.
    """
    findings = analysis.get("findings", [])
    rows: list[dict[str, Any]] = []
    severity_counts: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}
    notes_count = 0
    unattached_count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if finding.get("type") == "unattached":
            if finding.get("description", "").strip():
                unattached_count += 1
            notes_count += len(finding.get("notes", []))
            continue
        severity = finding.get("severity", "")
        if severity in severity_counts:
            severity_counts[severity] += 1
        hosts_list = finding.get("hosts", [])
        host_count = len(hosts_list)
        hosts = f"{host_count} ({hosts_list[0]}, {hosts_list[1]})" if host_count >= 2 else (
            f"1 ({hosts_list[0]})" if host_count == 1 else "0"
        )
        rows.append({
            "id": finding.get("id", ""),
            "severity": severity,
            "alerts": finding.get("count", 0),
            "hosts": hosts,
            "finding": finding.get("description", ""),
            "notes": len(finding.get("notes", [])),
            "flags": len(finding.get("flags", [])),
        })
        notes_count += len(finding.get("notes", []))
    return rows, severity_counts, notes_count, unattached_count