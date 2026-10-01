"""
Tests for ravensight/ui.py — reporters, finish table, counting handler,
timings extraction and the empty-choices LLM stream chunk.
"""
from __future__ import annotations

import io
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ravensight import analyser
from ravensight.analyser import _extract_timings
from ravensight.ui import (
    Console,  # re-exported: tests must not import rich directly
    CountingHandler,
    PlainReporter,
    RichRunReporter,
    build_finish_table,
    create_reporter,
    quiet_third_party_loggers,
)

LLM_CONFIG = {
    "base_url": "http://llm.invalid/v1",
    "api_key": "local",
    "model": "test-model",
    "max_tokens": 512,
    "temperature": 0.0,
}


def _alert(description: str, level: int, agent: str = "host-1") -> dict[str, Any]:
    """Build one alert dict in the documented Wazuh shape."""
    return {
        "_source": {
            "agent": {"name": agent},
            "rule": {"id": "1002", "description": description, "level": level},
            "@timestamp": "2026-09-24T10:00:00.000Z",
        }
    }


def _cluster_finding(
    fid: str,
    severity: str,
    hosts: list[str],
    count: int,
    description: str = "Finding text",
    notes: list[str] | None = None,
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Build one cluster finding dict as analyse() produces it."""
    finding: dict[str, Any] = {
        "type": "rule",
        "id": fid,
        "severity": severity,
        "hosts": hosts,
        "count": count,
        "description": description,
        "notes": notes or [],
        "flags": flags or [],
    }
    return finding


def _unattached(description: str) -> dict[str, Any]:
    """Build one unattached finding dict as _parse_analysis produces it."""
    return {
        "type": "unattached",
        "description": description,
        "count": 0,
        "hosts": [],
        "severity": "",
        "narrative": "",
        "recommendation": "",
    }


class DummyReporter:
    """Records RunReporter calls for assertions."""

    def __init__(self) -> None:
        self.services: list[tuple[str, str, str]] = []
        self.stages: list[tuple[str, str]] = []
        self.llm_done_calls: list[tuple[int, int | None, float | None]] = []
        self.llm_started = False
        self.chunks = 0

    def service(self, name: str, state: str, detail: str = "") -> None:
        self.services.append((name, state, detail))

    def stage(self, name: str, state: str, total: int | None = None) -> None:
        self.stages.append((name, state))

    def advance(self, name: str, n: int = 1) -> None:
        """No-op advance to satisfy the RunReporter protocol."""

    def llm_start(self) -> None:
        self.llm_started = True

    def llm_tick(self) -> None:
        self.chunks += 1

    def llm_done(self, chunks: int, tokens: int | None, tok_s: float | None) -> None:
        self.llm_done_calls.append((chunks, tokens, tok_s))

    def finish(
        self,
        analysis: dict[str, Any],
        report_path: Path | None,
        warnings: int,
        errors: int,
    ) -> None:
        return None

    @contextmanager
    def run(self) -> Iterator[DummyReporter]:
        yield self


def test_plain_reporter_no_output(capsys: pytest.CaptureFixture[str]) -> None:
    """PlainReporter methods all no-op and print nothing."""
    rep = PlainReporter()
    rep.service("wazuh", "ok")
    rep.stage("Fetch alerts", "done")
    rep.llm_start()
    rep.llm_tick()
    rep.llm_done(3, None, None)
    rep.finish({"findings": []}, None, 0, 0)
    with rep.run() as active:
        assert active is rep
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_create_reporter_no_progress() -> None:
    """--no-progress yields a PlainReporter and the plain StreamHandler format."""
    rep, handler = create_reporter(True)
    assert isinstance(rep, PlainReporter)
    assert isinstance(handler, logging.StreamHandler)
    assert handler.stream is sys.stderr
    assert handler.formatter is not None
    assert handler.formatter._fmt == "%(asctime)s - %(levelname)s - %(message)s"


def test_rich_run_reporter_non_tty_no_ansi() -> None:
    """A RichRunReporter on a non-terminal console emits no ANSI escapes."""
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False)
    rep = RichRunReporter(console)
    with rep.run():
        rep.service("wazuh", "ok")
        rep.stage("Fetch alerts", "active")
        rep.stage("Fetch alerts", "done")
        rep.llm_start()
        rep.llm_tick()
        rep.llm_done(2, 5, 1.5)
    rep.finish(
        {"findings": [_cluster_finding("C1", "High", ["h1"], 3)]},
        Path("reports/2026-10-01_security_report.md"),
        1,
        0,
    )
    assert "\x1b[" not in buffer.getvalue()


def test_build_finish_table_severity_counts() -> None:
    """Severity counts exclude unattached; rows exclude them too."""
    analysis = {
        "findings": [
            _cluster_finding("C1", "High", ["h1"], 3, notes=["n1", "n2"]),
            _cluster_finding("C2", "Medium", ["h2"], 1),
            _cluster_finding("C3", "Low", ["h3"], 1),
            _unattached("free-floating note"),
        ]
    }
    rows, severity_counts, notes_count, unattached_count = build_finish_table(analysis)
    assert severity_counts == {"High": 1, "Medium": 1, "Low": 1}
    assert len(rows) == 3
    assert unattached_count == 1
    assert notes_count == 2


def test_build_finish_table_flags_count() -> None:
    """A finding's flags list length lands in the row's flags field."""
    analysis = {
        "findings": [_cluster_finding("C1", "High", ["h1"], 3, flags=["a", "b"])]
    }
    rows, _, _, _ = build_finish_table(analysis)
    assert rows[0]["flags"] == 2


def test_build_finish_table_excludes_unattached_from_rows() -> None:
    """Unattached findings never appear in the finish table rows."""
    analysis = {
        "findings": [
            _cluster_finding("C1", "High", ["h1"], 3),
            _unattached("note one"),
            _unattached("note two"),
        ]
    }
    rows, _, _, unattached_count = build_finish_table(analysis)
    assert len(rows) == 1
    assert rows[0]["id"] == "C1"
    assert unattached_count == 2


def test_build_finish_table_long_description() -> None:
    """A 200-character description still produces a row without raising."""
    analysis = {
        "findings": [_cluster_finding("C1", "High", ["h1"], 3, description="x" * 200)]
    }
    rows, _, _, _ = build_finish_table(analysis)
    assert len(rows) == 1
    assert len(rows[0]["finding"]) == 200


def test_build_finish_table_empty_analysis() -> None:
    """An empty findings list yields no rows and zero counts."""
    rows, severity_counts, notes_count, unattached_count = build_finish_table(
        {"findings": []}
    )
    assert rows == []
    assert severity_counts == {"High": 0, "Medium": 0, "Low": 0}
    assert notes_count == 0
    assert unattached_count == 0


def test_counting_handler_warning() -> None:
    """A WARNING record increments counter.warnings only."""
    counter = CountingHandler()
    record = logging.LogRecord("test", logging.WARNING, __file__, 1, "warn", (), None)
    counter.handle(record)
    assert counter.warnings == 1
    assert counter.errors == 0


def test_counting_handler_error_and_critical() -> None:
    """ERROR and CRITICAL records each increment counter.errors."""
    counter = CountingHandler()
    error = logging.LogRecord("test", logging.ERROR, __file__, 1, "boom", (), None)
    critical = logging.LogRecord("test", logging.CRITICAL, __file__, 1, "boom", (), None)
    counter.handle(error)
    counter.handle(critical)
    assert counter.errors == 2
    assert counter.warnings == 0


def test_extract_timings_present() -> None:
    """Timings are read from chunk.model_extra['timings']."""
    chunk = SimpleNamespace(
        choices=[],
        model_extra={"timings": {"predicted_n": 42, "predicted_per_second": 7.5}},
    )
    assert _extract_timings(chunk) == (42, 7.5)


def test_extract_timings_model_extra_none() -> None:
    """A chunk without model_extra yields (None, None)."""
    chunk = SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="x"))])
    assert _extract_timings(chunk) == (None, None)


def test_extract_timings_timings_missing() -> None:
    """An empty model_extra yields (None, None)."""
    chunk = SimpleNamespace(choices=[], model_extra={})
    assert _extract_timings(chunk) == (None, None)


def test_analyse_stream_with_empty_choices_chunk(monkeypatch: pytest.MonkeyPatch) -> None:
    """A final choices==[] chunk with timings must not crash and adds no text."""
    content_chunk = SimpleNamespace(
        choices=[SimpleNamespace(delta=SimpleNamespace(content="<findings>\n- [C1] Brute force attempt\n</findings>"))],
    )
    timings_chunk = SimpleNamespace(
        choices=[],
        model_extra={"timings": {"predicted_n": 5, "predicted_per_second": 1.0}},
    )

    class _FakeStream:
        def __iter__(self) -> _FakeStream:
            self._chunks = [content_chunk, timings_chunk]
            return self

        def __next__(self) -> Any:
            if not self._chunks:
                raise StopIteration
            return self._chunks.pop(0)

    class _Chat:
        def __init__(self) -> None:
            self.completions = self

        def create(self, **kwargs: Any) -> Any:
            return _FakeStream()

    class _Client:
        def __init__(self) -> None:
            self.chat = _Chat()

    monkeypatch.setattr(analyser, "OpenAI", lambda **kw: _Client())

    progress = DummyReporter()
    alerts = [_alert("SSHD brute force", 12)]
    result = analyser.analyse(alerts, {}, LLM_CONFIG, progress=progress)
    by_id = {f["id"]: f for f in result["findings"]}
    assert by_id["C1"]["narrative"] == "Brute force attempt"
    assert progress.llm_started
    assert progress.chunks == 1
    assert progress.llm_done_calls
    assert progress.llm_done_calls[-1][1] == 5
    assert ("llm", "ok", "") in progress.services
    assert ("LLM analysis", "done") in progress.stages


def test_finish_table_renders_unescaped_markup_verbatim() -> None:
    """Untrusted text containing rich markup tokens renders verbatim, not parsed."""
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=True)
    rep = RichRunReporter(console)
    finding = _cluster_finding(
        "C1",
        "High",
        ["h1"],
        1,
        description="See [/tmp/x] and [bold]x[/bold]",
    )
    rep.finish({"findings": [finding]}, None, 0, 0)
    output = buffer.getvalue()
    assert "[/tmp/x]" in output
    assert "[bold]x[/bold]" in output


def test_render_service_detail_unescaped() -> None:
    """A service detail containing rich markup tokens renders verbatim."""
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=True)
    rep = RichRunReporter(console)
    with rep.run():
        rep.service("embeddings", "warn", detail="[Errno 111] Connection refused")
    output = buffer.getvalue()
    assert "[Errno 111] Connection refused" in output


def test_llm_line_shows_chunks_per_second_when_tokens_none() -> None:
    """When tokens is None but tok_s is set, the panel shows chunks/s not tokens."""
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=True)
    rep = RichRunReporter(console)
    with rep.run():
        rep.llm_start()
        rep.llm_tick()
        rep.llm_tick()
        rep.llm_tick()
        rep.llm_tick()
        rep.llm_tick()
        rep.llm_done(5, None, 12.5)
    output = buffer.getvalue()
    assert "5 chunks" in output
    assert "12.5 chunks/s" in output
    assert "tokens" not in output


def test_analyse_marks_llm_ok_when_first_chunk_has_empty_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first chunk — even an empty-content one — triggers llm service ok and llm_start."""
    # First chunk: choices present, but delta.content is "" (no actual token payload).
    empty_content_chunk = SimpleNamespace(
        choices=[SimpleNamespace(delta=SimpleNamespace(content=""))],
    )
    # Second chunk: real content carrying the LLM output.
    content_chunk = SimpleNamespace(
        choices=[SimpleNamespace(
            delta=SimpleNamespace(
                content="<findings>\n- [C1] Brute force attempt\n</findings>",
            ),
        )],
    )

    class _FakeStream:
        def __iter__(self) -> _FakeStream:
            self._chunks = [empty_content_chunk, content_chunk]
            return self

        def __next__(self) -> Any:
            if not self._chunks:
                raise StopIteration
            return self._chunks.pop(0)

    class _Chat:
        def __init__(self) -> None:
            self.completions = self

        def create(self, **kwargs: Any) -> Any:
            return _FakeStream()

    class _Client:
        def __init__(self) -> None:
            self.chat = _Chat()

    monkeypatch.setattr(analyser, "OpenAI", lambda **kw: _Client())

    progress = DummyReporter()
    alerts = [_alert("SSHD brute force", 12)]
    result = analyser.analyse(alerts, {}, LLM_CONFIG, progress=progress)
    by_id = {f["id"]: f for f in result["findings"]}
    assert by_id["C1"]["narrative"] == "Brute force attempt"
    assert progress.llm_started
    assert progress.chunks == 1
    assert ("llm", "ok", "") in progress.services


def test_quiet_third_party_loggers_sets_warning_unless_debug() -> None:
    """Non-DEBUG levels quiet third-party loggers; DEBUG leaves them untouched."""
    names = ("httpx", "httpcore", "chromadb", "openai")
    for name in names:
        logging.getLogger(name).setLevel(logging.NOTSET)
    try:
        quiet_third_party_loggers("INFO")
        assert logging.getLogger("httpx").level == logging.WARNING
        assert logging.getLogger("httpcore").level == logging.WARNING
        assert logging.getLogger("chromadb").level == logging.WARNING
        assert logging.getLogger("openai").level == logging.WARNING
        for name in names:
            logging.getLogger(name).setLevel(logging.NOTSET)
        quiet_third_party_loggers("DEBUG")
        assert logging.getLogger("httpx").level == logging.NOTSET
    finally:
        for name in names:
            logging.getLogger(name).setLevel(logging.NOTSET)


def test_stage_active_to_done_renders_full_task() -> None:
    """stage active→done produces a completed task without raising."""
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=True, width=120)
    rep = RichRunReporter(console)
    with rep.run():
        rep.stage("Fetch alerts", "active")
        rep.stage("Fetch alerts", "done")
    assert buffer.getvalue()


def test_advance_baseline_update_reaches_total() -> None:
    """advance() on a total=3 stage reaches 3 after three advances."""
    rep = RichRunReporter(Console(file=io.StringIO(), force_terminal=True))
    rep.stage("Baseline update", "active", total=3)
    rep.advance("Baseline update")
    rep.advance("Baseline update")
    rep.advance("Baseline update")
    task_id = rep._task_ids["Baseline update"]
    assert rep._completed_for(task_id) == 3


def test_advance_unknown_name_is_ignored() -> None:
    """advance() on an unknown stage name is silently ignored."""
    rep = RichRunReporter(Console(file=io.StringIO(), force_terminal=True))
    rep.advance("Does not exist")
    assert "Does not exist" not in rep._task_ids


def test_llm_tick_advances_llm_task() -> None:
    """llm_tick advances the LLM task's completed count."""
    rep = RichRunReporter(Console(file=io.StringIO(), force_terminal=True))
    rep.llm_start()
    rep.llm_tick()
    rep.llm_tick()
    task_id = rep._task_ids["LLM analysis"]
    assert rep._completed_for(task_id) == 2


def test_rendered_panel_has_title_and_border() -> None:
    """The live panel renders a 'Ravensight' title inside a bordered box."""
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=True, width=120)
    rep = RichRunReporter(console)
    with rep.run():
        rep.stage("Config", "done")
    output = buffer.getvalue()
    assert "Ravensight" in output
    assert "\u2500" in output


def test_finish_summary_shows_llm_info() -> None:
    """The finish summary appends 'LLM: N tokens · X.X tok/s' when known."""
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=True)
    rep = RichRunReporter(console)
    rep.llm_done(5, 512, 31.4)
    rep.finish({"findings": []}, None, 0, 0)
    assert "LLM: 512 tokens \u00B7 31.4 tok/s" in buffer.getvalue()


def test_finish_table_long_finding_on_one_line_with_ellipsis() -> None:
    """A 200-character finding truncates with an ellipsis on a single line."""
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=True, width=120)
    rep = RichRunReporter(console)
    finding = _cluster_finding("C1", "High", ["h1"], 1, description="x" * 200)
    rep.finish({"findings": [finding]}, None, 0, 0)
    output = buffer.getvalue()
    assert "\u2026" in output
    assert "x" * 200 not in output
    x_lines = [line for line in output.splitlines() if "x" in line]
    assert len(x_lines) == 1
    assert "x\u2026" in x_lines[0]


def test_plain_reporter_accepts_total_and_advance() -> None:
    """PlainReporter accepts the new total and advance arguments without error."""
    rep = PlainReporter()
    rep.stage("Baseline update", "active", total=3)
    rep.advance("Baseline update")
    rep.stage("Baseline update", "done")
    rep.advance("Baseline update", n=2)
