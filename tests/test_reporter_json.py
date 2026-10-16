"""
Tests for the JSON report written beside the markdown report.

No network, no LLM. Real evidence comes from the redacted fixtures.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from ravensight import reporter
from ravensight.analyser import extract_alert_clusters
from ravensight.reporter import Reporter
from tests.test_reporter_findings import _att, _cluster, _make_asd_data, _make_e8_scores

_FIXED_NOW = datetime(2026, 10, 15, 9, 30, 15, tzinfo=timezone.utc)


class _FrozenDatetime:
    """Stand-in for the datetime class whose now() always returns a fixed time."""

    @staticmethod
    def now(tz: Any = None) -> datetime:
        """Return the fixed time, ignoring the timezone argument."""
        return _FIXED_NOW


def _make_reporter(tmp_path: Path, overwrite: bool = False) -> Reporter:
    """Build a Reporter writing into the given temporary directory."""
    return Reporter({"output_dir": str(tmp_path), "overwrite": overwrite})


def _load(path: Path) -> dict[str, Any]:
    """Read the JSON file that sits beside a markdown report path."""
    return json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))


def _fixture_clusters() -> list[dict[str, Any]]:
    """Build real clusters (syscheck and firewall evidence) from the redacted fixtures."""
    fixtures = Path(__file__).parent / "fixtures"
    alerts = [
        json.loads((fixtures / name).read_text())
        for name in ("syscheck-550.json", "firewall-mixed-dir-87702.json")
    ]
    clusters = extract_alert_clusters(alerts)
    assert any(c.get("evidence") for c in clusters)
    return clusters


def test_json_is_valid_with_expected_keys(tmp_path: Path) -> None:
    """The JSON parses and has the documented top-level keys."""
    path = _make_reporter(tmp_path).generate({"summary": "s", "findings": [_cluster()]})
    payload = _load(path)
    assert set(payload) == {
        "schema_version",
        "generated_at",
        "run",
        "findings",
        "trends_markdown",
        "e8_status",
        "finding_pointers",
        "matched_controls",
    }
    assert payload["schema_version"] == 1


def test_generated_at_is_converted_to_utc() -> None:
    """A non-UTC time is written as the exact UTC ISO string (bypasses generate() so the host timezone cannot hide the conversion)."""
    local_now = datetime(2026, 10, 15, 18, 0, 15, tzinfo=timezone(timedelta(hours=9, minutes=30)))
    payload = reporter._build_json_payload(
        {"findings": []},
        generated_at=local_now,
        trends=None,
        run_params=None,
        e8_scores=None,
        matched_controls=None,
        finding_pointers=None,
        attestation=None,
    )
    assert payload["generated_at"] == "2026-10-15T08:30:15+00:00"


def test_json_path_matches_markdown_default_mode(tmp_path: Path) -> None:
    """In dated-folder mode the JSON is the markdown path with a .json suffix."""
    path = _make_reporter(tmp_path).generate({"summary": "s", "findings": []})
    assert path.with_suffix(".json").is_file()
    assert path.with_suffix(".json").parent == path.parent


def test_json_path_matches_markdown_overwrite_mode(tmp_path: Path) -> None:
    """In overwrite mode the JSON is the flat dated file name with .json."""
    path = _make_reporter(tmp_path, overwrite=True).generate({"summary": "s", "findings": []})
    json_path = path.with_suffix(".json")
    assert json_path.is_file()
    assert json_path.parent == tmp_path
    assert json_path.stem == path.stem
    assert path.parent == tmp_path


def test_run_null_by_default_and_echoed(tmp_path: Path) -> None:
    """run is null by default and echoes run_params when given."""
    rep = _make_reporter(tmp_path, overwrite=True)
    data = {"summary": "s", "findings": []}
    assert _load(rep.generate(data))["run"] is None
    params = {"hours": 24, "level": 7}
    assert _load(rep.generate(data, run_params=params))["run"] == params


def test_trends_markdown_string_or_null(tmp_path: Path) -> None:
    """trends_markdown is the opaque trends text, or null when absent."""
    rep = _make_reporter(tmp_path, overwrite=True)
    data = {"summary": "s", "findings": []}
    assert _load(rep.generate(data))["trends_markdown"] is None
    trends = "### Anomalies\n\n- x (+2.4σ)"
    assert _load(rep.generate(data, trends=trends))["trends_markdown"] == trends


def test_each_finding_type_serialises(tmp_path: Path) -> None:
    """Cluster, vulnerability, unattached and legacy string findings all map."""
    findings: list[Any] = [
        _cluster(id="C1", evidence=None),
        _cluster(id="C2", type="vulnerability", cves=["CVE-2026-0001"]),
        {"type": "unattached", "description": "LLM note", "recommendation": "Check it."},
        {"type": "unattached", "description": "  "},
        "Plain legacy finding",
        {"description": "bare dict"},
    ]
    path = _make_reporter(tmp_path).generate({"summary": "s", "findings": findings})
    items = _load(path)["findings"]
    assert len(items) == 5
    assert items[0]["id"] == "C1"
    assert items[0]["severity"] == "High"
    assert items[0]["recommendation"] == "Enforce key-only authentication."
    assert items[0]["hosts"] == ["host-1", "host-2"]
    assert items[1]["type"] == "vulnerability"
    assert items[1]["cves"] == ["CVE-2026-0001"]
    assert items[2] == {
        "type": "unattached",
        "description": "LLM note",
        "recommendation": "Check it.",
    }
    assert items[3] == {"type": "legacy", "text": "Plain legacy finding"}
    assert items[4]["type"] == "cluster"
    assert items[4]["id"] is None
    assert items[4]["hosts"] == []


def test_real_evidence_finding_serialises(tmp_path: Path) -> None:
    """Findings built from real fixtures keep their evidence structure in the JSON."""
    clusters = _fixture_clusters()
    path = _make_reporter(tmp_path).generate({"summary": "s", "findings": clusters})
    items = _load(path)["findings"]
    assert [i["evidence"] for i in items] == [c.get("evidence") for c in clusters]
    assert any(i["evidence"] and "syscheck" in i["evidence"] for i in items)


def test_real_shaped_e8_pointers_and_attestation(tmp_path: Path) -> None:
    """E8 scores, pointers, matched controls and attestation are written as given."""
    pointers = [
        {
            "id": "C1",
            "ism": [{"id": "ISM-1175", "category": "Patching", "shared": ["patch"]}],
            "e8": [{"strategy": "Patch applications", "shared": ["patch"]}],
        }
    ]
    attestation = {
        "Patch applications": _att("Attested", 2, "Patched monthly"),
        "Patch operating systems": _att("Not assessed"),
    }
    controls = _make_asd_data()["ism"]
    path = _make_reporter(tmp_path).generate(
        {"summary": "s", "findings": [_cluster(id="C1")]},
        asd_data=_make_asd_data(),
        e8_scores=_make_e8_scores(),
        matched_controls=controls,
        finding_pointers=pointers,
        attestation=attestation,
    )
    payload = _load(path)
    assert payload["e8_status"] == _make_e8_scores()
    assert payload["finding_pointers"] == pointers
    assert payload["matched_controls"] == controls
    assert payload["attestation"] == attestation


@pytest.mark.parametrize("attestation", [None, {}])
def test_attestation_key_omitted_when_absent(tmp_path: Path, attestation: dict | None) -> None:
    """The attestation key is omitted when there is none."""
    path = _make_reporter(tmp_path).generate(
        {"summary": "s", "findings": []}, attestation=attestation
    )
    assert "attestation" not in _load(path)


def test_excluded_sections_not_in_json(tmp_path: Path) -> None:
    """summary, mitre_tags and similar_incidents never appear in the JSON."""
    data = {
        "summary": "secret summary",
        "findings": [],
        "mitre_tags": [{"tactic": "Execution", "description": "d"}],
        "similar_incidents": "- 2026-09-29T22:11:23 past incident",
    }
    path = _make_reporter(tmp_path).generate(data)
    payload = _load(path)
    for key in ("summary", "mitre_tags", "similar_incidents"):
        assert key not in payload
    text = path.with_suffix(".json").read_text(encoding="utf-8")
    assert "secret summary" not in text
    assert "past incident" not in text


def test_markdown_byte_identical_with_json_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The markdown written is identical whether or not the JSON writer runs."""
    monkeypatch.setattr(reporter, "datetime", _FrozenDatetime)
    data = {"summary": "s", "findings": [_cluster(id="C1"), "legacy"]}
    with_json = Reporter({"output_dir": str(tmp_path / "a"), "overwrite": True}).generate(data)
    assert with_json.with_suffix(".json").is_file()

    monkeypatch.setattr(Reporter, "_write_json", lambda *args, **kwargs: None)
    without_json = Reporter({"output_dir": str(tmp_path / "b"), "overwrite": True}).generate(data)
    assert not without_json.with_suffix(".json").exists()
    assert with_json.read_bytes() == without_json.read_bytes()


def test_json_write_oserror_logs_warning_and_keeps_markdown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An OSError writing the JSON logs a warning, keeps the markdown and leaves no tmp file."""

    def fail_write(self: Path, text: str, encoding: str | None = None) -> int:
        """Create the temp file, then fail like a full disk."""
        self.touch()
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", fail_write)
    with caplog.at_level(logging.WARNING, logger="ravensight.reporter"):
        path = _make_reporter(tmp_path).generate({"summary": "s", "findings": []})
    assert path.suffix == ".md"
    assert path.read_text().startswith("# Security Report")
    assert not path.with_suffix(".json").exists()
    assert list(tmp_path.rglob("*.tmp")) == []
    assert any(r.levelno == logging.WARNING and "disk full" in r.getMessage() for r in caplog.records)


def test_json_unserialisable_value_logs_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A value json cannot encode logs a warning and keeps the markdown.

    json.dumps raises before the tmp file is ever created on this path, so the
    no-.tmp assertion only guards against a regression in that ordering.
    """
    with caplog.at_level(logging.WARNING, logger="ravensight.reporter"):
        path = _make_reporter(tmp_path).generate(
            {"summary": "s", "findings": []}, run_params={"bad": object()}
        )
    assert path.read_text().startswith("# Security Report")
    assert not path.with_suffix(".json").exists()
    assert list(tmp_path.rglob("*.tmp")) == []
    assert any(
        r.levelno == logging.WARNING and "JSON report not written" in r.getMessage()
        for r in caplog.records
    )


def test_json_circular_reference_logs_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A circular reference (ValueError from json) logs a warning and keeps the markdown.

    json.dumps raises before the tmp file is created, so no .tmp or .json file exists.
    """
    circular: dict[str, Any] = {}
    circular["self"] = circular
    with caplog.at_level(logging.WARNING, logger="ravensight.reporter"):
        path = _make_reporter(tmp_path).generate(
            {"summary": "s", "findings": []}, run_params=circular
        )
    assert path.suffix == ".md"
    assert path.read_text().startswith("# Security Report")
    assert not path.with_suffix(".json").exists()
    assert list(tmp_path.rglob("*.tmp")) == []
    assert list(tmp_path.rglob("*.json")) == []
    assert any(
        r.levelno == logging.WARNING and "JSON report not written" in r.getMessage()
        for r in caplog.records
    )
