"""
Tests for baseline handling of dict findings and rule severities (Build 1b).

No network — embedder interactions are faked with a stub.
"""

import json
from pathlib import Path
from typing import Any

from ravensight import baseline
from ravensight.embedder import finding_text


def _dict_finding(**overrides: Any) -> dict[str, Any]:
    """Build a cluster-shaped dict finding."""
    finding: dict[str, Any] = {
        "id": "C1",
        "type": "rule",
        "description": "SSHD brute force attempts",
        "rule_ids": ["5710"],
        "hosts": ["host-1"],
        "count": 12,
        "max_level": 12,
        "severity": "High",
        "first_seen": "2026-09-24T08:00:00.000Z",
        "last_seen": "2026-09-24T09:00:00.000Z",
        "cves": [],
        "package": None,
        "narrative": "Narrative text.",
        "recommendation": "Recommendation text.",
    }
    finding.update(overrides)
    return finding


class _StubEmbedder:
    """Records add_embedding calls instead of touching a vector store."""

    def __init__(self) -> None:
        self.degraded = False
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def add_embedding(self, text: str, metadata: dict[str, Any]) -> None:
        self.calls.append((text, metadata))


def test_dict_findings_round_trip(tmp_path: Path) -> None:
    """Dict findings written to the baseline survive a load unchanged."""
    path = tmp_path / "baseline.json"
    manager = baseline.Manager({"path": str(path)})
    findings = [_dict_finding(), _dict_finding(id="C2", severity="Medium")]
    manager.update({"findings": findings, "recommendations": ["rec one"]})

    reloaded = baseline.Manager({"path": str(path)})
    assert reloaded.load()["findings"] == findings
    # JSON round-trip is clean — no sets or other non-serialisable values
    with path.open("r", encoding="utf-8") as f:
        json.load(f)


def test_update_writes_severity_from_rule_severities(tmp_path: Path) -> None:
    """baseline.update embeds rule severities when supplied."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update(
        {"findings": [], "recommendations": []},
        rule_counts={"SSHD brute force": 4},
        rule_severities={"SSHD brute force": "High"},
    )
    assert len(stub.calls) == 1
    text, metadata = stub.calls[0]
    assert text == "SSHD brute force: 4 alerts"
    assert metadata["severity"] == "High"


def test_update_severity_defaults_unknown_without_rule_severities(
    tmp_path: Path,
) -> None:
    """Existing callers passing no rule_severities keep 'unknown' severity."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update({"findings": [], "recommendations": []}, rule_counts={"r": 1})
    assert stub.calls[0][1]["severity"] == "unknown"


def test_update_severity_none_guard(tmp_path: Path) -> None:
    """An explicit None rule_severities is guarded and defaults to 'unknown'."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update(
        {"findings": [], "recommendations": []},
        rule_counts={"r": 1},
        rule_severities=None,
    )
    assert stub.calls[0][1]["severity"] == "unknown"


def test_finding_text_dict_and_string() -> None:
    """finding_text embeds '{description}: {narrative}' for dicts, str otherwise."""
    assert finding_text("plain string") == "plain string"
    assert finding_text(_dict_finding()) == (
        "SSHD brute force attempts: Narrative text."
    )
    assert finding_text(_dict_finding(narrative="")) == "SSHD brute force attempts"


def test_finding_text_json_safe_and_deterministic() -> None:
    """finding_text output is deterministic and JSON-serialisable."""
    finding = _dict_finding()
    first = finding_text(finding)
    finding["count"] = 999
    finding["first_seen"] = "changed"
    assert finding_text(finding) == first
    json.dumps(first)


def test_migrate_baseline_uses_finding_text_not_repr(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """migrate_baseline embeds finding_text() and the dict's real severity."""
    from ravensight.embedder import Embedder

    monkeypatch.setattr(Embedder, "encode", lambda self, text: [0.0] * 8)
    emb = Embedder({"chroma_db_path": str(tmp_path / "chroma")})
    data = {
        "updated_at": "2026-09-24T00:00:00",
        "findings": [_dict_finding()],
        "recommendations": [],
    }
    emb.migrate_baseline(data)

    doc = emb._collection.get(where={"rule_group": "baseline_finding"})
    text = doc["documents"][0]
    assert text == "SSHD brute force attempts: Narrative text."
    assert text != repr(data["findings"][0])
    assert doc["metadatas"][0]["severity"] == "High"
    assert doc["metadatas"][0]["summary"] == text


def test_summary_round_trip_and_renders_in_report(tmp_path: Path) -> None:
    """A stored summary survives reload and renders in the report body."""
    from ravensight.reporter import Reporter

    summary = "X alerts in Y clusters across 3 hosts"
    path = tmp_path / "baseline.json"
    manager = baseline.Manager({"path": str(path)})
    manager.update(
        {"findings": [_dict_finding()], "recommendations": ["rec one"], "summary": summary}
    )

    reloaded = baseline.Manager({"path": str(path)})
    assert reloaded.load()["summary"] == summary

    rep = Reporter({"output_dir": str(tmp_path / "reports")})
    report = rep._build_report(reloaded.load())
    assert summary in report
    assert "No summary available" not in report


def test_migrate_baseline_string_finding_unchanged(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """String findings still embed via str() with 'unknown' severity."""
    from ravensight.embedder import Embedder

    monkeypatch.setattr(Embedder, "encode", lambda self, text: [0.0] * 8)
    emb = Embedder({"chroma_db_path": str(tmp_path / "chroma")})
    data = {
        "updated_at": "2026-09-24T00:00:00",
        "findings": ["plain string finding"],
        "recommendations": [],
    }
    emb.migrate_baseline(data)

    doc = emb._collection.get(where={"rule_group": "baseline_finding"})
    assert doc["documents"][0] == "plain string finding"
    assert doc["metadatas"][0]["severity"] == "unknown"
