"""
Tests for baseline handling of dict findings and per-cluster vector writes.

No network — embedder interactions are faked with a stub.
"""

import json
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

from ravensight import analyser, baseline
from ravensight.embedder import finding_text

DEFAULT_PARAMS = {"hours": 24, "agent": None, "level": 7}


def _cluster(**overrides: Any) -> dict[str, Any]:
    """Build a cluster dict as extract_alert_clusters() returns."""
    cluster: dict[str, Any] = {
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
    cluster.update(overrides)
    return cluster


def _vuln_cluster(**overrides: Any) -> dict[str, Any]:
    """Build a vulnerability cluster with a package."""
    cluster = _cluster(
        type="vulnerability",
        description="2 vulnerabilities affect openssl",
        hosts=["host-2"],
        count=2,
        severity="Medium",
        package="openssl",
    )
    cluster.update(overrides)
    return cluster


class _StubEmbedder:
    """Records add_embedding calls instead of touching a vector store."""

    def __init__(self) -> None:
        self.degraded = False
        self._chroma_failure: str | None = None
        self.calls: list[tuple[str, dict[str, Any], str | None]] = []

    def add_embedding(
        self, text: str, metadata: dict[str, Any], doc_id: str | None = None
    ) -> None:
        self.calls.append((text, metadata, doc_id))


def _expected_doc_id(key: str, day: str) -> str:
    """Compute the deterministic doc_id baseline writes for key+day."""
    return "alert-" + sha256(f"{key}|{day}".encode()).hexdigest()[:32]


def test_dict_findings_round_trip(tmp_path: Path) -> None:
    """Dict findings written to the baseline survive a load unchanged."""
    path = tmp_path / "baseline.json"
    manager = baseline.Manager({"path": str(path)})
    findings = [_cluster(), _cluster(id="C2", severity="Medium")]
    manager.update({"findings": findings, "recommendations": ["rec one"]})

    reloaded = baseline.Manager({"path": str(path)})
    assert reloaded.load()["findings"] == findings
    # JSON round-trip is clean — no sets or other non-serialisable values
    with path.open("r", encoding="utf-8") as f:
        json.load(f)


def test_is_default_run_matches_approved_parameters() -> None:
    """is_default_run is True only for 24 h, no agent, level 7."""
    assert baseline.is_default_run({"hours": 24, "agent": None, "level": 7}) is True
    assert baseline.is_default_run({"hours": 168, "agent": None, "level": 7}) is False
    assert baseline.is_default_run({"hours": 24, "agent": "001", "level": 7}) is False
    assert baseline.is_default_run({"hours": 24, "agent": None, "level": 3}) is False
    assert baseline.is_default_run({"hours": 24}) is False
    assert baseline.is_default_run(None) is False


def test_update_writes_one_vector_per_cluster(tmp_path: Path) -> None:
    """One default run writes exactly one vector per cluster."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    clusters = [_cluster(), _vuln_cluster()]
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=clusters,
        run_params=DEFAULT_PARAMS,
    )
    assert len(stub.calls) == 2


def test_update_vector_text_has_no_counts(tmp_path: Path) -> None:
    """Embedding text carries no counts; vuln text names package and host."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=[_cluster(count=12), _vuln_cluster(count=2)],
        run_params=DEFAULT_PARAMS,
    )
    rule_text, _, _ = stub.calls[0]
    vuln_text, _, _ = stub.calls[1]
    assert rule_text == "SSHD brute force attempts"
    assert vuln_text == "Vulnerabilities affect openssl on host host-2"
    assert "12" not in rule_text
    assert "2 " not in vuln_text


def test_update_doc_id_stable_same_day_and_unique_per_key(tmp_path: Path) -> None:
    """doc_id is deterministic per key+day and distinct between keys."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=[_cluster(), _vuln_cluster()],
        run_params=DEFAULT_PARAMS,
    )
    today = datetime.now().strftime("%Y-%m-%d")
    rule_key = analyser.cluster_key(_cluster())
    vuln_key = analyser.cluster_key(_vuln_cluster())
    _, _, rule_doc_id = stub.calls[0]
    _, _, vuln_doc_id = stub.calls[1]
    assert rule_doc_id == _expected_doc_id(rule_key, today)
    assert vuln_doc_id == _expected_doc_id(vuln_key, today)
    assert rule_doc_id != vuln_doc_id


def test_update_doc_id_changes_across_days(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The same key on a different calendar day gets a different doc_id."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    clusters = [_cluster()]

    day_one = datetime(2026, 9, 28, 6, 0, 0)
    day_two = datetime(2026, 9, 29, 6, 0, 0)

    class _FrozenDateTime(datetime):
        """datetime subclass whose now() returns a fixed value."""

        _frozen = day_one

        @classmethod
        def now(cls, tz: Any = None) -> datetime:
            return cls._frozen

    monkeypatch.setattr(baseline, "datetime", _FrozenDateTime)
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=clusters,
        run_params=DEFAULT_PARAMS,
    )
    first_id = stub.calls[0][2]

    _FrozenDateTime._frozen = day_two
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=clusters,
        run_params=DEFAULT_PARAMS,
    )
    second_id = stub.calls[1][2]

    assert first_id == _expected_doc_id("rule|SSHD brute force attempts", "2026-09-28")
    assert second_id == _expected_doc_id("rule|SSHD brute force attempts", "2026-09-29")
    assert first_id != second_id


def test_update_severity_comes_from_cluster(tmp_path: Path) -> None:
    """Vector metadata severity is the cluster's own severity label."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=[_cluster(severity="High"), _vuln_cluster(severity="Medium")],
        run_params=DEFAULT_PARAMS,
    )
    assert stub.calls[0][1]["severity"] == "High"
    assert stub.calls[1][1]["severity"] == "Medium"


def test_update_summary_uses_singular_and_plural(tmp_path: Path) -> None:
    """Metadata summary uses 'alert'/'alerts' correctly and appends host for vulns."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=[_cluster(count=1), _vuln_cluster(count=2)],
        run_params=DEFAULT_PARAMS,
    )
    assert stub.calls[0][1]["summary"] == "SSHD brute force attempts: 1 alert"
    assert stub.calls[1][1]["summary"] == (
        "2 vulnerabilities affect openssl: 2 alerts on host-2"
    )


def test_update_no_vector_writes_for_non_default_runs(tmp_path: Path) -> None:
    """Non-default runs (hours, agent, level) write no vectors but still snapshot."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=[_cluster()],
        run_params={"hours": 168, "agent": None, "level": 7},
    )
    assert stub.calls == []
    history = manager.load()["scan_history"]
    assert len(history) == 1
    assert history[0]["hours"] == 168


def test_update_no_vector_writes_without_run_params(tmp_path: Path) -> None:
    """Missing run_params means no vector writes even with clusters present."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update({"findings": [], "recommendations": []}, clusters=[_cluster()])
    assert stub.calls == []


def test_snapshot_carries_run_params_and_cluster_counts(tmp_path: Path) -> None:
    """The snapshot records hours/agent/level and per-cluster counts, no rule_groups."""
    path = tmp_path / "baseline.json"
    manager = baseline.Manager({"path": str(path)})
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=[_cluster(count=12), _vuln_cluster(count=2)],
        run_params={"hours": 24, "agent": "agent-9", "level": 7},
    )
    snapshot = manager.load()["scan_history"][-1]
    assert snapshot["hours"] == 24
    assert snapshot["agent"] == "agent-9"
    assert snapshot["level"] == 7
    assert snapshot["cluster_counts"] == {
        "rule|SSHD brute force attempts": 12,
        "vuln|host-2|openssl": 2,
    }
    assert "rule_groups" not in snapshot
    assert "timestamp" in snapshot


def test_scan_history_pruned_to_ninety_days(tmp_path: Path) -> None:
    """Entries older than SCAN_HISTORY_MAX_DAYS are dropped; unparseable kept."""
    path = tmp_path / "baseline.json"
    manager = baseline.Manager({"path": str(path)})
    old_ok = (datetime.now() - timedelta(days=100)).isoformat()
    recent = (datetime.now() - timedelta(days=2)).isoformat()
    manager.load()["scan_history"] = [
        {"timestamp": old_ok, "cluster_counts": {"rule|stale": 1}},
        {"timestamp": "not-a-date", "cluster_counts": {"rule|kept": 1}},
        {"timestamp": recent, "cluster_counts": {"rule|fresh": 1}},
    ]
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=[],
        run_params=DEFAULT_PARAMS,
    )
    kept = manager.load()["scan_history"]
    timestamps = [e.get("timestamp") for e in kept]
    assert old_ok not in timestamps
    assert "not-a-date" in timestamps
    assert recent in timestamps


def test_update_breaks_when_embedder_degrades_mid_run(tmp_path: Path) -> None:
    """A mid-run embedder failure stops cluster writes but never crashes update."""

    class _FlakyEmbedder(_StubEmbedder):
        """Fails on the first call after setting degraded, like the real embedder."""

        def add_embedding(
            self, text: str, metadata: dict[str, Any], doc_id: str | None = None
        ) -> None:
            self.calls.append((text, metadata, doc_id))
            self.degraded = True
            self._chroma_failure = "ChromaError: vanished"
            raise ValueError("embedding server unreachable")

    path = tmp_path / "baseline.json"
    stub = _FlakyEmbedder()
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=[_cluster(id="C1"), _cluster(id="C2", description="Other rule")],
        run_params=DEFAULT_PARAMS,
    )
    assert len(stub.calls) == 1
    assert path.exists()


def test_degraded_embedder_skips_writes_entirely(tmp_path: Path) -> None:
    """An already-degraded embedder triggers the warning break before any encode."""
    path = tmp_path / "baseline.json"
    stub = _StubEmbedder()
    stub.degraded = True
    stub._chroma_failure = "ConnectError: connection refused"
    manager = baseline.Manager({"path": str(path)}, embedder=stub)
    manager.update(
        {"findings": [], "recommendations": []},
        clusters=[_cluster()],
        run_params=DEFAULT_PARAMS,
    )
    assert stub.calls == []


def test_finding_text_dict_and_string() -> None:
    """finding_text embeds '{description}: {narrative}' for dicts, str otherwise."""
    assert finding_text("plain string") == "plain string"
    assert finding_text(_cluster()) == (
        "SSHD brute force attempts: Narrative text."
    )
    assert finding_text(_cluster(narrative="")) == "SSHD brute force attempts"


def test_finding_text_json_safe_and_deterministic() -> None:
    """finding_text output is deterministic and JSON-serialisable."""
    finding = _cluster()
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
        "findings": [_cluster()],
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
        {"findings": [_cluster()], "recommendations": ["rec one"], "summary": summary}
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
