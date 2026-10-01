"""Tests for scripts/eval_prompt.py scoring and row shape (Build 1e).

No LLM, no network: analyser.analyse() and the config/ping helpers are
monkeypatched.
"""

import json
import sys
from pathlib import Path
from typing import Any

from scripts import eval_prompt


def _cluster(**overrides: Any) -> dict[str, Any]:
    """Build one cluster finding dict with sensible defaults."""
    cluster: dict[str, Any] = {
        "id": "C1",
        "type": "rule",
        "description": "SSHD brute force",
        "hosts": ["host-1"],
        "count": 3,
        "severity": "High",
        "narrative": "n",
        "recommendation": "r",
        "evidence": {"generic": {"srcips": ["192.0.2.1"]}},
        "flags": [],
    }
    cluster.update(overrides)
    return cluster


def test_score_clusters_returns_f8_from_flagged_findings() -> None:
    """F8 is the total number of fidelity flags across clusters."""
    clusters = [
        _cluster(flags=["T1100", "8443"]),
        _cluster(id="C2", flags=["CVE-2026-9999"]),
        _cluster(id="C3"),
    ]
    scores = eval_prompt._score_clusters(clusters, {})
    assert scores["F8"] == 3
    for name in ("F1", "F2", "F3", "F4", "F5", "F6", "F7"):
        assert name in scores


def _patch_main(
    monkeypatch: Any, tmp_path: Path, analyse_result: Any
) -> Path:
    """Monkeypatch config, ping and analyse(); return the fixtures dir."""
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "alert.json").write_text(
        json.dumps(
            {
                "_source": {
                    "agent": {"name": "host-1"},
                    "rule": {"id": "1", "description": "d"},
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        eval_prompt,
        "_load_config",
        lambda path: {
            "llm": {
                "base_url": "http://llm.invalid/v1",
                "api_key": "local",
                "model": "test-model",
            }
        },
    )
    monkeypatch.setattr(eval_prompt, "_ping_llm", lambda url: True)
    monkeypatch.setattr(eval_prompt.analyser, "analyse", lambda alerts, **kw: analyse_result)
    return fixtures


def test_success_row_has_f1_to_f8_error_none_and_clusters(
    monkeypatch: Any, tmp_path: Path, capsys: Any
) -> None:
    """A successful run row carries F1–F8, error None and a clusters list."""
    result = {
        "findings": [_cluster(flags=["T1100"])],
        "mitre_tags": [],
    }
    fixtures = _patch_main(monkeypatch, tmp_path, result)
    out_json = tmp_path / "eval.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "eval_prompt",
            "--runs",
            "1",
            "--fixtures",
            str(fixtures),
            "--json",
            str(out_json),
        ],
    )
    eval_prompt.main()
    rows = json.loads(out_json.read_text(encoding="utf-8"))
    assert len(rows) == 1
    row = rows[0]
    for name in ("F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8"):
        assert name in row
    assert row["error"] is None
    assert row["F8"] == 1
    assert len(row["clusters"]) == 1
    entry = row["clusters"][0]
    assert entry["id"] == "C1"
    assert entry["hosts"] == ["host-1"]
    assert entry["narrative"] == "n"
    assert entry["recommendation"] == "r"
    assert "srcip 192.0.2.1" in entry["evidence"]
    assert entry["flags"] == ["T1100"]
    printed = capsys.readouterr().out
    assert "F8" in printed.splitlines()[0]


def test_error_row_is_only_error_key(
    monkeypatch: Any, tmp_path: Path, capsys: Any
) -> None:
    """A failed run row stays exactly {'error': '...'} with no F keys."""

    def _boom(alerts: Any, **kw: Any) -> Any:
        raise RuntimeError("llm down")

    fixtures = _patch_main(monkeypatch, tmp_path, None)
    monkeypatch.setattr(eval_prompt.analyser, "analyse", _boom)
    out_json = tmp_path / "eval.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "eval_prompt",
            "--runs",
            "1",
            "--fixtures",
            str(fixtures),
            "--json",
            str(out_json),
        ],
    )
    eval_prompt.main()
    rows = json.loads(out_json.read_text(encoding="utf-8"))
    assert len(rows) == 1
    assert set(rows[0].keys()) == {"error"}
    assert "RuntimeError" in rows[0]["error"]
