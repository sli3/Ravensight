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


# --- negation-aware scoring (Build 2a) ---


def test_unnegated_count_basic_cases() -> None:
    """_unnegated_count respects negators, clause boundaries and 'rather than'."""
    assert eval_prompt._unnegated_count("no evidence of tampering", "tamper") == 0
    assert eval_prompt._unnegated_count("files were not altered", "alter") == 0
    assert eval_prompt._unnegated_count("this is not a scan", "scan") == 0
    assert (
        eval_prompt._unnegated_count(
            "completed without any signs of compromise", "compromis"
        )
        == 0
    )
    assert eval_prompt._unnegated_count("didn't fail", "fail") == 0
    assert eval_prompt._unnegated_count("tampering with files occurred", "tamper") == 1
    assert (
        eval_prompt._unnegated_count("No change. The file was altered.", "alter") == 1
    )
    assert (
        eval_prompt._unnegated_count(
            "it was not a scan but rather a normal connection", "scan"
        )
        == 0
    )


def test_score_clusters_negation_heavy_cluster_scores_zero() -> None:
    """Negating every failure-mode term yields zero for F1/F2/F4/F5/F7."""
    cluster = {
        "id": "C1",
        "narrative": (
            "no pfsense, not a scan, no external interface, not altered, "
            "no tamper, never restore, neither malicious nor compromise, "
            "without interrupt, not incomplete, cannot fail, not broken, "
            "no forensic isolation, no reimage, no incident response"
        ),
        "recommendation": "",
        "evidence": {
            "firewall": {},
            "syscheck": {},
            "dpkg": {},
        },
        "flags": [],
    }
    scores = eval_prompt._score_clusters([cluster], {})
    for name in ("F1", "F2", "F4", "F5", "F7"):
        assert scores[name] == 0, name


def test_score_clusters_positive_control_cluster_scores_one() -> None:
    """Mentioning every failure-mode term without negation yields one each."""
    cluster = {
        "id": "C1",
        "narrative": (
            "pfsense scan external interface alter tamper restore malicious "
            "compromise interrupt incomplete fail broken forensic isolat "
            "reimage incident response"
        ),
        "recommendation": "",
        "evidence": {
            "firewall": {},
            "syscheck": {},
            "dpkg": {},
        },
        "flags": [],
    }
    scores = eval_prompt._score_clusters([cluster], {})
    for name in ("F1", "F2", "F4", "F5", "F7"):
        assert scores[name] == 1, name


def test_score_clusters_f3_accepts_ports_plural() -> None:
    """F3 regex matches 'ports 443' as well as 'port 443'."""
    cluster = {
        "id": "C1",
        "narrative": "traffic on ports 443 only",
        "recommendation": "",
        "evidence": {"firewall": {}},
        "flags": [],
    }
    scores = eval_prompt._score_clusters([cluster], {})
    assert scores["F3"] == 1


def test_unnegated_count_review_fix_cases() -> None:
    """Curly apostrophes, 'rather than', brackets and none/nothing negate."""
    assert eval_prompt._unnegated_count("it didn’t fail", "fail") == 0
    assert eval_prompt._unnegated_count("blocks rather than scans", "scan") == 0
    assert eval_prompt._unnegated_count("logged instead of tampering", "tamper") == 0
    assert eval_prompt._unnegated_count("(not altered)", "alter") == 0
    assert eval_prompt._unnegated_count("nothing was altered", "alter") == 0
    assert eval_prompt._unnegated_count("none were tampered with", "tamper") == 0
    assert eval_prompt._unnegated_count("rather a scan than a block", "scan") == 1


def test_unnegated_count_rather_than_with_words_between() -> None:
    """'rather than an inbound scan' is negated even with words in between."""
    text = "consistent with routine outbound filtering rather than an inbound scan"
    assert eval_prompt._unnegated_count(text, "scan") == 0
    text = "normal filtering instead of an external scan"
    assert eval_prompt._unnegated_count(text, "scan") == 0
    assert eval_prompt._unnegated_count("rather a scan than a block", "scan") == 1
