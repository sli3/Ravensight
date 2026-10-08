"""
Tests for cluster-aware LLM response parsing and the data-built summary.

Uses a fake LLM (monkeypatched analyser.OpenAI) — no network.
"""

import logging
from typing import Any

import pytest

from ravensight import analyser
from ravensight.analyser import _build_prompt, _parse_analysis, extract_alert_clusters
from tests.conftest import _make_fake_stream


def _alert(description: str, level: int, agent: str = "host-1") -> dict[str, Any]:
    """Build one alert dict in the documented Wazuh shape."""
    return {
        "_source": {
            "agent": {"name": agent},
            "rule": {"id": "1002", "description": description, "level": level},
            "@timestamp": "2026-09-24T10:00:00.000Z",
        }
    }


def _two_clusters() -> list[dict[str, Any]]:
    return extract_alert_clusters(
        [
            _alert("SSHD brute force", 12),
            _alert("Suspicious file", 7),
        ]
    )


def test_attaches_narrative_and_recommendation_by_id() -> None:
    """A plain [C1] prefix attaches narrative and recommendation to that cluster."""
    clusters = _two_clusters()
    text = (
        "<findings>\n"
        "- [C1] Brute force from external hosts\n"
        "- [C2] File dropped in /tmp\n"
        "</findings>\n"
        "<recommendations>\n"
        "- [C1] Block the source IPs\n"
        "- [C2] Investigate the file\n"
        "</recommendations>"
    )
    result = _parse_analysis(text, clusters=clusters)
    by_id = {f["id"]: f for f in result["findings"]}
    assert by_id["C1"]["narrative"] == "Brute force from external hosts"
    assert by_id["C2"]["narrative"] == "File dropped in /tmp"
    assert by_id["C1"]["recommendation"] == "Block the source IPs"
    assert by_id["C2"]["recommendation"] == "Investigate the file"
    assert result["recommendations"] == [
        "Block the source IPs",
        "Investigate the file",
    ]


@pytest.mark.parametrize(
    "prefix",
    ["C1:", "**[C1]**:", "**[C1]** -", "[C1] -"],
)
def test_tolerant_id_prefix_variants(prefix: str) -> None:
    """Bold markers, brackets and separators are all tolerated."""
    clusters = _two_clusters()
    text = f"<findings>\n- {prefix} narrative text\n</findings>"
    result = _parse_analysis(text, clusters=clusters)
    assert result["findings"][0]["narrative"] == "narrative text"


def test_stray_finding_n_stripped_after_id() -> None:
    """A stray 'Finding 2:' after the id is stripped, not embedded in the text."""
    clusters = _two_clusters()
    text = "<findings>\n- [C1] Finding 2: real narrative here\n</findings>"
    result = _parse_analysis(text, clusters=clusters)
    assert result["findings"][0]["narrative"] == "real narrative here"


def test_repeated_id_appends_with_space() -> None:
    """Two lines for the same id append the narrative with a space."""
    clusters = _two_clusters()
    text = (
        "<findings>\n"
        "- [C1] first part\n"
        "- [C1] second part\n"
        "</findings>"
    )
    result = _parse_analysis(text, clusters=clusters)
    assert result["findings"][0]["narrative"] == "first part second part"


def test_no_id_and_unknown_id_become_unattached(caplog: Any) -> None:
    """Lines with no id or an unknown id become unattached dicts and are logged."""
    clusters = _two_clusters()
    text = (
        "<findings>\n"
        "- Some free-floating observation\n"
        "- [C99] Cluster id the data never had\n"
        "</findings>\n"
        "<recommendations>\n"
        "- Another loose recommendation\n"
        "</recommendations>"
    )
    with caplog.at_level(logging.WARNING, logger="ravensight.analyser"):
        result = _parse_analysis(text, clusters=clusters)

    unattached = [f for f in result["findings"] if f["type"] == "unattached"]
    assert len(unattached) == 3  # nothing dropped
    assert unattached[0]["description"] == "Some free-floating observation"
    assert unattached[1]["description"] == "[C99] Cluster id the data never had"
    assert unattached[2]["recommendation"] == "Another loose recommendation"
    assert all(f["count"] == 0 and f["hosts"] == [] for f in unattached)
    warnings = [
        r for r in caplog.records
        if r.levelname == "WARNING" and "Unattached" in r.message
    ]
    assert len(warnings) == 3


def test_legacy_parse_without_clusters_unchanged() -> None:
    """Without clusters the parser keeps the legacy string behaviour."""
    text = (
        "<findings>\n- Legacy finding A\n</findings>\n"
        "<recommendations>\n- Legacy rec A\n</recommendations>"
    )
    result = _parse_analysis(text)
    assert result["findings"] == ["Legacy finding A"]
    assert result["recommendations"] == ["Legacy rec A"]
    assert result["summary"] == "Legacy finding A"


def test_prompt_template_has_no_finding_one() -> None:
    """The prompt template must not contain the legacy 'Finding 1' string."""
    prompt = _build_prompt([_alert("A rule", 3)], {}, clusters=_two_clusters())
    assert "Finding 1" not in prompt


def test_parse_analysis_ignores_stray_mitre_tags_block() -> None:
    """A stray <mitre_tags> block is silently ignored — no tags, no findings."""
    clusters = _two_clusters()
    text = (
        "<findings>\n"
        "- [C1] Brute force from external hosts\n"
        "</findings>\n"
        "<mitre_tags>\n"
        "- Defense Evasion: foo\n"
        "</mitre_tags>"
    )
    result = _parse_analysis(text, clusters=clusters)
    assert result["mitre_tags"] == []
    assert len(result["findings"]) == 2
    assert all(f["type"] != "unattached" for f in result["findings"])
    assert result["findings"][0]["narrative"] == "Brute force from external hosts"


LLM_KNOWN_STRING = "LLM SUPPLIED NARRATIVE TEXT MUST NOT LEAK INTO SUMMARY"
LLM_CONFIG = {
    "base_url": "http://llm.invalid/v1",
    "api_key": "local",
    "model": "test-model",
    "max_tokens": 512,
    "temperature": 0.0,
}


def test_summary_is_data_built(monkeypatch: pytest.MonkeyPatch) -> None:
    """Summary comes from alert data only — never from LLM text."""
    class _Chat:
        def __init__(self) -> None:
            self.completions = self

        def create(self, **kwargs: Any) -> Any:
            return _make_fake_stream(
                f"<findings>\n- [C1] {LLM_KNOWN_STRING}\n</findings>"
            )

    class _Client:
        def __init__(self) -> None:
            self.chat = _Chat()

    monkeypatch.setattr(analyser, "OpenAI", lambda **kw: _Client())

    alerts = [
        _alert("SSHD brute force", 12),
        _alert("SSHD brute force", 12, agent="host-2"),
        _alert("Suspicious file", 7),
    ]
    result = analyser.analyse(alerts, {}, LLM_CONFIG)

    assert result["summary"].startswith("3 alerts in 2 clusters")
    assert "2 hosts" in result["summary"]
    assert "1 High, 1 Medium, 0 Low" in result["summary"]
    assert LLM_KNOWN_STRING not in result["summary"]
    assert "Finding 1" not in result["summary"]
    # narrative attachment still works through analyse()
    assert result["findings"][0]["narrative"] == LLM_KNOWN_STRING
