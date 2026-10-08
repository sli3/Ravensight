"""
Tests for data-built alert clustering (Build 1b).

Fixtures use documented Wazuh alert shapes only — no live fetch, no network.
"""

import re
from typing import Any

import pytest

from ravensight import analyser
from ravensight.analyser import (
    MAX_PROMPT_CLUSTERS,
    cluster_key,
    cluster_label,
    extract_alert_clusters,
    severity_from_level,
)
from tests.conftest import _make_fake_stream


def _alert(
    description: str = "Test rule",
    level: Any = 3,
    rule_id: Any = "1002",
    agent: Any = "host-1",
    timestamp: Any = "2026-09-24T10:00:00.000Z",
    vuln: Any = None,
    groups: Any = None,
) -> dict[str, Any]:
    """Build one alert dict in the documented Wazuh shape."""
    source: dict[str, Any] = {
        "agent": {"name": agent} if agent is not None else {},
        "rule": {"id": rule_id, "description": description, "level": level},
        "@timestamp": timestamp,
    }
    if source["@timestamp"] is None:
        del source["@timestamp"]
    if agent is None:
        source["agent"] = None
    if vuln is not None:
        source["data"] = {"vulnerability": vuln}
    if groups is not None:
        source["rule"]["groups"] = groups
    return {"_source": source}


def _vuln_alert(
    cve: str,
    package: str,
    agent: str = "host-1",
    level: int = 10,
    description: str = "CVE-2026-1234 affects openssl",
) -> dict[str, Any]:
    """Build a vulnerability alert with the documented cve/package fields."""
    return _alert(
        description=description,
        level=level,
        rule_id="23503",
        agent=agent,
        vuln={"cve": cve, "package": {"name": package}},
        groups=["vulnerability-detector"],
    )


def test_same_host_package_different_cves_one_cluster() -> None:
    """Same host and package with different CVEs merge into one cluster."""
    alerts = [
        _vuln_alert("CVE-2026-1001", "openssl"),
        _vuln_alert("CVE-2026-1002", "openssl"),
    ]
    clusters = extract_alert_clusters(alerts)
    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster["type"] == "vulnerability"
    assert cluster["count"] == 2
    assert cluster["cves"] == ["CVE-2026-1001", "CVE-2026-1002"]
    assert cluster["package"] == "openssl"
    assert cluster["hosts"] == ["host-1"]


def test_same_host_two_packages_two_clusters() -> None:
    """Same host with two different packages yields two clusters."""
    alerts = [
        _vuln_alert("CVE-2026-1001", "openssl"),
        _vuln_alert("CVE-2026-2001", "curl"),
    ]
    clusters = extract_alert_clusters(alerts)
    assert len(clusters) == 2
    assert {c["package"] for c in clusters} == {"openssl", "curl"}


def test_package_parsed_from_description_when_absent() -> None:
    """Package name falls back to parsing the rule description."""
    alerts = [
        _alert(
            description="CVE-2026-4321 affects libxml2",
            level=10,
            rule_id="23503",
            vuln={"cve": "CVE-2026-4321"},  # no package sub-field
            groups=["vulnerability-detector"],
        )
    ]
    clusters = extract_alert_clusters(alerts)
    assert len(clusters) == 1
    assert clusters[0]["package"] == "libxml2"
    assert clusters[0]["cves"] == ["CVE-2026-4321"]


def test_rule_alerts_merge_across_hosts() -> None:
    """Non-vulnerability alerts group by description alone, merging hosts."""
    alerts = [
        _alert(description="SSHD brute force", level=10, agent="host-1"),
        _alert(description="SSHD brute force", level=12, agent="host-2"),
    ]
    clusters = extract_alert_clusters(alerts)
    assert len(clusters) == 1
    assert clusters[0]["type"] == "rule"
    assert clusters[0]["count"] == 2
    assert clusters[0]["hosts"] == ["host-1", "host-2"]
    assert clusters[0]["cves"] == []


def test_multi_cve_description_wording() -> None:
    """More than one CVE rewords the description; a single CVE keeps the original."""
    multi = [
        _vuln_alert("CVE-2026-1001", "openssl"),
        _vuln_alert("CVE-2026-1002", "openssl"),
    ]
    clusters = extract_alert_clusters(multi)
    assert clusters[0]["description"] == "2 vulnerabilities affect openssl"

    single = [_vuln_alert("CVE-2026-1001", "openssl")]
    clusters = extract_alert_clusters(single)
    assert clusters[0]["description"] == "CVE-2026-1234 affects openssl"


def test_null_agent_timestamp_data_do_not_crash() -> None:
    """Missing agent, @timestamp and data fields degrade gracefully."""
    alerts = [
        {"_source": {"rule": {"id": "1002", "description": "Broken alert"}}},
        _alert(description="Broken alert", agent=None, timestamp=None),
        {"_source": {"data": None, "rule": {"description": "Broken alert"}}},
    ]
    clusters = extract_alert_clusters(alerts)
    assert len(clusters) == 1
    assert clusters[0]["hosts"] == ["unknown"]
    assert clusters[0]["first_seen"] == ""
    assert clusters[0]["last_seen"] == ""
    assert clusters[0]["count"] == 3


@pytest.mark.parametrize(
    ("level", "expected"),
    [(6, "Low"), (7, "Medium"), (11, "Medium"), (12, "High"), (16, "High")],
)
def test_severity_boundaries(level: int, expected: str) -> None:
    """severity_from_level maps documented level bands correctly."""
    assert severity_from_level(level) == expected


def test_severity_zero_and_none_are_low() -> None:
    """Level 0 and unparseable/None levels coerce to Low."""
    assert severity_from_level(0) == "Low"
    assert severity_from_level(None) == "Low"
    assert severity_from_level("not-a-number") == "Low"


def test_ordering_severity_count_description_with_ids() -> None:
    """Clusters order by severity, then count descending, then description; ids follow."""
    alerts = [
        _alert(description="Zeta rule", level=3),          # Low, 1
        _alert(description="Beta rule", level=7),          # Medium, 2
        _alert(description="Alpha rule", level=7),         # Medium, 2
        _alert(description="Gamma rule", level=7),         # Medium, 1
        _alert(description="Delta rule", level=12),        # High, 1
    ]
    alerts.append(_alert(description="Beta rule", level=7, agent="host-2"))
    alerts.append(_alert(description="Alpha rule", level=7, agent="host-2"))
    clusters = extract_alert_clusters(alerts)
    assert [c["id"] for c in clusters] == ["C1", "C2", "C3", "C4", "C5"]
    assert [c["description"] for c in clusters] == [
        "Delta rule",
        "Alpha rule",
        "Beta rule",
        "Gamma rule",
        "Zeta rule",
    ]


LLM_CONFIG = {
    "base_url": "http://llm.invalid/v1",
    "api_key": "local",
    "model": "test-model",
    "max_tokens": 512,
    "temperature": 0.0,
}


def test_prompt_caps_clusters_and_reports_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """45 clusters produce 40 prompt lines plus an omitted note; findings keep all 45."""
    sink: dict[str, Any] = {}

    class _Chat:
        def __init__(self) -> None:
            self.completions = self

        def create(self, **kwargs: Any) -> Any:
            sink["messages"] = kwargs.get("messages", [])
            return _make_fake_stream("")

    class _Client:
        def __init__(self) -> None:
            self.chat = _Chat()

    monkeypatch.setattr(analyser, "OpenAI", lambda **kw: _Client())

    alerts = [
        _alert(description=f"Rule number {i:02d}", level=3 + (i % 14))
        for i in range(45)
    ]
    result = analyser.analyse(
        alerts,
        {},
        LLM_CONFIG,
        lookback_hours=24,
    )

    prompt_text = sink["messages"][0]["content"]
    cluster_lines = re.findall(r"^\[C\d+\] ", prompt_text, flags=re.MULTILINE)
    assert len(cluster_lines) == MAX_PROMPT_CLUSTERS
    assert "(+5 lower-severity clusters omitted" in prompt_text

    assert len(result["findings"]) == 45
    assert all(isinstance(f, dict) for f in result["findings"])
    assert result["recommendations"] == []


def test_cluster_key_uses_package_not_description_or_id() -> None:
    """Vuln keys use (host, package) even when the description was rewritten."""
    cluster = {
        "id": "C1",
        "type": "vulnerability",
        "description": "2 vulnerabilities affect openssl",
        "hosts": ["host-1"],
        "package": "openssl",
        "count": 2,
        "severity": "Medium",
    }
    assert cluster_key(cluster) == "vuln|host-1|openssl"


def test_cluster_key_vuln_without_package_uses_description() -> None:
    """Vuln clusters with no package fall back to (host, description)."""
    cluster = {
        "id": "C2",
        "type": "vulnerability",
        "description": "Multiple CVEs detected",
        "hosts": ["host-3"],
        "package": None,
        "count": 1,
        "severity": "High",
    }
    assert cluster_key(cluster) == "vuln|host-3|Multiple CVEs detected"


def test_cluster_key_rule_uses_description_only() -> None:
    """Rule keys ignore hosts and use the description alone."""
    cluster = {
        "id": "C3",
        "type": "rule",
        "description": "SSHD brute force",
        "hosts": ["host-1", "host-2"],
        "package": None,
        "count": 7,
        "severity": "Medium",
    }
    assert cluster_key(cluster) == "rule|SSHD brute force"


def test_cluster_label_vuln_and_rule_forms() -> None:
    """Labels render 'Vulnerabilities in p (h)' for vuln keys, description for rule keys."""
    assert cluster_label("vuln|host-1|openssl") == "Vulnerabilities in openssl (host-1)"
    assert cluster_label("rule|SSHD brute force") == "SSHD brute force"


def test_cluster_label_survives_pipes_in_description() -> None:
    """Descriptions containing '|' survive the maxsplit-based label parse."""
    assert cluster_label("rule|user | sudo | root") == "user | sudo | root"
    assert cluster_label("vuln|h|pkg | with | pipes") == "Vulnerabilities in pkg | with | pipes (h)"


def test_rule_id_int_str_and_none() -> None:
    """Int and str rule ids become strings; None is skipped entirely."""
    alerts = [
        _alert(description="A", rule_id=5715),
        _alert(description="A", rule_id="5716"),
        _alert(description="A", rule_id=None),
    ]
    clusters = extract_alert_clusters(alerts)
    assert clusters[0]["rule_ids"] == ["5715", "5716"]


def test_null_rule_description_clusters_sort_without_typeerror() -> None:
    """Explicit null rule descriptions coalesce to 'Unknown' and sort cleanly."""
    alerts = [
        {
            "_source": {
                "agent": {"name": "host-1"},
                "rule": {"id": "23503", "description": None, "level": 10},
                "data": {
                    "vulnerability": {
                        "cve": "CVE-2026-1001",
                        "package": {"name": "openssl"},
                    }
                },
            }
        },
        {
            "_source": {
                "agent": {"name": "host-1"},
                "rule": {"id": "23503", "description": None, "level": 10},
                "data": {
                    "vulnerability": {
                        "cve": "CVE-2026-1002",
                        "package": {"name": "curl"},
                    }
                },
            }
        },
    ]
    clusters = extract_alert_clusters(alerts)
    assert len(clusters) == 2
    assert [c["description"] for c in clusters] == ["Unknown", "Unknown"]
    assert {c["package"] for c in clusters} == {"openssl", "curl"}


def test_cve_primary_field_and_regex_fallback() -> None:
    """data.vulnerability.cve wins; the description regex is the fallback."""
    primary = [
        _alert(
            description="CVE-2026-9999 affects openssl but field wins",
            level=10,
            vuln={"cve": "CVE-2026-7777", "package": {"name": "openssl"}},
            groups=["vulnerability-detector"],
        )
    ]
    clusters = extract_alert_clusters(primary)
    assert clusters[0]["cves"] == ["CVE-2026-7777"]

    fallback = [
        _alert(
            description="Multiple CVEs CVE-2026-5555 and CVE-2026-5556 detected",
            level=10,
            vuln={},  # empty dict still marks it a vulnerability alert
            groups=["vulnerability-detector"],
        )
    ]
    clusters = extract_alert_clusters(fallback)
    assert clusters[0]["cves"] == ["CVE-2026-5555", "CVE-2026-5556"]
    # no package resolvable -> keyed on (agent, description), description kept as-is
    assert clusters[0]["package"] is None
    assert clusters[0]["description"] == (
        "Multiple CVEs CVE-2026-5555 and CVE-2026-5556 detected"
    )
