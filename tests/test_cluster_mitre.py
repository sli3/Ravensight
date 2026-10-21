"""
Tests for MITRE technique ids carried onto clusters from rule.mitre.id.

The ids are data-built: they must not change the prompt, the fidelity flags,
the cluster key or the JSON report. No network, no LLM, no ChromaDB.
"""

from typing import Any

import pytest

from ravensight.analyser import (
    _build_prompt,
    _fidelity_flags,
    _parse_analysis,
    cluster_key,
    extract_alert_clusters,
)
from ravensight.reporter import _json_finding


def _alert(
    description: str = "SSHD brute force",
    mitre: Any = None,
    vulnerability: bool = False,
    include_mitre: bool = False,
) -> dict[str, Any]:
    """Build one synthetic alert; rule.mitre is added only when asked for."""
    rule: dict[str, Any] = {"id": "5710", "description": description, "level": 10}
    if include_mitre or mitre is not None:
        rule["mitre"] = mitre
    source: dict[str, Any] = {
        "agent": {"name": "host-1"},
        "rule": rule,
        "@timestamp": "2026-09-24T10:00:00.000Z",
    }
    if vulnerability:
        source["data"] = {
            "vulnerability": {"cve": "CVE-2026-1234", "package": {"name": "openssl"}}
        }
    return {"_source": source}


def _ids(mitre: Any) -> list[str]:
    """Return the mitre_ids of the single cluster built from one alert."""
    clusters = extract_alert_clusters([_alert(mitre=mitre, include_mitre=True)])
    assert len(clusters) == 1
    return clusters[0]["mitre_ids"]


def test_ids_sorted_deduplicated_across_alerts() -> None:
    """Ids from several alerts in one cluster are merged, sorted and unique."""
    clusters = extract_alert_clusters(
        [
            _alert(mitre={"id": ["T1110", "T1562.001"]}),
            _alert(mitre={"id": ["T1078", "T1110"]}),
        ]
    )
    assert clusters[0]["mitre_ids"] == ["T1078", "T1110", "T1562.001"]


def test_lower_case_is_uppercased() -> None:
    """Lower-case ids are uppercased before validation."""
    assert _ids({"id": [" t1078 ", "t1562.001"]}) == ["T1078", "T1562.001"]


def test_single_string_id() -> None:
    """A single string id is treated as a one-item list."""
    assert _ids({"id": "T1078"}) == ["T1078"]


@pytest.mark.parametrize(
    "mitre",
    [
        None,
        "T1078",
        ["T1078"],
        123,
        {},
        {"id": None},
        {"id": 123},
        {"id": ""},
        {"id": ["T10"]},
        {"id": ["foo"]},
        {"id": [["T1078"]]},
        {"id": [None]},
        {"id": [123, "", "T10", "foo", ["T1078"], None]},
        {"id": ["T1078.1"]},
        {"id": ["T١٠٧٨"]},
    ],
)
def test_bad_values_add_nothing(mitre: Any) -> None:
    """Missing or malformed rule.mitre values add nothing and never raise."""
    assert _ids(mitre) == []


def test_no_rule_mitre_key() -> None:
    """An alert without rule.mitre yields an empty list."""
    clusters = extract_alert_clusters([_alert()])
    assert clusters[0]["mitre_ids"] == []


def test_vulnerability_and_rule_clusters_carry_field() -> None:
    """Both cluster types carry mitre_ids; empty by default."""
    clusters = extract_alert_clusters(
        [
            _alert(mitre={"id": ["T1190"]}, vulnerability=True, description="vuln"),
            _alert(description="plain rule"),
        ]
    )
    by_type = {c["type"]: c for c in clusters}
    assert by_type["vulnerability"]["mitre_ids"] == ["T1190"]
    assert by_type["rule"]["mitre_ids"] == []


def test_parse_analysis_findings_keep_mitre_ids() -> None:
    """Findings built from clusters carry mitre_ids unchanged."""
    clusters = extract_alert_clusters([_alert(mitre={"id": ["T1110", "T1078"]})])
    text = (
        "<findings>\n- [C1] Brute force\n</findings>\n"
        "<recommendations>\n- [C1] Block IPs\n</recommendations>"
    )
    result = _parse_analysis(text, clusters=clusters)
    assert result["findings"][0]["mitre_ids"] == ["T1078", "T1110"]


def test_prompt_unchanged_by_mitre() -> None:
    """The prompt is identical with and without rule.mitre."""
    with_mitre = [_alert(mitre={"id": ["T1110"]})]
    without = [_alert()]
    assert _build_prompt(with_mitre, {}) == _build_prompt(without, {})


def test_fidelity_flags_unchanged_by_mitre() -> None:
    """Fidelity flags ignore mitre_ids; a narrated technique id stays flagged."""
    cluster = extract_alert_clusters([_alert()])[0]
    cluster["narrative"] = "Matches technique T1110 here."
    bare = {k: v for k, v in cluster.items() if k != "mitre_ids"}
    with_ids = dict(cluster, mitre_ids=["T1110"])
    assert _fidelity_flags(with_ids, set()) == _fidelity_flags(bare, set())
    assert _fidelity_flags(with_ids, set()) == ["T1110"]


def test_cluster_key_unchanged_by_mitre() -> None:
    """cluster_key is the same with and without mitre ids."""
    with_mitre = extract_alert_clusters([_alert(mitre={"id": ["T1110"]})])[0]
    without = extract_alert_clusters([_alert()])[0]
    assert cluster_key(with_mitre) == cluster_key(without)
    vuln_with = extract_alert_clusters(
        [_alert(mitre={"id": ["T1190"]}, vulnerability=True)]
    )[0]
    vuln_without = extract_alert_clusters([_alert(vulnerability=True)])[0]
    assert cluster_key(vuln_with) == cluster_key(vuln_without)


def test_json_finding_omits_mitre_ids() -> None:
    """The reporter's JSON finding does not expose mitre_ids."""
    cluster = extract_alert_clusters([_alert(mitre={"id": ["T1110"]})])[0]
    assert cluster["mitre_ids"] == ["T1110"]
    mapped = _json_finding(cluster)
    assert mapped is not None
    assert "mitre_ids" not in mapped
