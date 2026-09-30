"""
Tests for per-cluster mechanical evidence extraction (Build 1c).

Fixtures are redacted real alerts loaded from tests/fixtures/; synthetic
alerts use the same _alert factory pattern as test_clusters.py.
No network, no LLM, no ChromaDB.
"""

import json
from pathlib import Path
from typing import Any

from ravensight.analyser import cluster_key, extract_alert_clusters
from ravensight.baseline import Manager
from ravensight.evidence import (
    MAX_EVIDENCE_VALUE_CHARS,
    MAX_EVIDENCE_VALUES,
    accumulate,
    render_evidence,
)


def _fixture(name: str) -> dict[str, Any]:
    """Load one redacted real-alert fixture by file name."""
    return json.loads((Path(__file__).parent / "fixtures" / name).read_text())


def _alert(
    description: str = "Test rule",
    level: Any = 3,
    rule_id: Any = "1002",
    agent: Any = "host-1",
    timestamp: Any = "2026-09-24T10:00:00.000Z",
    groups: Any = None,
    data: Any = None,
    syscheck: Any = None,
    full_log: Any = None,
    previous_log: Any = None,
    previous_output: Any = None,
    predecoder: Any = None,
) -> dict[str, Any]:
    """Build one synthetic alert dict in the documented Wazuh shape."""
    source: dict[str, Any] = {
        "agent": {"name": agent},
        "rule": {"id": rule_id, "description": description, "level": level},
        "@timestamp": timestamp,
    }
    if groups is not None:
        source["rule"]["groups"] = groups
    if data is not None:
        source["data"] = data
    if syscheck is not None:
        source["syscheck"] = syscheck
    if full_log is not None:
        source["full_log"] = full_log
    if previous_log is not None:
        source["previous_log"] = previous_log
    if previous_output is not None:
        source["previous_output"] = previous_output
    if predecoder is not None:
        source["predecoder"] = predecoder
    return {"_source": source}


def _syscheck_alert(
    path: str = "/etc/resolv.conf",
    event: str = "modified",
    changed_attributes: Any = None,
    description: str = "Integrity checksum changed.",
) -> dict[str, Any]:
    """Build a synthetic syscheck alert."""
    syscheck: dict[str, Any] = {"path": path, "event": event}
    if changed_attributes is not None:
        syscheck["changed_attributes"] = changed_attributes
    return _alert(
        description=description,
        level=7,
        rule_id="550",
        groups=["ossec", "syscheck"],
        syscheck=syscheck,
    )


def _dpkg_alert(
    status: Any = "status installed",
    package: Any = "libc-bin",
    version: Any = "2.39-0ubuntu8.9",
    description: str = "New dpkg (Debian Package) installed.",
) -> dict[str, Any]:
    """Build a synthetic dpkg alert."""
    data: dict[str, Any] = {}
    if package is not None:
        data["package"] = package
    if version is not None:
        data["version"] = version
    if status is not None:
        data["dpkg_status"] = status
    return _alert(
        description=description,
        level=7,
        rule_id="2902",
        groups=["syslog", "dpkg"],
        data=data,
    )


def _netstat_alert(
    full_log: Any,
    previous_log: Any,
    description: str = "Listened ports status (netstat) changed (new port opened or closed).",
) -> dict[str, Any]:
    """Build a synthetic netstat (rule 533) alert."""
    return _alert(
        description=description,
        level=7,
        rule_id="533",
        groups=["ossec"],
        full_log=full_log,
        previous_log=previous_log,
    )


def _only_cluster(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract exactly one cluster from the given alerts."""
    clusters = extract_alert_clusters(alerts)
    assert len(clusters) == 1
    return clusters[0]


# --- syscheck ---


def test_syscheck_fixture_evidence() -> None:
    """Syscheck fixture yields paths, event, changed attributes, content verdict."""
    cluster = _only_cluster([_fixture("syscheck-550.json")])
    assert cluster["evidence"] == {
        "syscheck": {
            "paths": ["/etc/resolv.conf"],
            "events": ["modified"],
            "changed": ["inode", "mtime"],
            "content": "unchanged",
        }
    }


def test_syscheck_fixture_rendering() -> None:
    """Syscheck fixture evidence renders as the documented example line."""
    cluster = _only_cluster([_fixture("syscheck-550.json")])
    assert render_evidence(cluster["evidence"]) == (
        "paths /etc/resolv.conf; event modified; changed inode, mtime; "
        "content unchanged"
    )


def test_syscheck_content_verdict_changed_on_checksum_attributes() -> None:
    """md5 or size in changed_attributes flips the verdict to 'changed'."""
    for attribute in ("md5", "size"):
        cluster = _only_cluster(
            [_syscheck_alert(changed_attributes=["inode", attribute])]
        )
        assert cluster["evidence"]["syscheck"]["content"] == "changed"


def test_syscheck_content_verdict_omitted_when_no_attributes() -> None:
    """An empty changed_attributes list never claims 'unchanged'."""
    cluster = _only_cluster([_syscheck_alert(changed_attributes=[])])
    syscheck = cluster["evidence"]["syscheck"]
    assert "changed" not in syscheck
    assert "content" not in syscheck


def test_syscheck_block_missing_yields_no_evidence_key() -> None:
    """A syscheck-group alert without a syscheck block carries no evidence."""
    alert = _alert(
        description="Integrity checksum changed.",
        level=7,
        rule_id="550",
        groups=["ossec", "syscheck"],
    )
    cluster = _only_cluster([alert])
    assert "evidence" not in cluster


# --- dpkg ---


def test_dpkg_fixtures_evidence() -> None:
    """Both dpkg fixtures produce one stripped-status entry in their clusters."""
    clusters = extract_alert_clusters(
        [_fixture("dpkg-installed-2902.json"), _fixture("dpkg-half-configured-2904.json")]
    )
    assert len(clusters) == 2
    entries = sorted(
        c["evidence"]["dpkg"]["packages"][0] for c in clusters
    )
    assert entries == [
        "libc-bin 2.39-0ubuntu8.9: half-configured",
        "libc-bin 2.39-0ubuntu8.9: installed",
    ]


def test_dpkg_both_statuses_in_one_cluster_sorted() -> None:
    """A synthetic cluster with both statuses renders them sorted."""
    cluster = _only_cluster(
        [
            _dpkg_alert(status="status installed"),
            _dpkg_alert(status="status half-configured"),
        ]
    )
    assert cluster["evidence"]["dpkg"]["packages"] == [
        "libc-bin 2.39-0ubuntu8.9: half-configured, installed"
    ]


def test_dpkg_fixture_rendering() -> None:
    """Dpkg fixture evidence renders as the documented example line."""
    cluster = _only_cluster([_fixture("dpkg-installed-2902.json")])
    assert render_evidence(cluster["evidence"]) == (
        "libc-bin 2.39-0ubuntu8.9: installed"
    )


def test_dpkg_missing_fields_degrade_without_raising() -> None:
    """Missing package/version/status fields degrade gracefully."""
    clusters = extract_alert_clusters(
        [
            _dpkg_alert(package=None),
            _dpkg_alert(version=None),
            _dpkg_alert(status=None),
        ]
    )
    assert len(clusters) == 1
    # only the status-less alert carried package+version
    assert clusters[0]["evidence"]["dpkg"]["packages"] == [
        "libc-bin 2.39-0ubuntu8.9"
    ]


# --- netstat ---


def test_netstat_fixture_evidence() -> None:
    """Netstat fixture yields exactly one opened port with its process."""
    cluster = _only_cluster([_fixture("netstat-533.json")])
    assert cluster["evidence"] == {
        "netstat": {"added": ["tcp 127.0.0.1:40002 (code-server)"]}
    }


def test_netstat_fixture_rendering() -> None:
    """Netstat fixture evidence renders as the documented example line."""
    cluster = _only_cluster([_fixture("netstat-533.json")])
    assert render_evidence(cluster["evidence"]) == (
        "opened tcp 127.0.0.1:40002 (code-server)"
    )


def test_netstat_same_key_different_pid_is_no_change() -> None:
    """Same protocol + address with a different PID yields no evidence."""
    previous = "tcp 0.0.0.0:22 0.0.0.0:* 1/systemd"
    current = "tcp 0.0.0.0:22 0.0.0.0:* 99/systemd"
    cluster = _only_cluster([_netstat_alert(current, previous)])
    assert "evidence" not in cluster


def test_netstat_removed_port_rendered_closed() -> None:
    """A port present only in the previous log renders as closed."""
    previous = "tcp 0.0.0.0:22 0.0.0.0:* 1/systemd\ntcp 0.0.0.0:443 0.0.0.0:* 2/nginx"
    current = "tcp 0.0.0.0:22 0.0.0.0:* 1/systemd"
    cluster = _only_cluster([_netstat_alert(current, previous)])
    assert cluster["evidence"]["netstat"] == {
        "removed": ["tcp 0.0.0.0:443 (nginx)"]
    }
    assert render_evidence(cluster["evidence"]) == "closed tcp 0.0.0.0:443 (nginx)"


def test_netstat_missing_previous_log_yields_no_evidence() -> None:
    """No previous_log means no diff baseline and no evidence key."""
    cluster = _only_cluster(
        [_netstat_alert("tcp 0.0.0.0:22 0.0.0.0:* 1/systemd", None)]
    )
    assert "evidence" not in cluster


def test_netstat_added_capped_at_three() -> None:
    """More than three new ports are capped at MAX_EVIDENCE_NETSTAT_VALUES."""
    previous = "tcp 0.0.0.0:22 0.0.0.0:* 1/systemd"
    current_lines = [previous] + [
        f"tcp 127.0.0.1:{50000 + i} 0.0.0.0:* {100 + i}/svc{i}" for i in range(5)
    ]
    cluster = _only_cluster([_netstat_alert("\n".join(current_lines), previous)])
    added = cluster["evidence"]["netstat"]["added"]
    assert len(added) == 3


# --- docker ---


def test_docker_kill_fixture_evidence() -> None:
    """Docker kill fixture yields container, action, signal, compose and image."""
    cluster = _only_cluster([_fixture("docker-kill-87924.json")])
    assert cluster["evidence"] == {
        "docker": {
            "containers": ["memsvc"],
            "actions": ["kill"],
            "signals": ["15"],
            "compose": ["memsvc/memsvc"],
            "images": ["registry.example.net/memsvc:latest"],
        }
    }


def test_docker_kill_fixture_rendering() -> None:
    """Docker kill fixture evidence renders as the documented example line."""
    cluster = _only_cluster([_fixture("docker-kill-87924.json")])
    assert render_evidence(cluster["evidence"]) == (
        "container memsvc; action kill; signal 15; compose memsvc/memsvc; "
        "image registry.example.net/memsvc:latest"
    )


def test_docker_start_fixture_has_no_signal() -> None:
    """Docker start fixture omits the signals list entirely."""
    cluster = _only_cluster([_fixture("docker-start-87903.json")])
    docker = cluster["evidence"]["docker"]
    assert docker["actions"] == ["start"]
    assert "signals" not in docker


# --- vulnerability ---


def test_vulnerability_fixture_evidence() -> None:
    """Vuln fixture yields status counts and version; severity/score omitted."""
    cluster = _only_cluster([_fixture("vuln-solved-23502.json")])
    vuln = cluster["evidence"]["vulnerability"]
    assert vuln["statuses"] == {"Solved": 1}
    assert vuln["versions"] == ["6.8.0-139.139"]
    assert "severities" not in vuln
    assert "score_bases" not in vuln


def test_vulnerability_fixture_rendering() -> None:
    """Vuln fixture evidence renders as the documented example line."""
    cluster = _only_cluster([_fixture("vuln-solved-23502.json")])
    assert render_evidence(cluster["evidence"]) == (
        "status Solved×1; version 6.8.0-139.139"
    )


# --- firewall ---


def test_firewall_multiple_fixture_evidence() -> None:
    """Multiple-block firewall fixture yields capped sources and total count."""
    cluster = _only_cluster([_fixture("firewall-multiple-87702.json")])
    assert cluster["evidence"] == {
        "firewall": {
            "actions": ["block"],
            "directions": ["in"],
            "interfaces": ["vtnet1"],
            "ipversions": ["ipv6"],
            "protocols": ["tcp"],
            "sources": [
                "fd00:0:0:1::a",
                "fd00:0:0:1::b",
                "fd00:0:0:1::c",
            ],
            "destinations": [
                "2001:db8:100::2",
                "2001:db8:101::2",
                "2001:db8:200::5f",
                "2001:db8:201::84",
            ],
            "dstports": ["443"],
            "sources_total": 3,
        }
    }
    rendered = render_evidence(cluster["evidence"])
    src_part = next(p for p in rendered.split("; ") if p.startswith("src "))
    assert (
        "fd00:0:0:1::a, fd00:0:0:1::b, fd00:0:0:1::c (3 distinct)"
        in src_part
    )
    assert "443" not in src_part


def test_firewall_multiple_fixture_rendering() -> None:
    """Multiple-block firewall fixture renders as the documented example line."""
    cluster = _only_cluster([_fixture("firewall-multiple-87702.json")])
    assert render_evidence(cluster["evidence"]) == (
        "action block; dir in; iface vtnet1; ipv6; proto tcp; "
        "src fd00:0:0:1::a, fd00:0:0:1::b, fd00:0:0:1::c (3 distinct); "
        "dst 2001:db8:100::2, 2001:db8:101::2, 2001:db8:200::5f, "
        "2001:db8:201::84; dport 443"
    )


def test_firewall_drop_fixture_evidence() -> None:
    """Single-drop firewall fixture yields one source and no distinct suffix."""
    cluster = _only_cluster([_fixture("firewall-drop-87701.json")])
    assert cluster["evidence"] == {
        "firewall": {
            "actions": ["block"],
            "directions": ["in"],
            "interfaces": ["vtnet1"],
            "ipversions": ["ipv6"],
            "protocols": ["tcp"],
            "sources": ["fd00:0:0:1::c"],
            "destinations": ["2001:db8:202::5e"],
            "dstports": ["80"],
            "sources_total": 1,
        }
    }
    rendered = render_evidence(cluster["evidence"])
    assert rendered == (
        "action block; dir in; iface vtnet1; ipv6; proto tcp; "
        "src fd00:0:0:1::c; dst 2001:db8:202::5e; dport 80"
    )
    assert "(1 distinct)" not in rendered


def test_firewall_synthetic_ipv4() -> None:
    """A synthetic IPv4 filterlog line parses src, dst, dport and ipversion."""
    cluster = _only_cluster(
        [
            _alert(
                predecoder={"program_name": "filterlog"},
                full_log=(
                    "Sep 30 10:00:00 fw.example.net filterlog[1]: "
                    "5,,,abc,vtnet0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,"
                    "60,192.0.2.50,198.51.100.7,51515,22,0,S,1,,64240,,mss"
                ),
            )
        ]
    )
    fw = cluster["evidence"]["firewall"]
    assert fw["sources"] == ["192.0.2.50"]
    assert fw["destinations"] == ["198.51.100.7"]
    assert fw["dstports"] == ["22"]
    assert fw["ipversions"] == ["ipv4"]
    assert fw["protocols"] == ["tcp"]


def test_firewall_synthetic_icmp_no_dport() -> None:
    """A non-TCP/UDP filterlog line parses cleanly with no dstport."""
    cluster = _only_cluster(
        [
            _alert(
                predecoder={"program_name": "filterlog"},
                full_log=(
                    "Sep 30 10:00:00 fw.example.net filterlog[1]: "
                    "1,,,abc,em0,match,block,in,4,0x0,,64,12345,0,none,1,icmp,"
                    "84,192.0.2.10,198.51.100.9"
                ),
            )
        ]
    )
    fw = cluster["evidence"]["firewall"]
    assert fw["protocols"] == ["icmp"]
    assert "dstports" not in fw or fw["dstports"] == []


def test_firewall_malformed_lines_skipped() -> None:
    """Malformed filterlog lines are skipped without producing firewall evidence."""
    cluster = _only_cluster(
        [
            _alert(
                predecoder={"program_name": "filterlog"},
                full_log=(
                    "Sep 30 10:00:00 fw.example.net sshd[1]: no filterlog here\n"
                    "Sep 30 10:00:01 fw.example.net filterlog[1]: 1,2,3\n"
                    "Sep 30 10:00:02 fw.example.net filterlog[1]: "
                    "1,,,abc,em0,match,block,in,99,0x0,,64,12345,0,none,6,tcp,"
                    "60,192.0.2.1,198.51.100.1,1234,80,0"
                ),
            )
        ]
    )
    assert "evidence" not in cluster


def test_firewall_sources_capped_but_count_kept() -> None:
    """Distinct firewall sources are capped while the true count is preserved."""
    lines = "\n".join(
        (
            "Sep 30 10:00:00 fw.example.net filterlog[1]: "
            f"1,,,abc,em0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,"
            f"60,192.0.2.{i},198.51.100.1,1234,80,0"
        )
        for i in range(1, 7)
    )
    cluster = _only_cluster(
        [_alert(predecoder={"program_name": "filterlog"}, full_log=lines)]
    )
    fw = cluster["evidence"]["firewall"]
    assert len(fw["sources"]) == MAX_EVIDENCE_VALUES == 5
    assert fw["sources_total"] == 6
    rendered = render_evidence(cluster["evidence"])
    assert "(6 distinct)" in rendered


# --- generic ---


def test_generic_srcip_and_dstuser_collected() -> None:
    """A generic alert collects distinct srcip and dstuser values."""
    cluster = _only_cluster(
        [
            _alert(data={"srcip": "192.0.2.1", "dstuser": "root"}),
            _alert(data={"srcip": "192.0.2.2", "dstuser": "root"}),
        ]
    )
    assert cluster["evidence"] == {
        "generic": {"srcips": ["192.0.2.1", "192.0.2.2"], "dstusers": ["root"]}
    }


def test_generic_nothing_present_yields_no_evidence_key() -> None:
    """A generic alert with no data fields carries no evidence key."""
    cluster = _only_cluster([_alert()])
    assert "evidence" not in cluster


def test_generic_drops_non_ip_srcip() -> None:
    """Generic accumulator rejects srcip values that are not valid IP addresses."""
    acc: dict[str, Any] = {}
    accumulate(acc, _alert(data={"srcip": "443", "dstuser": "alice"}))
    accumulate(acc, _alert(data={"srcip": "192.0.2.9"}))
    accumulate(acc, _alert(data={"srcip": "2001:db8::1"}))
    generic = acc["generic"]
    assert generic["srcips"] == ["192.0.2.9", "2001:db8::1"]
    assert "443" not in generic["srcips"]
    assert generic["dstusers"] == ["alice"]


# --- caps and truncation ---


def test_distinct_values_capped_at_max_evidence_values() -> None:
    """More than five distinct paths accumulate only the first five."""
    alerts = [
        _syscheck_alert(path=f"/etc/file{i}") for i in range(7)
    ]
    cluster = _only_cluster(alerts)
    paths = cluster["evidence"]["syscheck"]["paths"]
    assert len(paths) == MAX_EVIDENCE_VALUES == 5


def test_long_value_truncated_with_ellipsis() -> None:
    """A 500-char value truncates to 100 chars ending with an ellipsis."""
    cluster = _only_cluster([_syscheck_alert(path="/" + "x" * 499)])
    value = cluster["evidence"]["syscheck"]["paths"][0]
    assert len(value) == MAX_EVIDENCE_VALUE_CHARS == 100
    assert value.endswith("…")


def test_render_evidence_empty_inputs() -> None:
    """Absent or empty evidence renders as the empty string."""
    assert render_evidence(None) == ""
    assert render_evidence({}) == ""
    assert render_evidence({"generic": {}}) == ""


# --- all fixtures together ---


def test_all_fixtures_produce_nine_clusters() -> None:
    """All nine fixtures together extract nine clusters without exceptions."""
    alerts = [
        _fixture("syscheck-550.json"),
        _fixture("dpkg-installed-2902.json"),
        _fixture("dpkg-half-configured-2904.json"),
        _fixture("netstat-533.json"),
        _fixture("docker-kill-87924.json"),
        _fixture("docker-start-87903.json"),
        _fixture("vuln-solved-23502.json"),
        _fixture("firewall-multiple-87702.json"),
        _fixture("firewall-drop-87701.json"),
    ]
    clusters = extract_alert_clusters(alerts)
    assert len(clusters) == 9
    assert all("evidence" in c for c in clusters)


# --- unchanged-output regressions ---


def _regression_cluster() -> dict[str, Any]:
    """Build one output-shaped cluster dict for regression checks."""
    return {
        "id": "C1",
        "type": "vulnerability",
        "description": "CVE-2026-1234 affects openssl",
        "rule_ids": ["23503"],
        "hosts": ["host-1"],
        "count": 1,
        "max_level": 10,
        "severity": "Medium",
        "first_seen": "2026-09-24T10:00:00.000Z",
        "last_seen": "2026-09-24T10:00:00.000Z",
        "cves": ["CVE-2026-1234"],
        "package": "openssl",
        "narrative": "",
        "recommendation": "",
    }


_SAMPLE_EVIDENCE = {
    "vulnerability": {"statuses": {"Solved": 1}, "versions": ["1.2.3"]}
}


def test_cluster_key_unaffected_by_evidence() -> None:
    """cluster_key() output is identical with and without an evidence dict."""
    cluster = _regression_cluster()
    with_evidence = {**cluster, "evidence": _SAMPLE_EVIDENCE}
    assert cluster_key(with_evidence) == cluster_key(cluster)


def test_baseline_vector_text_unaffected_by_evidence() -> None:
    """_cluster_vector_text() output is identical with and without evidence."""
    cluster = _regression_cluster()
    with_evidence = {**cluster, "evidence": _SAMPLE_EVIDENCE}
    assert Manager._cluster_vector_text(with_evidence) == (
        Manager._cluster_vector_text(cluster)
    )


def test_baseline_cluster_summary_unaffected_by_evidence() -> None:
    """_cluster_summary() output is identical with and without evidence."""
    cluster = _regression_cluster()
    with_evidence = {**cluster, "evidence": _SAMPLE_EVIDENCE}
    assert Manager._cluster_summary(with_evidence) == (
        Manager._cluster_summary(cluster)
    )


def test_netstat_missing_full_log_gives_no_evidence() -> None:
    """previous_log without a usable full_log must not report every port as closed."""
    alert = _fixture("netstat-533.json")
    del alert["_source"]["full_log"]
    [cluster] = extract_alert_clusters([alert])
    assert "evidence" not in cluster