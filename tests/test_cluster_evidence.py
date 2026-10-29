"""
Tests for per-cluster mechanical evidence extraction (facts read straight from alerts).

Fixtures are redacted real alerts loaded from tests/fixtures/; synthetic
alerts use the same _alert factory pattern as test_clusters.py.
No network, no LLM, no ChromaDB.
"""

import json
from pathlib import Path
from typing import Any

from ravensight.analyser import _build_prompt, cluster_key, extract_alert_clusters
from ravensight.baseline import Manager
from ravensight.evidence import (
    MAX_EVIDENCE_LINE_CHARS,
    MAX_EVIDENCE_VALUE_CHARS,
    MAX_EVIDENCE_VALUES,
    _classify_ip_scope,
    _empty_shape_acc,
    _project_firewall,
    _render_firewall,
    accumulate,
    detect_shape,
    dpkg_event,
    render_evidence,
    sca_check_policy,
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


def _sca_alert(
    title: Any = "Ensure permissions on /etc/security/opasswd are configured.",
    result: Any = "failed",
    agent: str = "Wazuh",
) -> dict[str, Any]:
    """Build an inline SCA check alert using the observed Indexer fields."""
    policy = "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0."
    alert = _alert(
        description=f"{policy}: {title}", level=7, rule_id="19007", agent=agent,
        timestamp="2026-10-29T03:43:39.736+0000", groups=["sca"],
        data={"sca": {
            "type": "check", "policy": policy, "scan_id": "1479757890",
            "check": {"id": "35770", "title": title, "result": result},
        }},
    )
    source = alert["_source"]
    source["timestamp"] = source.pop("@timestamp")
    return alert


def test_sca_shape_and_existing_fixture_shapes() -> None:
    """SCA checks have their own shape while existing fixtures keep theirs."""
    assert detect_shape(_sca_alert()) == "sca"
    for filename, shape in (
        ("syscheck-550.json", "syscheck"),
        ("dpkg-installed-2902.json", "dpkg"),
        ("dpkg-half-configured-2904.json", "dpkg"),
        ("netstat-533.json", "netstat"),
        ("docker-kill-87924.json", "docker"),
        ("docker-start-87903.json", "docker"),
        ("vuln-solved-23502.json", "vulnerability"),
        ("firewall-mixed-dir-87702.json", "firewall"),
        ("firewall-drop-87701.json", "firewall"),
        ("firewall-multiple-87702.json", "firewall"),
    ):
        assert detect_shape(_fixture(filename)) == shape


def test_sca_policy_validation_and_cleaning() -> None:
    """Malformed SCA policy fields return None and valid names are cleaned."""
    for alert in (
        {}, {"_source": []}, {"_source": {"rule": []}},
        {"_source": {"rule": {"groups": 1}}},
    ):
        assert sca_check_policy(alert) is None
    for field, values in (
        ("type", [None, "summary"]),
        ("policy", [None, 7, "", " \n "]),
    ):
        for value in values:
            alert = _sca_alert()
            alert["_source"]["data"]["sca"][field] = value
            assert sca_check_policy(alert) is None
    alert = _sca_alert()
    alert["_source"]["data"]["sca"]["policy"] = "  CIS\n Ubuntu  "
    assert sca_check_policy(alert) == "CIS Ubuntu"


def test_sca_checks_sorted_capped_and_rendered() -> None:
    """SCA values are distinct, sorted, capped at five and show overflow."""
    alerts = [_sca_alert(title=f"Check {i}") for i in (4, 2, 3, 1, 0, 5, 6, 6)]
    evidence = _only_cluster(alerts)["evidence"]
    assert evidence["sca"]["checks"] == [f"Check {i}: failed" for i in range(5)]
    assert evidence["sca"]["more"] == {"checks": 2}
    assert render_evidence(evidence) == (
        "checks " + ", ".join(f"Check {i}: failed" for i in range(5)) + " (+2 more)"
    )


def test_sca_long_title_preserves_result_in_main_evidence() -> None:
    """Shortening a long title keeps the full result in the main checks value."""
    evidence = _only_cluster([_sca_alert(title="Ensure permissions " * 20)])["evidence"]
    value = evidence["sca"]["checks"][0]
    assert len(value) <= MAX_EVIDENCE_VALUE_CHARS
    assert value.endswith("…: failed")
    assert render_evidence(evidence).endswith(": failed")


def test_sca_oversized_result_guard() -> None:
    """Results leaving no title space fall back to the bounded title alone."""
    for size in (97, 98, 110):
        evidence = _only_cluster([
            _sca_alert(title="Ensure permissions", result="x" * size)
        ])["evidence"]
        value = evidence["sca"]["checks"][0]
        assert len(value) <= MAX_EVIDENCE_VALUE_CHARS
        if size == 97:
            assert value == "…: " + "x" * size
        else:
            assert value == "Ensure permissions"


def test_sca_missing_title_or_result() -> None:
    """An absent result leaves the title alone and absent titles add nothing."""
    alert = _sca_alert(title="Ensure permissions")
    del alert["_source"]["data"]["sca"]["check"]["result"]
    assert _only_cluster([alert])["evidence"]["sca"]["checks"] == ["Ensure permissions"]
    for title in (None, "", " \n "):
        assert "evidence" not in _only_cluster([_sca_alert(title=title)])
    del alert["_source"]["data"]["sca"]["check"]["title"]
    assert "evidence" not in _only_cluster([alert])


def test_sca_results_keep_wording_and_render_safely() -> None:
    """Whitespace collapses without changing Wazuh's result or leaking pipes."""
    evidence = _only_cluster([
        _sca_alert(title="Ensure | permissions", result=" Not\n applicable ")
    ])["evidence"]
    assert evidence["sca"]["checks"] == ["Ensure | permissions: Not applicable"]
    assert render_evidence(evidence) == "checks Ensure \\| permissions: Not applicable"


def test_sca_per_host_rendering_remains_bounded() -> None:
    """Per-host SCA text may truncate while the main checks retain results."""
    alerts = [
        _sca_alert(title=f"Check {i} " + "permissions " * 20, agent=host)
        for host in ("Wazuh", "host-2") for i in range(2)
    ]
    evidence = _only_cluster(alerts)["evidence"]
    assert all(value.endswith(": failed") for value in evidence["sca"]["checks"])
    rendered = render_evidence(evidence)
    assert rendered.startswith("checks ")
    for host in ("Wazuh", "host-2"):
        segment = rendered.split(f"[{host}: ", 1)[1].split("]", 1)[0]
        assert len(segment) <= 120
        assert segment.endswith("…")


# --- scope classifier ---


def test_scope_classifier_rfc1918_internal() -> None:
    """RFC 1918, loopback and link-local IPv4 ranges classify as internal."""
    for ip in (
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.0.42",
        "127.0.0.1",
        "169.254.1.1",
    ):
        assert _classify_ip_scope(ip) == "internal"


def test_scope_classifier_ula_and_link_local_internal() -> None:
    """ULA, link-local and loopback IPv6 ranges classify as internal."""
    assert _classify_ip_scope("fd00:0:0:1::c") == "internal"
    assert _classify_ip_scope("fd12:3456:789a::1") == "internal"
    assert _classify_ip_scope("fe80::1") == "internal"
    assert _classify_ip_scope("::1") == "internal"


def test_scope_classifier_documentation_ranges_external() -> None:
    """RFC 5737 and 2001:db8::/32 documentation ranges classify as external."""
    assert _classify_ip_scope("2001:db8::1") == "external"
    assert _classify_ip_scope("2001:db8:202::5e") == "external"
    assert _classify_ip_scope("192.0.2.1") == "external"
    assert _classify_ip_scope("198.51.100.7") == "external"
    assert _classify_ip_scope("203.0.113.10") == "external"


def test_scope_classifier_garbage_returns_none() -> None:
    """Unparseable values return None instead of raising."""
    assert _classify_ip_scope("not-an-ip") is None
    assert _classify_ip_scope("") is None
    assert _classify_ip_scope(None) is None  # type: ignore[arg-type]
    assert _classify_ip_scope(443) is None  # type: ignore[arg-type]


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
        "content unchanged; event modified; changed inode, mtime; "
        "paths /etc/resolv.conf"
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


def test_dpkg_event_returns_key_and_status() -> None:
    """dpkg_event parses the 'status ' prefix into (pkg ver, status)."""
    assert dpkg_event(_dpkg_alert()) == (
        "libc-bin 2.39-0ubuntu8.9",
        "installed",
    )


def test_dpkg_event_accepts_status_without_prefix() -> None:
    """dpkg_event also handles a bare status with no 'status ' prefix."""
    assert dpkg_event(_dpkg_alert(status="installed")) == (
        "libc-bin 2.39-0ubuntu8.9",
        "installed",
    )


def test_dpkg_event_none_when_status_missing() -> None:
    """dpkg_event returns None when dpkg_status is absent."""
    assert dpkg_event(_dpkg_alert(status=None)) is None


def test_dpkg_event_none_when_package_missing() -> None:
    """dpkg_event returns None when package is absent."""
    assert dpkg_event(_dpkg_alert(package=None)) is None


def test_dpkg_event_none_when_version_missing() -> None:
    """dpkg_event returns None when version is absent."""
    assert dpkg_event(_dpkg_alert(version=None)) is None


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
            "src_scopes": ["internal"],
            "dst_scopes": ["external"],
            "direction_scopes": {"in": [["internal", "external"]]},
            "sources_total": 3,
            "sources_by_version": {"ipv6": 3},
        }
    }
    rendered = render_evidence(cluster["evidence"])
    src_part = next(p for p in rendered.split("; ") if p.startswith("src "))
    assert (
        "fd00:0:0:1::a, fd00:0:0:1::b, fd00:0:0:1::c (3 distinct: 3 ipv6)"
        in src_part
    )
    assert "443" not in src_part


def test_firewall_multiple_fixture_rendering() -> None:
    """Multiple-block firewall fixture renders as the documented example line."""
    cluster = _only_cluster([_fixture("firewall-multiple-87702.json")])
    assert render_evidence(cluster["evidence"]) == (
        "action block; dir in; iface vtnet1; scope internal → external; "
        "ip versions ipv6; proto tcp; "
        "src fd00:0:0:1::a, fd00:0:0:1::b, fd00:0:0:1::c "
        "(3 distinct: 3 ipv6); "
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
            "src_scopes": ["internal"],
            "dst_scopes": ["external"],
            "direction_scopes": {"in": [["internal", "external"]]},
            "sources_total": 1,
        }
    }
    rendered = render_evidence(cluster["evidence"])
    assert rendered == (
        "action block; dir in; iface vtnet1; scope internal → external; "
        "ip versions ipv6; proto tcp; "
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
    assert fw["src_scopes"] == ["external"]
    assert fw["dst_scopes"] == ["external"]


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
    assert "(6 distinct: 6 ipv4)" in rendered


def test_firewall_mixed_ipv4_ipv6_suffix() -> None:
    """Mixed-version sources render the per-version breakdown, ipv4 first."""
    lines = []
    for i in (1, 2, 3):
        lines.append(
            "Sep 30 10:00:00 fw.example.net filterlog[1]: "
            f"1,,,abc,em0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,"
            f"60,192.0.2.{i},198.51.100.1,1234,80,0"
        )
    for suffix in ("a", "b"):
        lines.append(
            "Sep 30 10:00:01 fw.example.net filterlog[1]: "
            "14,,,00000000000000000000000000000000,em0,match,block,in,6,"
            "0x00,0x00013,64,tcp,6,40,"
            f"fd00:0:0:1::{suffix},2001:db8:100::2,40002"
        )
    cluster = _only_cluster(
        [_alert(predecoder={"program_name": "filterlog"}, full_log="\n".join(lines))]
    )
    fw = cluster["evidence"]["firewall"]
    assert fw["sources_total"] == 5
    assert fw["sources_by_version"] == {"ipv4": 3, "ipv6": 2}
    rendered = render_evidence(cluster["evidence"])
    assert "(5 distinct: 3 ipv4, 2 ipv6)" in rendered


def test_firewall_scope_survives_400_char_truncation() -> None:
    """The scope segment stays in the prompt line even when the rendered
    evidence exceeds MAX_EVIDENCE_LINE_CHARS and is truncated."""
    lines = "\n".join(
        (
            "Sep 30 10:00:00 fw.example.net filterlog[1]: "
            f"1,,,abc,em0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,"
            f"60,192.0.2.{i},198.51.100.{i},1234,{i}{'9' * 89},0"
        )
        for i in range(1, 6)
    )
    cluster = _only_cluster(
        [_alert(predecoder={"program_name": "filterlog"}, full_log=lines)]
    )
    rendered = render_evidence(cluster["evidence"])
    assert len(rendered) > MAX_EVIDENCE_LINE_CHARS
    prompt = _build_prompt([], {}, clusters=[cluster])
    cluster_line = next(
        line for line in prompt.splitlines() if line.startswith("[C1]")
    )
    assert "scope external → external" in cluster_line
    assert cluster_line.endswith("…")


def test_firewall_mixed_direction_fixture_evidence() -> None:
    """Mixed-direction fixture accumulates per-direction scope pairs."""
    cluster = _only_cluster([_fixture("firewall-mixed-dir-87702.json")])
    fw = cluster["evidence"]["firewall"]
    assert set(fw["direction_scopes"]) == {"in", "out"}
    assert fw["direction_scopes"]["in"] == [["external", "internal"]]
    assert fw["direction_scopes"]["out"] == [["internal", "external"]]


def test_firewall_mixed_direction_fixture_rendering() -> None:
    """Mixed-direction fixture renders scope with direction groups."""
    cluster = _only_cluster([_fixture("firewall-mixed-dir-87702.json")])
    rendered = render_evidence(cluster["evidence"])
    assert "scope in external → internal / out internal → external" in rendered


def test_firewall_single_direction_renders_flat_scope() -> None:
    """A single direction still renders the flat src → dst scope."""
    cluster = _only_cluster([_fixture("firewall-drop-87701.json")])
    rendered = render_evidence(cluster["evidence"])
    assert "scope internal → external" in rendered
    assert " / " not in rendered


def test_firewall_direction_scopes_capped_at_two_pairs() -> None:
    """Per-direction scope groups keep only the first two sorted pairs."""
    acc = _empty_shape_acc("firewall")
    acc["direction_scopes"] = {
        "in": {
            ("external", "internal"),
            ("external", "internal2"),
            ("external", "internal3"),
        },
        "out": {("internal", "external")},
    }
    projected = _project_firewall(acc)
    assert len(projected["direction_scopes"]["in"]) == 2
    rendered = _render_firewall(projected)
    scope_part = next(p for p in rendered if p.startswith("scope "))
    assert scope_part.count("→") == 3


def test_firewall_legacy_dict_renders_flat_scope() -> None:
    """A legacy evidence dict without direction_scopes renders the flat scope."""
    rendered = _render_firewall({"src_scopes": ["internal"], "dst_scopes": ["external"]})
    assert rendered == ["scope internal → external"]


# --- per-host evidence ---


def test_per_host_two_syscheck_hosts() -> None:
    """A two-host rule cluster carries per-host evidence, hosts sorted ASCII."""
    alerts = [
        _alert(
            description="Integrity checksum changed.",
            level=7,
            rule_id="550",
            groups=["ossec", "syscheck"],
            agent="kamaji",
            syscheck={"path": "/etc/ld.so.cache", "event": "modified"},
        ),
        _alert(
            description="Integrity checksum changed.",
            level=7,
            rule_id="550",
            groups=["ossec", "syscheck"],
            agent="OPNsense",
            syscheck={"path": "/etc/passwd", "event": "modified"},
        ),
    ]
    cluster = _only_cluster(alerts)
    per_host = cluster["evidence"]["per_host"]
    assert sorted(per_host) == ["OPNsense", "kamaji"]
    assert per_host["kamaji"]["syscheck"]["paths"] == ["/etc/ld.so.cache"]
    assert per_host["OPNsense"]["syscheck"]["paths"] == ["/etc/passwd"]
    rendered = render_evidence(cluster["evidence"])
    assert "per host [OPNsense: event modified; paths /etc/passwd]" in rendered
    assert "[kamaji: event modified; paths /etc/ld.so.cache]" in rendered
    assert rendered.index("[OPNsense:") < rendered.index("[kamaji:")


def test_per_host_absent_for_single_host_cluster() -> None:
    """A single-host cluster never carries a per_host evidence key."""
    cluster = _only_cluster([_syscheck_alert(path="/etc/ld.so.cache")])
    assert "per_host" not in cluster["evidence"]
    rendered = render_evidence(cluster["evidence"])
    assert "per host" not in rendered


def test_per_host_segment_truncated_at_max_host_chars() -> None:
    """A host's inner text longer than 120 chars cuts to 119 chars + ellipsis."""
    evidence_dict = {
        "per_host": {
            "longhost": {
                "dpkg": {"packages": ["a" * 200]},
            }
        }
    }
    segment = "[longhost: " + "a" * 119 + "…]"
    assert render_evidence(evidence_dict) == "per host " + segment


def test_per_host_syscheck_content_first_when_paths_long() -> None:
    """Even when a host's path list exceeds the per-host cap, content leads."""
    long_path = "/etc/" + "a" * 200
    evidence_dict = {
        "per_host": {
            "host1": {
                "syscheck": {
                    "content": "unchanged",
                    "events": ["modified"],
                    "changed": ["inode"],
                    "paths": [long_path],
                }
            }
        }
    }
    rendered = render_evidence(evidence_dict)
    segment_start = rendered.find("[host1: ") + len("[host1: ")
    assert rendered[segment_start:].startswith("content ")


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


_FIREWALL_DATA: dict[str, Any] = {
    "actions": ["block"],
    "directions": ["in"],
    "interfaces": ["vtnet0"],
    "ipversions": ["ipv4"],
    "protocols": ["tcp"],
    "sources": ["1.2.3.4"],
    "destinations": ["5.6.7.8"],
    "dstports": ["443"],
}


def test_firewall_labels_stay_short_by_default_for_the_prompt() -> None:
    """The default rendering keeps the short labels, so the LLM prompt is unchanged."""
    rendered = "; ".join(_render_firewall(_FIREWALL_DATA))
    assert rendered == (
        "action block; dir in; iface vtnet0; ip versions ipv4; proto tcp; "
        "src 1.2.3.4; dst 5.6.7.8; dport 443"
    )


def test_firewall_labels_spelled_out_with_plain_labels() -> None:
    """plain_labels spells out every abbreviated firewall field name."""
    rendered = "; ".join(_render_firewall(_FIREWALL_DATA, plain_labels=True))
    assert rendered == (
        "action block; direction in; interface vtnet0; IP versions ipv4; "
        "protocol tcp; source 1.2.3.4; destination 5.6.7.8; destination port 443"
    )


def test_plain_labels_reach_per_host_firewall_evidence() -> None:
    """Spelled-out labels also apply inside per-host segments."""
    small = {"directions": ["in"], "dstports": ["443"]}
    evidence = {"per_host": {"fw-1": {"firewall": small}}}
    assert "destination port 443" in render_evidence(evidence, plain_labels=True)
    assert "dport 443" in render_evidence(evidence)
    assert "destination port" not in render_evidence(evidence)

# --- visible truncation markers ---


def test_dpkg_overflow_renders_more_packages_marker() -> None:
    """More than five distinct packages renders '(+N more packages)'."""
    alerts = [_dpkg_alert(package=f"pkg{i}") for i in range(8)]
    cluster = _only_cluster(alerts)
    dpkg = cluster["evidence"]["dpkg"]
    assert len(dpkg["packages"]) == MAX_EVIDENCE_VALUES
    assert dpkg["more"] == {"packages": 3}
    assert render_evidence(cluster["evidence"]).endswith("(+3 more packages)")


def test_dpkg_overflow_of_one_is_singular() -> None:
    """Exactly one package over the cap renders '(+1 more package)'."""
    alerts = [_dpkg_alert(package=f"pkg{i}") for i in range(MAX_EVIDENCE_VALUES + 1)]
    cluster = _only_cluster(alerts)
    assert cluster["evidence"]["dpkg"]["more"] == {"packages": 1}
    assert render_evidence(cluster["evidence"]).endswith("(+1 more package)")


def _syscheck_hosts_evidence(content_a: str, content_b: str) -> dict[str, Any]:
    """Build evidence with a combined syscheck verdict and two per-host segments."""
    return {
        "syscheck": {"content": "changed", "paths": ["/etc/passwd"]},
        "per_host": {
            "host-a": {"syscheck": {"content": content_a, "paths": ["/etc/passwd"]}},
            "host-b": {"syscheck": {"content": content_b, "paths": ["/etc/passwd"]}},
        },
    }


def test_syscheck_content_differs_by_host_with_plain_labels() -> None:
    """With plain_labels, disagreeing hosts replace the combined verdict; segments stay unchanged."""
    evidence = _syscheck_hosts_evidence("changed", "unchanged")
    plain = render_evidence(evidence, plain_labels=True)
    default = render_evidence(evidence)
    assert plain.startswith("content differs by host; ")
    assert "[host-a: content changed; paths /etc/passwd]" in plain
    assert "[host-b: content unchanged; paths /etc/passwd]" in plain
    assert plain.split("per host ")[1] == default.split("per host ")[1]


def test_syscheck_content_agreeing_hosts_unchanged() -> None:
    """Hosts that agree keep the combined verdict."""
    evidence = _syscheck_hosts_evidence("changed", "changed")
    assert render_evidence(evidence, plain_labels=True).startswith("content changed; ")


def test_syscheck_content_single_host_unchanged() -> None:
    """Without per_host the combined verdict is untouched."""
    evidence = {"syscheck": {"content": "changed", "paths": ["/etc/passwd"]}}
    assert render_evidence(evidence, plain_labels=True) == (
        "content changed; paths /etc/passwd"
    )


def test_syscheck_default_render_pins_old_combined_verdict() -> None:
    """The default (prompt) render keeps the combined verdict even when hosts disagree."""
    evidence = _syscheck_hosts_evidence("changed", "unchanged")
    assert render_evidence(evidence).startswith("content changed; paths /etc/passwd; ")
    assert "differs by host" not in render_evidence(evidence)


def test_syscheck_paths_overflow_renders_more_marker() -> None:
    """Syscheck paths beyond the cap render '(+N more)' after the shown paths."""
    alerts = [_syscheck_alert(path=f"/etc/f{i}") for i in range(7)]
    cluster = _only_cluster(alerts)
    syscheck = cluster["evidence"]["syscheck"]
    assert syscheck["more"] == {"paths": 2}
    assert "paths /etc/f0, /etc/f1, /etc/f2, /etc/f3, /etc/f4 (+2 more)" in (
        render_evidence(cluster["evidence"])
    )


def test_netstat_overflow_renders_more_marker() -> None:
    """Netstat ports beyond the cap of three render '(+N more)'."""
    previous = "tcp 0.0.0.0:22 0.0.0.0:* 1/systemd"
    current_lines = [previous] + [
        f"tcp 127.0.0.1:{50000 + i} 0.0.0.0:* {100 + i}/svc{i}" for i in range(5)
    ]
    cluster = _only_cluster([_netstat_alert("\n".join(current_lines), previous)])
    netstat = cluster["evidence"]["netstat"]
    assert netstat["more"] == {"added": 2}
    assert "(+2 more)" in render_evidence(cluster["evidence"])


def test_no_more_key_when_no_cap_hit() -> None:
    """Within the caps there is no 'more' key and rendering is unchanged."""
    alerts = [_syscheck_alert(path=f"/etc/f{i}") for i in range(5)]
    cluster = _only_cluster(alerts)
    assert "more" not in cluster["evidence"]["syscheck"]
    rendered = render_evidence(cluster["evidence"])
    assert "more" not in rendered
    assert "paths /etc/f0, /etc/f1, /etc/f2, /etc/f3, /etc/f4" in rendered


def test_repeated_dropped_values_counted_once() -> None:
    """A refused value seen many times is counted once in 'more'."""
    alerts = [_syscheck_alert(path=f"/etc/f{i}") for i in range(5)]
    alerts += [_syscheck_alert(path="/etc/extra") for _ in range(4)]
    cluster = _only_cluster(alerts)
    assert cluster["evidence"]["syscheck"]["more"] == {"paths": 1}


def test_per_host_segment_carries_more_marker() -> None:
    """The overflow marker appears inside the per-host segment."""
    alerts = [
        _alert(
            description="Integrity checksum changed.",
            level=7,
            rule_id="550",
            groups=["ossec", "syscheck"],
            agent="kamaji",
            syscheck={"path": f"/e/{i}", "event": "modified"},
        )
        for i in range(7)
    ]
    alerts.append(
        _alert(
            description="Integrity checksum changed.",
            level=7,
            rule_id="550",
            groups=["ossec", "syscheck"],
            agent="OPNsense",
            syscheck={"path": "/etc/passwd", "event": "modified"},
        )
    )
    cluster = _only_cluster(alerts)
    per_host = cluster["evidence"]["per_host"]
    assert per_host["kamaji"]["syscheck"]["more"] == {"paths": 2}
    assert "more" not in per_host["OPNsense"]["syscheck"]
    rendered = render_evidence(cluster["evidence"])
    segment = rendered.split("[kamaji: ", 1)[1].split("]", 1)[0]
    assert "(+2 more)" in segment


def test_per_host_cut_at_word_boundary() -> None:
    """An over-long per-host segment is cut at a word boundary, not mid-word."""
    evidence_dict = {
        "per_host": {
            "h": {
                "syscheck": {
                    "content": "unchanged",
                    "events": ["modified"],
                    "changed": ["inode"],
                    "paths": ["/etc/aaaaaaaa", "/etc/bbbbbbbb", "/etc/cccccccc"] * 4,
                }
            }
        }
    }
    rendered = render_evidence(evidence_dict)
    segment = rendered.split("[h: ", 1)[1]
    assert segment.endswith("…]")
    body = segment[:-2]
    assert len(body) < 120
    assert not body.endswith(",")
    last = body.split(" ")[-1].rstrip(",;")
    assert last in {"/etc/aaaaaaaa", "/etc/bbbbbbbb", "/etc/cccccccc"}


def test_evidence_absent_when_nothing_extracted() -> None:
    """With nothing extractable the 'evidence' key stays absent."""
    cluster = _only_cluster([_alert(description="Plain")])
    assert "evidence" not in cluster
