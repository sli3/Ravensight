"""
Tests for the Build 1e fidelity guard in ravensight.analyser.

The guard flags narrative/recommendation tokens that the cluster's own
evidence cannot support. No network, no LLM.
"""

import copy
from typing import Any

from ravensight.analyser import _build_prompt, _fidelity_flags
from ravensight.evidence import MAX_EVIDENCE_LINE_CHARS, render_evidence


def _finding(narrative: str = "", **overrides: Any) -> dict[str, Any]:
    """Build one cluster-shaped finding dict with sensible defaults."""
    finding: dict[str, Any] = {
        "id": "C1",
        "type": "rule",
        "description": "SSHD brute force attempts",
        "rule_ids": ["5710"],
        "hosts": ["host-1"],
        "count": 3,
        "max_level": 12,
        "severity": "High",
        "first_seen": "2026-09-24T08:15:00.000Z",
        "last_seen": "2026-09-24T10:30:00.000Z",
        "cves": [],
        "package": None,
        "narrative": narrative,
        "recommendation": "",
        "notes": [],
    }
    finding.update(overrides)
    return finding


def test_technique_id_flagged_tactic_id_not() -> None:
    """A MITRE technique id is flagged; a tactic id (TA0001) is left alone."""
    flags = _fidelity_flags(
        _finding(narrative="Matches technique T1100 but not tactic TA0001."), set()
    )
    assert flags == ["T1100"]


def test_cve_in_cves_not_flagged() -> None:
    """A CVE already attached to the cluster is not flagged."""
    finding = _finding(
        narrative="Vulnerability CVE-2026-1234 is solved.",
        type="vulnerability",
        package="openssl",
        cves=["CVE-2026-1234"],
    )
    assert "CVE-2026-1234" not in _fidelity_flags(finding, set())


def test_absent_cve_flagged() -> None:
    """A CVE the cluster does not carry is flagged."""
    flags = _fidelity_flags(
        _finding(narrative="Vulnerability CVE-2026-9999 found."), set()
    )
    assert "CVE-2026-9999" in flags


def test_path_in_evidence_with_full_stop_not_flagged() -> None:
    """A path present in evidence is not flagged even with a trailing full stop."""
    finding = _finding(
        narrative="The file /etc/resolv.conf. was modified.",
        evidence={
            "syscheck": {"paths": ["/etc/resolv.conf"], "events": ["modified"]}
        },
    )
    assert _fidelity_flags(finding, set()) == []


def test_absent_path_flagged() -> None:
    """A path absent from the evidence corpus is flagged."""
    flags = _fidelity_flags(
        _finding(narrative="The file /root/.ssh/backdoor was added."), set()
    )
    assert "/root/.ssh/backdoor" in flags


def test_port_in_evidence_not_flagged() -> None:
    """A port number present in the evidence corpus is not flagged."""
    finding = _finding(
        narrative="Blocked inbound dport 443 traffic.",
        evidence={"firewall": {"dstports": ["443"], "protocols": ["tcp"]}},
    )
    assert "443" not in _fidelity_flags(finding, set())


def test_absent_port_flagged() -> None:
    """A port number absent from the evidence corpus is flagged."""
    flags = _fidelity_flags(
        _finding(narrative="Blocked inbound dport 8443 traffic."), set()
    )
    assert "8443" in flags


def test_network_token_supported_by_corpus_address() -> None:
    """A /32 network is not flagged when an address inside it is in evidence."""
    finding = _finding(
        narrative="Traffic arrived from 2a01:4f8::/32.",
        evidence={"generic": {"srcips": ["2a01:4f8:10:20::99"]}},
    )
    assert "2a01:4f8::/32" not in _fidelity_flags(finding, set())


def test_count_claim_supported_by_sources_total() -> None:
    """'3 distinct sources' is not flagged when the evidence shows three."""
    finding = _finding(
        count=10,
        narrative="The cluster saw 3 distinct sources.",
        evidence={
            "firewall": {
                "sources": ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
                "sources_total": 3,
                "sources_by_version": {"ipv4": 3},
            }
        },
    )
    assert "3" not in _fidelity_flags(finding, set())


def test_absent_count_claim_flagged() -> None:
    """'17 sources' is flagged when neither the count nor the corpus holds 17."""
    flags = _fidelity_flags(
        _finding(count=3, narrative="Observed 17 sources in this cluster."), set()
    )
    assert "17" in flags


def test_known_provider_flagged() -> None:
    """A cloud provider name unknown to the cluster is flagged."""
    flags = _fidelity_flags(
        _finding(narrative="The requests came from Cloudflare addresses."), set()
    )
    assert "Cloudflare" in flags


def test_vendor_name_not_flagged() -> None:
    """A vendor name from the platform agents map is never flagged."""
    finding = _finding(narrative="The OPNsense firewall blocked the traffic.")
    assert "OPNsense" not in _fidelity_flags(finding, {"OPNsense"})


def test_value_past_prompt_cap_but_in_evidence_not_flagged() -> None:
    """A value cut by the 400-char prompt cap is still supported by the corpus."""
    long_paths = [f"/srv/app/{'p' * 90}{i}" for i in range(5)]
    target = long_paths[-1]
    finding = _finding(
        narrative=f"The log {target} was rotated.",
        evidence={"syscheck": {"paths": long_paths, "events": ["modified"]}},
    )
    rendered = render_evidence(finding["evidence"])
    assert len(rendered) > MAX_EVIDENCE_LINE_CHARS
    assert _fidelity_flags(finding, set()) == []


def test_evidence_dict_unchanged_after_guard() -> None:
    """The guard never mutates the finding's evidence (deepcopy compare)."""
    finding = _finding(
        narrative="Matches technique T1100.",
        evidence={
            "syscheck": {"paths": ["/etc/resolv.conf"], "events": ["modified"]}
        },
    )
    before = copy.deepcopy(finding["evidence"])
    _fidelity_flags(finding, set())
    assert finding["evidence"] == before


def test_build_prompt_never_contains_flag_text() -> None:
    """Flags are report-only: no flag text ever reaches the LLM prompt."""
    cluster = _finding(narrative="Narrative mentioning T1100.", flags=["T1100"])
    prompt = _build_prompt([], {}, clusters=[cluster])
    assert "T1100" not in prompt


def test_host_count_claim_not_flagged() -> None:
    """A count claim equal to the number of hosts in the cluster is supported."""
    flags = _fidelity_flags(
        _finding(
            narrative="The same change appears on 2 hosts.",
            hosts=["kamaji", "OPNsense"],
        ),
        set(),
    )
    assert flags == []


def test_technique_id_in_notes_not_flagged() -> None:
    """A technique id the cluster's own notes already name is supported."""
    flags = _fidelity_flags(
        _finding(
            narrative="The rule's T1110 tag does not fit; T1078 is not shown.",
            notes=["its same-source wording and T1110 tag do not describe the sources"],
        ),
        set(),
    )
    assert flags == ["T1078"]