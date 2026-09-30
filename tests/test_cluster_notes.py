"""
Tests for data-built cluster notes (Build 1d): the notes field default, dpkg
upgrade-sequence pairing, and the rule 87702 IPv6 artefact note.

Fixtures are redacted real alerts loaded from tests/fixtures/; synthetic
alerts use the same _alert factory pattern as test_cluster_evidence.py.
No network, no LLM, no ChromaDB.
"""

import copy
import json
from pathlib import Path
from typing import Any

from ravensight.analyser import (
    RULE_87702_IPV6_ARTEFACT_NOTE,
    extract_alert_clusters,
)


def _fixture(name: str) -> dict[str, Any]:
    """Load one redacted real-alert fixture by file name."""
    return json.loads((Path(__file__).parent / "fixtures" / name).read_text())


def _alert(
    description: str,
    rule_id: Any,
    level: Any = 7,
    agent: Any = "host-a",
    timestamp: Any = "2026-09-24T10:00:00.000Z",
    groups: Any = None,
    data: Any = None,
    full_log: Any = None,
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
    if full_log is not None:
        source["full_log"] = full_log
    if predecoder is not None:
        source["predecoder"] = predecoder
    return {"_source": source}


def _dpkg_alert(
    status: str,
    package: str = "libc-bin",
    version: str = "2.39-0ubuntu8.9",
    agent: str = "host-a",
    timestamp: str = "2026-09-24T10:00:00.000Z",
) -> dict[str, Any]:
    """Build a synthetic dpkg alert; status wording mirrors the real rules."""
    if status == "installed":
        description = "New dpkg (Debian Package) installed."
        rule_id = "2902"
    else:
        description = "Dpkg (Debian Package) half configured."
        rule_id = "2904"
    return _alert(
        description=description,
        rule_id=rule_id,
        agent=agent,
        timestamp=timestamp,
        groups=["syslog", "dpkg"],
        data={
            "package": package,
            "version": version,
            "dpkg_status": f"status {status}",
        },
    )


def _dpkg_fixture_alert(
    status: str,
    timestamp: Any = None,
    package: Any = None,
    version: Any = None,
) -> dict[str, Any]:
    """Deepcopy the matching dpkg fixture with edited fields (fixtures stay
    untouched on disk).
    """
    name = (
        "dpkg-installed-2902.json"
        if status == "installed"
        else "dpkg-half-configured-2904.json"
    )
    alert = copy.deepcopy(_fixture(name))
    source = alert["_source"]
    if timestamp is not None:
        source["timestamp"] = timestamp
    if package is not None:
        source["data"]["package"] = package
    if version is not None:
        source["data"]["version"] = version
    return alert


def test_extract_alert_clusters_notes_field_default_empty() -> None:
    """Clusters carry a notes list that starts empty when nothing applies."""
    clusters = extract_alert_clusters([_fixture("syscheck-550.json")])
    assert len(clusters) == 1
    assert clusters[0]["notes"] == []


def test_dpkg_pairing_normal_case() -> None:
    """The real 2902/2904 fixtures pair into a normal upgrade sequence note."""
    clusters = extract_alert_clusters(
        [
            _fixture("dpkg-installed-2902.json"),
            _fixture("dpkg-half-configured-2904.json"),
        ]
    )
    assert len(clusters) == 2
    by_desc = {c["description"]: c for c in clusters}
    half = by_desc["Dpkg (Debian Package) half configured."]
    installed = by_desc["New dpkg (Debian Package) installed."]
    assert half["notes"] == [
        (
            "normal dpkg upgrade sequence: libc-bin 2.39-0ubuntu8.9 "
            f"half-configured → installed within 1 s (see {installed['id']})"
        )
    ]
    assert installed["notes"] == [
        (
            "normal dpkg upgrade sequence: libc-bin 2.39-0ubuntu8.9 "
            f"half-configured → installed within 1 s (see {half['id']})"
        )
    ]


def test_dpkg_pairing_no_pair_when_too_far_apart() -> None:
    """Timestamps 90 s apart do not pair."""
    clusters = extract_alert_clusters(
        [
            _dpkg_alert("half-configured", timestamp="2026-09-24T10:00:00.000Z"),
            _dpkg_alert("installed", timestamp="2026-09-24T10:01:30.000Z"),
        ]
    )
    assert all(c["notes"] == [] for c in clusters)


def test_dpkg_pairing_no_pair_when_different_versions() -> None:
    """Same package at different versions does not pair."""
    clusters = extract_alert_clusters(
        [
            _dpkg_alert("half-configured", version="2.39-0ubuntu8.8"),
            _dpkg_alert("installed", version="2.39-0ubuntu8.9"),
        ]
    )
    assert all(c["notes"] == [] for c in clusters)


def test_dpkg_pairing_no_pair_when_different_hosts() -> None:
    """Same package/version/timestamps on different hosts does not pair."""
    clusters = extract_alert_clusters(
        [
            _dpkg_alert("half-configured", agent="host-a"),
            _dpkg_alert("installed", agent="host-b"),
        ]
    )
    assert all(c["notes"] == [] for c in clusters)


def test_dpkg_pairing_skips_unparseable_timestamp() -> None:
    """An unparseable timestamp skips pairing without raising."""
    clusters = extract_alert_clusters(
        [
            _dpkg_alert("half-configured", timestamp=""),
            _dpkg_alert("installed"),
        ]
    )
    assert all(c["notes"] == [] for c in clusters)


def test_dpkg_pairing_skips_timestamp_that_fails_fromisoformat() -> None:
    """A non-ISO timestamp string skips pairing without raising."""
    clusters = extract_alert_clusters(
        [
            _dpkg_alert("half-configured", timestamp="banana"),
            _dpkg_alert("installed"),
        ]
    )
    assert all(c["notes"] == [] for c in clusters)


def test_dpkg_pairing_installed_cluster_sorts_first() -> None:
    """Pairing is order-independent: an installed cluster with more alerts
    sorts first, and both clusters still get the note.
    """
    clusters = extract_alert_clusters(
        [
            _dpkg_fixture_alert("installed"),
            _dpkg_fixture_alert("installed"),
            _dpkg_fixture_alert("half-configured"),
        ]
    )
    assert len(clusters) == 2
    by_desc = {c["description"]: c for c in clusters}
    half = by_desc["Dpkg (Debian Package) half configured."]
    installed = by_desc["New dpkg (Debian Package) installed."]
    assert installed["count"] == 2  # sorts first
    note = (
        "normal dpkg upgrade sequence: libc-bin 2.39-0ubuntu8.9 "
        f"half-configured → installed within 1 s (see {installed['id']})"
    )
    mirror = (
        "normal dpkg upgrade sequence: libc-bin 2.39-0ubuntu8.9 "
        f"half-configured → installed within 1 s (see {half['id']})"
    )
    assert half["notes"] == [note]
    assert installed["notes"] == [mirror]


def test_dpkg_pairing_multi_package_apt_upgrade() -> None:
    """Two packages each paired within 2 ms, 5 minutes apart, land in one
    note on each cluster listing both pkg vers with the largest gap.
    """
    clusters = extract_alert_clusters(
        [
            _dpkg_fixture_alert(
                "half-configured", package="pkg-a", version="ver-a",
                timestamp="2026-09-24T10:00:00.000+00:00",
            ),
            _dpkg_fixture_alert(
                "installed", package="pkg-a", version="ver-a",
                timestamp="2026-09-24T10:00:00.002+00:00",
            ),
            _dpkg_fixture_alert(
                "half-configured", package="pkg-b", version="ver-b",
                timestamp="2026-09-24T10:05:00.000+00:00",
            ),
            _dpkg_fixture_alert(
                "installed", package="pkg-b", version="ver-b",
                timestamp="2026-09-24T10:05:00.002+00:00",
            ),
        ]
    )
    assert len(clusters) == 2
    by_desc = {c["description"]: c for c in clusters}
    half = by_desc["Dpkg (Debian Package) half configured."]
    installed = by_desc["New dpkg (Debian Package) installed."]
    note = (
        "normal dpkg upgrade sequence: pkg-a ver-a, pkg-b ver-b "
        f"half-configured → installed within 1 s (see {installed['id']})"
    )
    mirror = (
        "normal dpkg upgrade sequence: pkg-a ver-a, pkg-b ver-b "
        f"half-configured → installed within 1 s (see {half['id']})"
    )
    assert half["notes"] == [note]
    assert installed["notes"] == [mirror]


def test_dpkg_pairing_five_packages_lists_three_plus_more() -> None:
    """Five paired packages produce one note listing three plus '(+2 more)'."""
    alerts: list[dict[str, Any]] = []
    for index in range(1, 6):
        package = f"pkg{index}"
        version = f"ver{index}"
        alerts.append(
            _dpkg_fixture_alert(
                "half-configured", package=package, version=version,
                timestamp="2026-09-24T10:00:00.000+00:00",
            )
        )
        alerts.append(
            _dpkg_fixture_alert(
                "installed", package=package, version=version,
                timestamp="2026-09-24T10:00:00.002+00:00",
            )
        )
    clusters = extract_alert_clusters(alerts)
    assert len(clusters) == 2
    by_desc = {c["description"]: c for c in clusters}
    half = by_desc["Dpkg (Debian Package) half configured."]
    installed = by_desc["New dpkg (Debian Package) installed."]
    note = (
        "normal dpkg upgrade sequence: pkg1 ver1, pkg2 ver2, pkg3 ver3 "
        f"(+2 more) half-configured → installed within 1 s "
        f"(see {installed['id']})"
    )
    mirror = (
        "normal dpkg upgrade sequence: pkg1 ver1, pkg2 ver2, pkg3 ver3 "
        f"(+2 more) half-configured → installed within 1 s (see {half['id']})"
    )
    assert half["notes"] == [note]
    assert installed["notes"] == [mirror]


def test_dpkg_pairing_no_pair_when_same_package_different_hosts() -> None:
    """Half-configured on one host and installed on another do not pair."""
    half_configured = _dpkg_fixture_alert("half-configured")
    installed = _dpkg_fixture_alert("installed")
    installed["_source"]["agent"]["name"] = "host-b"
    assert half_configured["_source"]["agent"]["name"] == "host-a"
    clusters = extract_alert_clusters([half_configured, installed])
    assert all(c["notes"] == [] for c in clusters)


def test_rule_87702_artefact_note_for_ipv6() -> None:
    """The 87702 IPv6 fixture carries the artefact note."""
    clusters = extract_alert_clusters([_fixture("firewall-multiple-87702.json")])
    assert len(clusters) == 1
    assert clusters[0]["notes"] == [RULE_87702_IPV6_ARTEFACT_NOTE]


def test_rule_87702_artefact_note_absent_for_ipv4() -> None:
    """A synthetic 87702 IPv4 alert does not carry the artefact note."""
    alert = _alert(
        description="OPNsense firewall drop event.",
        rule_id="87702",
        level=5,
        agent="fw-a",
        full_log=(
            "Sep 30 10:00:00 fw.example.net filterlog[1]: "
            "5,,,abc,vtnet0,match,block,in,4,0x0,,64,12345,0,DF,6,tcp,"
            "60,192.0.2.50,198.51.100.7,51515,22,0,S,1,,64240,,mss"
        ),
        predecoder={"program_name": "filterlog"},
    )
    clusters = extract_alert_clusters([alert])
    assert len(clusters) == 1
    assert clusters[0]["notes"] == []
