"""
Tests for platform hints loading and platform context block construction
in ravensight.analyser.
"""

import json
import logging
from pathlib import Path
from typing import Any

from ravensight.analyser import (
    _build_asd_context,
    _build_host_facts_block,
    _build_platform_context,
    _load_asd_data,
    _load_platform_agents,
    _load_platform_hints,
    _rewrite_cluster_vendor_names,
)

FREEBSD_HINT = (
    "Link count mismatches on /boot/efi are a structural FAT32 artefact on "
    "FreeBSD/OPNsense — not an indicator of rootkit activity. Do not escalate."
)

FREEBSD_HINTS: dict[str, Any] = {
    "freebsd": {
        "description": "FreeBSD and derivatives (OPNsense, pfSense)",
        "filesystem_notes": (
            "FAT32 (EFI partition) does not implement Unix hard link counts."
        ),
        "rules": {
            "510": {
                "paths": ["/boot/efi"],
                "hint": FREEBSD_HINT,
            }
        },
    }
}


def _make_alert(
    agent_name: str,
    platform: str,
    rule_id: str,
    os_name: str = "FreeBSD",
    rule_description: str = "FIM: Hard link count changed",
) -> dict[str, Any]:
    """Build a Wazuh-shaped alert dict for testing."""
    return {
        "_source": {
            "agent": {
                "name": agent_name,
                "os": {"platform": platform, "name": os_name},
            },
            "rule": {"id": rule_id, "description": rule_description},
        }
    }


def test_load_platform_hints_missing_file_returns_empty_and_logs_warning(
    tmp_path: Path, caplog: Any
) -> None:
    """Missing hints file returns {} and logs a warning."""
    caplog.set_level(logging.WARNING, logger="ravensight.analyser")
    missing = str(tmp_path / "does_not_exist.json")
    result = _load_platform_hints(missing)
    assert result == {}
    assert any(
        "Platform hints file not found" in rec.message for rec in caplog.records
    )


def test_load_platform_hints_malformed_json_returns_empty(
    tmp_path: Path, caplog: Any
) -> None:
    """Malformed JSON returns {} without raising."""
    caplog.set_level(logging.WARNING, logger="ravensight.analyser")
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{ not valid json", encoding="utf-8")
    result = _load_platform_hints(str(bad_file))
    assert result == {}
    assert any(
        "Failed to parse platform hints file" in rec.message
        for rec in caplog.records
    )


def test_load_platform_hints_valid_json_returns_dict(tmp_path: Path) -> None:
    """Valid JSON file returns the parsed dict."""
    hints_file = tmp_path / "hints.json"
    hints_file.write_text(json.dumps(FREEBSD_HINTS), encoding="utf-8")
    result = _load_platform_hints(str(hints_file))
    assert result == FREEBSD_HINTS


def test_build_platform_context_freebsd_with_rule_510() -> None:
    """FreeBSD agent with rule 510 in batch yields full block with rule hint."""
    alerts = [_make_alert("fw1", "freebsd", "510")]
    context = _build_platform_context(alerts, FREEBSD_HINTS)
    assert context.startswith("Platform context:\n")
    lines = context.split("\n")
    assert lines[1].startswith("- Agent: fw1 (freebsd — FreeBSD and derivatives")
    assert "FAT32 (EFI partition) does not implement Unix hard link counts." in context
    assert "Known false positives for this platform:" in context
    assert f"  - Rule 510 on /boot/efi: {FREEBSD_HINT}" in context


def test_build_platform_context_freebsd_without_rule_510() -> None:
    """FreeBSD agent without rule 510 yields agent and notes lines, no rule hints."""
    alerts = [_make_alert("fw1", "freebsd", "5712")]
    context = _build_platform_context(alerts, FREEBSD_HINTS)
    assert context != ""
    assert "- Agent: fw1 (freebsd — FreeBSD and derivatives" in context
    assert "FAT32 (EFI partition) does not implement Unix hard link counts." in context
    assert "Known false positives" not in context


def test_build_platform_context_case_insensitive_platform() -> None:
    """Capitalised platform value matches lowercase hints key."""
    alerts = [_make_alert("fw1", "FreeBSD", "510")]
    context = _build_platform_context(alerts, FREEBSD_HINTS)
    assert "Known false positives for this platform:" in context
    assert "Rule 510 on /boot/efi" in context


def test_build_platform_context_missing_platform_yields_empty() -> None:
    """Alert without agent.os.platform yields empty string."""
    alerts = [
        {
            "_source": {
                "agent": {"name": "fw1"},
                "rule": {"id": "510", "description": "FIM event"},
            }
        }
    ]
    assert _build_platform_context(alerts, FREEBSD_HINTS) == ""


def test_build_platform_context_unknown_platform_yields_empty() -> None:
    """Alert with platform absent from hints keys yields empty string."""
    alerts = [_make_agent_alert("srv1", "aix", "7")]
    assert _build_platform_context(alerts, FREEBSD_HINTS) == ""


def test_build_platform_context_empty_hints_yields_empty() -> None:
    """Empty hints dict yields empty string."""
    alerts = [_make_alert("fw1", "freebsd", "510")]
    assert _build_platform_context(alerts, {}) == ""


def test_build_platform_context_two_platforms_two_blocks() -> None:
    """Two distinct platforms each produce a block separated by a blank line."""
    linux_hints: dict[str, Any] = {
        "freebsd": FREEBSD_HINTS["freebsd"],
        "linux": {
            "description": "Generic Linux hosts",
            "filesystem_notes": "procfs and sysfs expose volatile link counts.",
            "rules": {
                "5712": {
                    "paths": ["/proc"],
                    "hint": "Link count noise under /proc is expected on Linux.",
                }
            },
        },
    }
    alerts = [
        _make_alert("fw1", "freebsd", "510"),
        _make_agent_alert("srv1", "linux", "5712"),
    ]
    context = _build_platform_context(alerts, linux_hints)
    assert context.startswith("Platform context:\n")
    blocks = context[len("Platform context:\n"):].split("\n\n")
    assert len(blocks) == 2
    assert "freebsd — FreeBSD and derivatives" in blocks[0]
    assert "Rule 510 on /boot/efi" in blocks[0]
    assert "linux — Generic Linux hosts" in blocks[1]
    assert "Rule 5712 on /proc" in blocks[1]


def _make_agent_alert(agent_name: str, platform: str, rule_id: str) -> dict[str, Any]:
    """Build an alert without an os.name field for unknown-platform tests."""
    return {
        "_source": {
            "agent": {"name": agent_name, "os": {"platform": platform}},
            "rule": {"id": rule_id, "description": "Some event"},
        }
    }


def test_build_platform_context_null_source_yields_empty() -> None:
    """Alert with _source explicitly null yields empty string."""
    alerts = [{"_source": None}]
    assert _build_platform_context(alerts, FREEBSD_HINTS) == ""


def test_build_platform_context_null_agent_yields_empty() -> None:
    """Alert with agent explicitly null yields empty string."""
    alerts = [
        {
            "_source": {
                "agent": None,
                "rule": {"id": "510", "description": "FIM event"},
            }
        }
    ]
    assert _build_platform_context(alerts, FREEBSD_HINTS) == ""


def test_build_platform_context_null_os_yields_empty() -> None:
    """Alert with agent.os explicitly null yields empty string."""
    alerts = [
        {
            "_source": {
                "agent": {"name": "fw1", "os": None},
                "rule": {"id": "510", "description": "FIM event"},
            }
        }
    ]
    assert _build_platform_context(alerts, FREEBSD_HINTS) == ""


def test_build_platform_context_null_platform_yields_empty() -> None:
    """Alert with agent.os.platform explicitly null yields empty string."""
    alerts = [
        {
            "_source": {
                "agent": {"name": "fw1", "os": {"platform": None}},
                "rule": {"id": "510", "description": "FIM event"},
            }
        }
    ]
    assert _build_platform_context(alerts, FREEBSD_HINTS) == ""


def test_build_platform_context_null_rule_skipped() -> None:
    """Alert with rule null is skipped; valid alert still yields rule hint block."""
    alerts = [
        {"_source": {"agent": {"name": "fw1"}, "rule": None}},
        _make_alert("fw1", "freebsd", "510"),
    ]
    context = _build_platform_context(alerts, FREEBSD_HINTS)
    assert context != ""
    assert FREEBSD_HINT in context


def test_build_platform_context_mixed_nulls_with_valid_freebsd() -> None:
    """Batch mixing all null variants with one valid alert yields full block."""
    alerts = [
        {"_source": None},
        {
            "_source": {
                "agent": None,
                "rule": {"id": "510", "description": "FIM event"},
            }
        },
        {
            "_source": {
                "agent": {"name": "fw1", "os": None},
                "rule": {"id": "510", "description": "FIM event"},
            }
        },
        {
            "_source": {
                "agent": {"name": "fw1", "os": {"platform": None}},
                "rule": {"id": "510", "description": "FIM event"},
            }
        },
        {"_source": {"agent": {"name": "fw1"}, "rule": None}},
        _make_alert("fw1", "freebsd", "510"),
    ]
    context = _build_platform_context(alerts, FREEBSD_HINTS)
    assert context.startswith("Platform context:\n")
    assert "Rule 510 on /boot/efi" in context
    assert FREEBSD_HINT in context
    assert "FAT32 (EFI partition) does not implement Unix hard link counts." in context


def test_build_platform_context_null_agent_name_renders_unknown() -> None:
    """Null agent.name renders as 'unknown' rather than the literal None."""
    alerts = [
        {
            "_source": {
                "agent": {
                    "name": None,
                    "os": {"platform": "freebsd", "name": "FreeBSD"},
                },
                "rule": {"id": "510", "description": "FIM event"},
            }
        }
    ]
    context = _build_platform_context(alerts, FREEBSD_HINTS)
    assert context.startswith("Platform context:\n")
    assert "- Agent: unknown (freebsd" in context
    assert "Agent: None" not in context
    assert "FAT32 (EFI partition) does not implement Unix hard link counts." in context
    assert "Rule 510 on /boot/efi" in context


def test_build_platform_context_null_rule_id_does_not_match_None_hint() -> None:
    """Null rule.id is skipped and never matches a hint keyed 'None'."""
    hints: dict[str, Any] = {
        "freebsd": {
            "description": FREEBSD_HINTS["freebsd"]["description"],
            "filesystem_notes": FREEBSD_HINTS["freebsd"]["filesystem_notes"],
            "rules": {
                **FREEBSD_HINTS["freebsd"]["rules"],
                "None": {
                    "paths": ["/var/log/null-id.log"],
                    "hint": "should-never-appear-in-output",
                },
            },
        }
    }
    alerts = [
        {
            "_source": {
                "agent": {
                    "name": "fw1",
                    "os": {"platform": "freebsd", "name": "FreeBSD"},
                },
                "rule": {"id": None, "description": "FIM event"},
            }
        }
    ]
    context = _build_platform_context(alerts, hints)
    assert context != ""
    assert "should-never-appear-in-output" not in context
    assert "Rule None" not in context


# --- platform agents map (Build 1d) ---


def test_build_platform_context_falls_back_to_agents_map() -> None:
    """Missing agent.os.platform falls back to the agent-name map."""
    alerts = [
        {
            "_source": {
                "agent": {"name": "fw1"},
                "rule": {"id": "510", "description": "FIM event"},
            }
        }
    ]
    platform_agents = {"fw1": {"platform": "freebsd", "vendor": "OPNsense"}}
    context = _build_platform_context(alerts, FREEBSD_HINTS, platform_agents)
    assert context.startswith("Platform context:\n")
    assert "- Agent: fw1 (freebsd — OPNsense)" in context
    assert "Rule 510 on /boot/efi" in context


def test_load_platform_agents_missing_file_logs_debug(
    tmp_path: Path, caplog: Any
) -> None:
    """Missing agents file returns {} and logs once at DEBUG."""
    caplog.set_level(logging.DEBUG, logger="ravensight.analyser")
    missing = str(tmp_path / "does_not_exist.json")
    result = _load_platform_agents(missing)
    assert result == {}
    assert any(
        "Platform agents file not found" in rec.message for rec in caplog.records
    )


def test_load_platform_agents_malformed_entries_skipped(
    tmp_path: Path, caplog: Any
) -> None:
    """Non-dict values and entries missing platform/vendor are skipped."""
    caplog.set_level(logging.DEBUG, logger="ravensight.analyser")
    agents_file = tmp_path / "agents.json"
    agents_file.write_text(
        json.dumps(
            {
                "fw1": {"platform": "freebsd"},
                "fw2": "not a dict",
                "fw3": {"platform": "freebsd", "vendor": "OPNsense"},
            }
        ),
        encoding="utf-8",
    )
    result = _load_platform_agents(str(agents_file))
    assert result == {"fw3": {"platform": "freebsd", "vendor": "OPNsense"}}
    assert any(
        "is not a dict" in rec.message for rec in caplog.records
    )
    assert any(
        "missing platform/vendor" in rec.message for rec in caplog.records
    )


def test_load_platform_agents_lowercase_key_resolves_opnsense(
    tmp_path: Path,
) -> None:
    """A JSON key 'OPNsense' resolves an alert agent named 'opnsense'."""
    agents_file = tmp_path / "agents.json"
    agents_file.write_text(
        json.dumps({"OPNsense": {"platform": "freebsd", "vendor": "OPNsense"}}),
        encoding="utf-8",
    )
    result = _load_platform_agents(str(agents_file))
    assert result == {"opnsense": {"platform": "freebsd", "vendor": "OPNsense"}}
    alerts = [
        {
            "_source": {
                "agent": {"name": "opnsense"},
                "rule": {"id": "510", "description": "FIM event"},
            }
        }
    ]
    context = _build_platform_context(alerts, FREEBSD_HINTS, result)
    assert "- Agent: opnsense (freebsd" in context


def test_load_platform_agents_duplicate_casefold_logs_warning(
    tmp_path: Path, caplog: Any
) -> None:
    """A second key that casefolds to an existing one is dropped with a warning."""
    caplog.set_level(logging.WARNING, logger="ravensight.analyser")
    agents_file = tmp_path / "agents.json"
    agents_file.write_text(
        json.dumps(
            {
                "OPNsense": {"platform": "freebsd", "vendor": "OPNsense"},
                "OPNSense": {"platform": "linux", "vendor": "Other"},
            }
        ),
        encoding="utf-8",
    )
    result = _load_platform_agents(str(agents_file))
    assert result == {"opnsense": {"platform": "freebsd", "vendor": "OPNsense"}}
    assert any(
        "Duplicate platform agents key after casefolding" in rec.message
        and "OPNSense" in rec.message
        for rec in caplog.records
    )


def test_build_host_facts_block_preserves_alert_casing() -> None:
    """Host facts lookup casefolds the key but prints the alert's own casing."""
    clusters = [
        {
            "id": "C1",
            "type": "rule",
            "description": "FW event",
            "hosts": ["OPNsense"],
        }
    ]
    platform_agents = {"opnsense": {"platform": "freebsd", "vendor": "OPNsense"}}
    block = _build_host_facts_block(clusters, platform_agents)
    assert "- OPNsense: OPNsense (freebsd)." in block


# --- vendor name rewrite (Build 2a) ---


def _cluster_for_rewrite(hosts: list[str], description: str) -> dict[str, Any]:
    """Build a minimal cluster dict for vendor rewrite tests."""
    return {
        "id": "C1",
        "type": "rule",
        "description": description,
        "hosts": hosts,
    }


def test_rewrite_vendor_name_positive_control() -> None:
    """A cluster with one mapped host rewrites vendor names to the mapped vendor."""
    clusters = [
        _cluster_for_rewrite(
            ["fw-a"],
            "PFONTEND pfSense firewall blocks events from same source.",
        )
    ]
    platform_agents = {"fw-a": {"platform": "freebsd", "vendor": "OPNsense"}}
    platform_hints = {
        "freebsd": {"description": "FreeBSD", "vendors": ["OPNsense", "pfSense"]}
    }
    _rewrite_cluster_vendor_names(clusters, platform_agents, platform_hints)
    assert clusters[0]["description"] == (
        "PFONTEND OPNsense firewall blocks events from same source."
    )
    assert "pfSense" not in clusters[0]["description"]


def test_rewrite_vendor_name_case_variants() -> None:
    """Vendor candidates are replaced case-insensitively with word boundaries."""
    for desc_in, desc_out in (
        ("PFSENSE firewall", "OPNsense firewall"),
        ("pfsense firewall", "OPNsense firewall"),
    ):
        clusters = [_cluster_for_rewrite(["fw-a"], desc_in)]
        platform_agents = {"fw-a": {"platform": "freebsd", "vendor": "OPNsense"}}
        platform_hints = {
            "freebsd": {"description": "FreeBSD", "vendors": ["OPNsense", "pfSense"]}
        }
        _rewrite_cluster_vendor_names(clusters, platform_agents, platform_hints)
        assert clusters[0]["description"] == desc_out


def test_rewrite_vendor_name_unmapped_host_unchanged() -> None:
    """A cluster with an unmapped host is left untouched."""
    clusters = [_cluster_for_rewrite(["fw-x"], "pfSense firewall")]
    platform_agents = {"fw-a": {"platform": "freebsd", "vendor": "OPNsense"}}
    platform_hints = {
        "freebsd": {"description": "FreeBSD", "vendors": ["OPNsense", "pfSense"]}
    }
    _rewrite_cluster_vendor_names(clusters, platform_agents, platform_hints)
    assert clusters[0]["description"] == "pfSense firewall"


def test_rewrite_vendor_name_mixed_vendors_unchanged() -> None:
    """A cluster whose hosts map to different vendors is left untouched."""
    clusters = [_cluster_for_rewrite(["fw-a", "fw-b"], "pfSense firewall")]
    platform_agents = {
        "fw-a": {"platform": "freebsd", "vendor": "OPNsense"},
        "fw-b": {"platform": "freebsd", "vendor": "pfSense"},
    }
    platform_hints = {
        "freebsd": {"description": "FreeBSD", "vendors": ["OPNsense", "pfSense"]}
    }
    _rewrite_cluster_vendor_names(clusters, platform_agents, platform_hints)
    assert clusters[0]["description"] == "pfSense firewall"


def test_rewrite_vendor_name_no_vendors_key_unchanged() -> None:
    """A hint entry without a vendors key leaves descriptions untouched."""
    clusters = [_cluster_for_rewrite(["fw-a"], "pfSense firewall")]
    platform_agents = {"fw-a": {"platform": "freebsd", "vendor": "OPNsense"}}
    platform_hints = {"freebsd": {"description": "FreeBSD"}}
    _rewrite_cluster_vendor_names(clusters, platform_agents, platform_hints)
    assert clusters[0]["description"] == "pfSense firewall"


def test_rewrite_vendor_name_candidate_equals_vendor_skipped() -> None:
    """A candidate identical to the mapped vendor is skipped, not self-replaced."""
    clusters = [_cluster_for_rewrite(["fw-a"], "OPNsense firewall")]
    platform_agents = {"fw-a": {"platform": "freebsd", "vendor": "OPNsense"}}
    platform_hints = {
        "freebsd": {"description": "FreeBSD", "vendors": ["OPNsense", "pfSense"]}
    }
    _rewrite_cluster_vendor_names(clusters, platform_agents, platform_hints)
    assert clusters[0]["description"] == "OPNsense firewall"


def test_rewrite_vendor_name_empty_vendor_treated_as_unmapped() -> None:
    """A mapped host with an empty vendor string is treated as unmapped."""
    clusters = [_cluster_for_rewrite(["fw-a"], "pfSense firewall")]
    platform_agents = {"fw-a": {"platform": "freebsd", "vendor": ""}}
    platform_hints = {
        "freebsd": {"description": "FreeBSD", "vendors": ["OPNsense", "pfSense"]}
    }
    _rewrite_cluster_vendor_names(clusters, platform_agents, platform_hints)
    assert clusters[0]["description"] == "pfSense firewall"


def test_build_platform_context_uses_mapped_vendor_name() -> None:
    """The platform context agent line shows the mapped vendor when available."""
    alerts = [
        {
            "_source": {
                "agent": {"name": "fw-a"},
                "rule": {"id": "510", "description": "FIM event"},
            }
        }
    ]
    platform_agents = {"fw-a": {"platform": "freebsd", "vendor": "OPNsense"}}
    context = _build_platform_context(alerts, FREEBSD_HINTS, platform_agents)
    assert "- Agent: fw-a (freebsd — OPNsense)" in context


# --- ASD context truncation (Build 2a) ---


def test_build_asd_context_collapses_before_truncating() -> None:
    """Newlines collapse before the 120-character truncation is applied."""
    asd_data = {
        "ism": [
            {
                "id": "ISM-1175",
                "category": "Patching",
                "description": "a\n" + "b " * 80,
            }
        ]
    }
    context = _build_asd_context(asd_data)
    control_line = next(line for line in context.splitlines() if line.startswith("  ISM-1175"))
    assert "\n" not in control_line
    assert "  ISM-1175: a b b" in control_line
    assert len(control_line.split(": ", 1)[1]) <= 120


# --- data file parity ---


def test_platform_hints_defaults_match_source() -> None:
    """The defaults copy of platform hints is byte-identical to the source."""
    source = Path("data/platform_hints.json").read_bytes()
    default = Path("data/defaults/platform_hints.json").read_bytes()
    assert source == default


def test_platform_context_non_string_agent_name_does_not_crash() -> None:
    """A non-string agent name keeps the hints description and does not raise."""
    alerts = [
        {
            "_source": {
                "agent": {"name": 7, "os": {"platform": "freebsd"}},
                "rule": {"id": "510", "description": "x"},
            }
        }
    ]
    hints = {"freebsd": {"description": "FreeBSD", "filesystem_notes": "note"}}
    agents = {"fw-a": {"platform": "freebsd", "vendor": "OPNsense"}}
    context = _build_platform_context(alerts, hints, platform_agents=agents)
    assert "- Agent: 7 (freebsd — FreeBSD)" in context


# --- ASD Essential Eight context (Build 2b) ---


def test_build_asd_context_omits_essential_eight_block_with_ism() -> None:
    """With both essential_eight and ism present, only the ISM block is rendered."""
    asd_data: dict[str, Any] = {
        "essential_eight": [
            {
                "strategy": "Patch applications",
                "controls": [
                    {"id": "ISM-1690", "levels": [1, 2, 3], "description": "x"},
                    {"id": "ISM-1691", "levels": [1, 2], "description": "y"},
                ],
            },
        ],
        "ism": [
            {"id": "ISM-1175", "category": "Patching", "description": "A control."}
        ],
    }
    context = _build_asd_context(asd_data)
    assert context.startswith("Relevant ISM Controls:")
    assert "Patch applications" not in context
    assert "Essential Eight" not in context
    assert "ISM-1175" in context


# The old test_build_asd_context_single_level_no_range was deleted: its only
# assertion was on a strategy line format, and the single-ML case is covered
# by test_build_asd_context_omits_essential_eight_block_with_ism above.


# The old test_build_asd_context_empty_strategy_controls_omitted was deleted:
# "Patch applications" not in context is now trivially true for any input,
# because the function never emits strategy names at all.


def test_build_asd_context_returns_empty_when_only_essential_eight() -> None:
    """Schema 2 data with essential_eight but no ISM controls yields an empty string."""
    asd_data: dict[str, Any] = {
        "essential_eight": [
            {
                "strategy": "Patch applications",
                "controls": [
                    {"id": "ISM-1690", "levels": [1, 2, 3], "description": "x"},
                ],
            },
        ],
        "ism": [],
    }
    assert _build_asd_context(asd_data) == ""


def test_build_asd_context_missing_essential_eight_omits_block() -> None:
    """ASD data without essential_eight renders only the ISM block."""
    asd_data: dict[str, Any] = {
        "ism": [
            {"id": "ISM-1175", "category": "Patching", "description": "A control."}
        ],
    }
    context = _build_asd_context(asd_data)
    assert "Essential Eight Strategies:" not in context
    assert "ISM-1175" in context


def test_build_asd_context_multi_ism_controls_in_multiple_categories() -> None:
    """Category headers are emitted exactly once each, in grouping order."""
    asd_data: dict[str, Any] = {
        "essential_eight": [],
        "ism": [
            {"id": "ISM-1175", "category": "Patching", "description": "First."},
            {"id": "ISM-1234", "category": "Logging", "description": "Second."},
            {"id": "ISM-5678", "category": "Logging", "description": "Third."},
        ],
    }
    context = _build_asd_context(asd_data)
    assert context.startswith("Relevant ISM Controls:")
    assert context.count("Patching:") == 1
    assert context.count("Logging:") == 1
    assert context.index("Patching:") < context.index("Logging:")
    for control_id in ("ISM-1175", "ISM-1234", "ISM-5678"):
        assert context.count(control_id) == 1


def test_load_asd_data_schema_one_logs_warning(tmp_path: Path, caplog: Any) -> None:
    """A schema 1 file is rejected with a warning and returns {}."""
    caplog.set_level(logging.WARNING, logger="ravensight.analyser")
    path = tmp_path / "asd.json"
    path.write_text(json.dumps({"schema": 1, "essential_eight": []}), encoding="utf-8")
    result = _load_asd_data(str(path))
    assert result == {}
    assert "older format" in caplog.text


def test_load_asd_data_missing_schema_logs_warning(tmp_path: Path, caplog: Any) -> None:
    """A file without a schema key is rejected with a warning."""
    caplog.set_level(logging.WARNING, logger="ravensight.analyser")
    path = tmp_path / "asd.json"
    path.write_text(json.dumps({"essential_eight": []}), encoding="utf-8")
    result = _load_asd_data(str(path))
    assert result == {}
    assert "older format" in caplog.text


def test_load_asd_data_non_dict_root_returns_empty(tmp_path: Path, caplog: Any) -> None:
    """A JSON file whose root is not a dict is rejected with a warning."""
    caplog.set_level(logging.WARNING, logger="ravensight.analyser")
    path = tmp_path / "asd.json"
    path.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    result = _load_asd_data(str(path))
    assert result == {}
    assert "older format" in caplog.text


def test_load_asd_data_schema_two_loads(tmp_path: Path, caplog: Any) -> None:
    """A schema 2 file loads and returns its contents."""
    caplog.set_level(logging.WARNING, logger="ravensight.analyser")
    data: dict[str, Any] = {"schema": 2, "essential_eight": [], "ism": []}
    path = tmp_path / "asd.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    result = _load_asd_data(str(path))
    assert result == data
    assert "older format" not in caplog.text
