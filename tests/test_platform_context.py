"""
Tests for platform hints loading and platform context block construction
in ravensight.analyser.
"""

import json
import logging
from pathlib import Path
from typing import Any

from ravensight.analyser import (
    _build_platform_context,
    _load_platform_agents,
    _load_platform_hints,
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
    assert "- Agent: fw1 (freebsd — FreeBSD and derivatives" in context
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
