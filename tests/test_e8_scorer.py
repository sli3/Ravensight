"""
Tests for Essential Eight related-control scoring (Build 2b).

The new score_findings returns 'Not assessed' status with related findings and
controls; it never produces pass/fail maturity verdicts.
"""

import json
import logging
from pathlib import Path
from typing import Any

from ravensight.e8_scorer import (
    MAX_FINDING_POINTERS,
    _stem,
    load_attestation,
    map_findings_to_controls,
    match_ism_controls,
    score_findings,
)


def _finding(**overrides: Any) -> dict[str, Any]:
    """Build a cluster-shaped dict finding."""
    finding: dict[str, Any] = {
        "id": "C1",
        "type": "rule",
        "description": "Routine log noise",
        "rule_ids": ["1002"],
        "hosts": ["host-1"],
        "count": 3,
        "max_level": 3,
        "severity": "Low",
        "first_seen": "",
        "last_seen": "",
        "cves": [],
        "package": None,
        "narrative": "",
        "recommendation": "",
    }
    finding.update(overrides)
    return finding


def _asd_data() -> dict[str, Any]:
    """Build ASD data with one strategy and two controls."""
    return {
        "essential_eight": [
            {
                "strategy": "Application control",
                "controls": [
                    {
                        "id": "ISM-1656",
                        "levels": [1, 2, 3],
                        "description": "Unauthorised applications execute on systems",
                    },
                    {
                        "id": "ISM-1657",
                        "levels": [2, 3],
                        "description": "Application control systems execute policy",
                    },
                ],
            },
        ],
        "ism": [],
    }


def test_status_is_always_not_assessed() -> None:
    """Every strategy is reported as Not assessed."""
    result = score_findings([_finding()], _asd_data())
    assert result == {
        "Application control": {
            "status": "Not assessed",
            "related_findings": [],
            "related_controls": [],
        }
    }


def test_one_shared_keyword_does_not_relate() -> None:
    """A single overlapping keyword is below the threshold."""
    finding = _finding(narrative="Unauthorised access detected")
    result = score_findings([finding], _asd_data())
    assert result["Application control"]["related_controls"] == []


def test_two_shared_keywords_no_longer_relate() -> None:
    """Two overlapping keywords are below the threshold of three."""
    finding = _finding(narrative="Unauthorised applications running")
    result = score_findings([finding], _asd_data())
    assert result["Application control"]["related_controls"] == []


def test_three_shared_keywords_relate() -> None:
    """Three overlapping keywords meet the minimum match score."""
    finding = _finding(narrative="Unauthorised applications execute on host-1")
    result = score_findings([finding], _asd_data())
    assert result["Application control"]["related_findings"] == ["C1"]
    assert result["Application control"]["related_controls"] == [
        {"id": "ISM-1656", "levels": [1, 2, 3]}
    ]


def test_related_controls_capped_at_three() -> None:
    """At most three related controls are returned per strategy."""
    asd_data: dict[str, Any] = {
        "essential_eight": [
            {
                "strategy": "Application control",
                "controls": [
                    {"id": f"ISM-{1656 + i}", "levels": [1], "description": "Unauthorised applications execute"}
                    for i in range(5)
                ],
            },
        ],
        "ism": [],
    }
    finding = _finding(narrative="Unauthorised applications execute on host-1")
    result = score_findings([finding], asd_data)
    assert len(result["Application control"]["related_controls"]) == 3


def test_blocklist_applied_casefold_key() -> None:
    """Blocked keywords from a title-cased override key apply to lower-case strategy."""
    asd_data = _asd_data()
    # Three keywords relate at the threshold; blocking one leaves two,
    # which is below the threshold of three.
    finding = _finding(narrative="Unauthorised applications execute detected")
    overrides = {
        "strategy_blocklist": {
            "Application Control": ["applications"],
        }
    }
    result = score_findings([finding], asd_data, overrides_path=None)
    assert result["Application control"]["related_controls"] != []

    # The override is constructed inline because _load_overrides reads a file.
    import json
    import tempfile
    from pathlib import Path
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(overrides, f)
        path = f.name
    try:
        result = score_findings([finding], asd_data, overrides_path=path)
        assert result["Application control"]["related_controls"] == []
    finally:
        Path(path).unlink()


def test_narrative_only_keywords_count() -> None:
    """Keywords appearing only in the narrative still contribute to matching
    (three shared keywords reach the MIN_E8_MATCH_SCORE threshold of 3)."""
    finding = _finding(narrative="Unauthorised applications execute on host-1")
    result = score_findings([finding], _asd_data())
    assert result["Application control"]["related_findings"] == ["C1"]


def test_non_string_finding_id_skipped_safely() -> None:
    """Findings with a non-string id do not break relatedness collection."""
    findings: list[dict | str] = [
        _finding(id=123, narrative="Unauthorised applications execute"),
        _finding(id="C2", narrative="Unauthorised applications execute"),
    ]
    result = score_findings(findings, _asd_data())
    assert result["Application control"]["related_findings"] == ["C2"]


def test_string_finding_converted_without_error() -> None:
    """A string finding is converted and can relate to controls."""
    result = score_findings(
        ["Unauthorised applications execute on host-1"],
        _asd_data(),
    )
    assert result["Application control"]["related_controls"] == [
        {"id": "ISM-1656", "levels": [1, 2, 3]}
    ]


def test_empty_asd_data_returns_empty() -> None:
    """Missing essential_eight yields an empty dict."""
    assert score_findings([_finding()], {}) == {}


def test_empty_essential_eight_returns_empty() -> None:
    """An empty essential_eight list yields an empty dict."""
    assert score_findings([_finding()], {"essential_eight": []}) == {}


def test_related_findings_deduplicated_and_in_input_order() -> None:
    """Related findings follow input order even when the best-ranked control
    matches a later finding; a control-major loop would emit rank order."""
    asd_data: dict[str, Any] = {
        "essential_eight": [
            {
                "strategy": "Application control",
                "controls": [
                    {
                        "id": "ISM-A",
                        "levels": [1],
                        "description": "Patch verification scanning routine",
                    },
                    {
                        "id": "ISM-B",
                        "levels": [2],
                        "description": "MFA token replay detection coverage",
                    },
                ],
            },
        ],
        "ism": [],
    }
    first = _finding(id="C1", narrative="Patch verification routine ran overnight")
    second = _finding(id="C2", narrative="MFA token replay detection coverage reviewed")
    result = score_findings([first, second], asd_data)
    assert result["Application control"]["related_findings"] == ["C1", "C2"]


def test_strategy_name_keywords_count_toward_match() -> None:
    """A control in a strategy named 'Multi-factor authentication' relates to a
    finding whose text mentions multi-factor authentication."""
    asd_data: dict[str, Any] = {
        "essential_eight": [
            {
                "strategy": "Multi-factor authentication",
                "controls": [
                    {
                        "id": "ISM-MFA",
                        "levels": [1, 2, 3],
                        "description": "Multi-factor authentication is used to verify users",
                    },
                ],
            },
        ],
        "ism": [],
    }
    finding = _finding(
        id="C9",
        narrative="Multi-factor authentication rolled out and users enrolled",
    )
    result = score_findings([finding], asd_data)
    assert result["Multi-factor authentication"]["related_findings"] == ["C9"]


def test_overrides_with_malformed_blocklist_returns_empty(
    tmp_path: Path, caplog: Any
) -> None:
    """A non-dict strategy_blocklist logs a warning and scoring still works."""
    from ravensight.e8_scorer import _load_overrides

    overrides_file = tmp_path / "e8_keyword_overrides.json"
    overrides_file.write_text(
        json.dumps({"strategy_blocklist": ["x", "y"]}), encoding="utf-8"
    )

    with caplog.at_level(logging.WARNING, logger="ravensight.e8_scorer"):
        blocklist = _load_overrides(str(overrides_file))
    assert blocklist == {}
    assert "strategy_blocklist" in caplog.text

    result = score_findings([_finding()], _asd_data(), overrides_path=str(overrides_file))
    assert result["Application control"]["status"] == "Not assessed"


def test_overrides_with_null_value_skipped_with_warning(
    tmp_path: Path, caplog: Any
) -> None:
    """A null (non-list) blocklist value is skipped with a warning."""
    from ravensight.e8_scorer import _load_overrides

    overrides_file = tmp_path / "e8_keyword_overrides.json"
    overrides_file.write_text(
        json.dumps({
            "strategy_blocklist": {
                "Application control": ["unauthorised"],
                "Bad": None,
            }
        }),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="ravensight.e8_scorer"):
        blocklist = _load_overrides(str(overrides_file))
    assert blocklist == {"application control": {"unauthorised"}}
    assert "malformed" in caplog.text

    result = score_findings([_finding()], _asd_data(), overrides_path=str(overrides_file))
    assert result["Application control"]["status"] == "Not assessed"


def test_overrides_with_non_string_items_in_value_skipped_with_warning(
    tmp_path: Path, caplog: Any
) -> None:
    """A blocklist value containing non-string items is skipped with a warning."""
    from ravensight.e8_scorer import _load_overrides

    overrides_file = tmp_path / "e8_keyword_overrides.json"
    overrides_file.write_text(
        json.dumps({
            "strategy_blocklist": {
                "Application control": ["unauthorised"],
                "Bad": [["nested"]],
            }
        }),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="ravensight.e8_scorer"):
        blocklist = _load_overrides(str(overrides_file))
    assert blocklist == {"application control": {"unauthorised"}}
    assert "malformed" in caplog.text

    result = score_findings([_finding()], _asd_data(), overrides_path=str(overrides_file))
    assert result["Application control"]["status"] == "Not assessed"


def test_strategy_with_no_controls_returns_empty_cells() -> None:
    """A strategy whose controls are all drift-skipped still appears with empty cells."""
    asd_data: dict[str, Any] = {
        "essential_eight": [
            {
                "strategy": "Patch applications",
                "controls": [],
            },
        ],
        "ism": [],
    }
    result = score_findings([_finding()], asd_data)
    assert result == {
        "Patch applications": {
            "status": "Not assessed",
            "related_findings": [],
            "related_controls": [],
        }
    }


def test_three_shared_generic_words_do_not_relate() -> None:
    """Even three shared E8_GENERIC_WORDS tokens never count toward matching."""
    asd_data: dict[str, Any] = {
        "essential_eight": [
            {
                "strategy": "Application control",
                "controls": [
                    {
                        "id": "ISM-GEN",
                        "levels": [1],
                        "description": "system services changed access content events",
                    },
                ],
            },
        ],
        "ism": [],
    }
    finding = _finding(
        narrative="system services changed access content events local required only"
    )
    result = score_findings([finding], asd_data)
    assert result["Application control"]["related_controls"] == []
    assert result["Application control"]["related_findings"] == []


def test_regression_benign_findings_do_not_relate() -> None:
    """Benign live-run findings produce no related controls or findings after tuning."""
    asd_data: dict[str, Any] = {
        "essential_eight": [
            {
                "strategy": "Access control",
                "controls": [
                    {
                        "id": "ISM-AC",
                        "levels": [1, 2, 3],
                        "description": (
                            "Privileged access to systems and their resources is "
                            "limited to only what is required for users to "
                            "undertake their duties or functions"
                        ),
                    },
                ],
            },
        ],
        "ism": [],
    }
    findings: list[dict[str, Any] | str] = [
        _finding(
            id="C1",
            description="FIM event",
            narrative="only inode metadata changed",
            recommendation="No action required",
        ),
        _finding(id="C2", narrative="local-only listener, benign local service"),
        _finding(id="C3", narrative="credential-access interpretation does not fit the events"),
    ]
    result = score_findings(findings, asd_data)
    for row in result.values():
        assert row["related_controls"] == []
        assert row["related_findings"] == []


def test_match_ism_controls_ignores_generic_words() -> None:
    """The ISM matcher subtracts E8_GENERIC_WORDS; generic words alone do not match."""
    asd_data: dict[str, Any] = {
        "ism": [
            {
                "id": "ISM-LOG",
                "category": "Logging",
                "description": "Access to systems is logged centrally",
            },
        ],
    }
    generic_only = _finding(description="systems access service", recommendation="")
    one_specific = _finding(description="systems access logged", recommendation="")
    two_specific = _finding(description="access logged centrally", recommendation="")
    assert match_ism_controls([generic_only], asd_data) == []
    assert match_ism_controls([one_specific], asd_data) == []
    assert [c["id"] for c in match_ism_controls([two_specific], asd_data)] == ["ISM-LOG"]


def test_match_ism_controls_ignores_narrative() -> None:
    """Only description and recommendation are matched; the LLM narrative is not."""
    asd_data: dict[str, Any] = {
        "ism": [
            {
                "id": "ISM-FW",
                "category": "Networking",
                "description": "Firewall blocks hostile traffic",
            },
        ],
    }
    narrative_only = _finding(
        description="Unrelated thing", recommendation="", narrative="firewall blocks hostile traffic"
    )
    described = _finding(
        description="Firewall blocks hostile sources", recommendation="", narrative=""
    )
    assert match_ism_controls([narrative_only], asd_data) == []
    assert [c["id"] for c in match_ism_controls([described], asd_data)] == ["ISM-FW"]


def test_match_ism_controls_requires_overlap_within_one_finding() -> None:
    """Keywords spread across separate findings do not add up to an ISM match."""
    asd_data: dict[str, Any] = {
        "ism": [
            {
                "id": "ISM-FW",
                "category": "Networking",
                "description": "Firewall blocks hostile traffic",
            },
        ],
    }
    split: list[dict | str] = [_finding(description="firewall rules"), _finding(description="hostile sources")]
    together: list[dict | str] = [_finding(description="firewall blocks hostile sources")]
    assert match_ism_controls(split, asd_data) == []
    assert [c["id"] for c in match_ism_controls(together, asd_data)] == ["ISM-FW"]


def test_stray_rule_group_key_has_no_effect() -> None:
    """A rule_group key on a finding is ignored by both scoring and ISM matching."""
    plain = _finding(narrative="Unauthorised")
    stray = _finding(narrative="Unauthorised", rule_group="applications execute")
    assert score_findings([stray], _asd_data()) == score_findings([plain], _asd_data())
    assert score_findings([stray], _asd_data())["Application control"]["related_controls"] == []

    ism_data: dict[str, Any] = {
        "ism": [
            {
                "id": "ISM-ZOO",
                "category": "Wildlife",
                "description": "Zebra quokka enclosures",
            },
        ],
    }
    # The default finding shares no keywords with ISM-ZOO, so only a read of
    # rule_group could produce a match.
    unrelated = _finding()
    stray_ism = _finding(rule_group="zebra quokka enclosures wildlife")
    assert match_ism_controls([unrelated], ism_data) == []
    assert match_ism_controls([stray_ism], ism_data) == []


# --- Per-finding pointers (report clarity Phase 1) ---


def _ism_asd(*controls: dict[str, str]) -> dict[str, Any]:
    """Build ASD data holding only ISM controls."""
    return {"essential_eight": [], "ism": list(controls)}


def test_map_findings_ism_pointer_lists_shared_words() -> None:
    """An ISM pointer records the finding and the words that matched."""
    asd_data = _ism_asd(
        {
            "id": "ISM-FW",
            "category": "Gateway logging",
            "description": "Firewall blocks hostile traffic at gateways",
        }
    )
    finding = _finding(description="Firewall blocks hostile sources", recommendation="")
    result = map_findings_to_controls([finding], asd_data)
    assert [row["id"] for row in result] == ["C1"]
    assert result[0]["ism"] == [
        {"id": "ISM-FW", "category": "Gateway logging", "shared": ["blocks", "firewall", "hostile"]}
    ]
    assert result[0]["e8"] == []


def test_map_findings_ism_ignores_narrative() -> None:
    """The narrative alone never creates an ISM pointer."""
    asd_data = _ism_asd(
        {"id": "ISM-FW", "category": "Gateway logging", "description": "Firewall blocks hostile traffic"}
    )
    finding = _finding(
        description="Unrelated thing", recommendation="", narrative="firewall blocks hostile traffic"
    )
    assert map_findings_to_controls([finding], asd_data)[0]["ism"] == []


def test_map_findings_caps_ism_pointers_best_first() -> None:
    """At most MAX_FINDING_POINTERS ISM controls are kept, best match first."""
    base = "alpha bravo charlie delta"
    controls = [
        {"id": f"ISM-{n}", "category": "Zulu", "description": base[: 5 * (n + 2)]}
        for n in range(5)
    ]
    finding = _finding(description=base, recommendation="")
    ism = map_findings_to_controls([finding], _ism_asd(*controls))[0]["ism"]
    assert len(ism) == MAX_FINDING_POINTERS
    counts = [len(item["shared"]) for item in ism]
    assert counts == sorted(counts, reverse=True)


def test_map_findings_skips_findings_without_an_id() -> None:
    """Legacy string findings have no id and produce no pointer rows."""
    asd_data = _ism_asd(
        {"id": "ISM-FW", "category": "Gateway logging", "description": "Firewall blocks hostile traffic"}
    )
    assert map_findings_to_controls(["Firewall blocks hostile traffic"], asd_data) == []


def test_map_findings_e8_agrees_with_score_findings() -> None:
    """E8 pointers list exactly the strategies whose related_findings include the finding."""
    finding = _finding(
        description="Unauthorised applications execute", recommendation="", narrative=""
    )
    scores = score_findings([finding], _asd_data())
    assert scores["Application control"]["related_findings"] == ["C1"]
    result = map_findings_to_controls([finding], _asd_data())
    assert result[0]["e8"] == [
        {"strategy": "Application control", "shared": ["applications", "execute", "unauthorised"]}
    ]


# --- Matching accuracy (report clarity Phase 1b) ---


def test_stemming_joins_common_word_forms() -> None:
    """patch, patches and patched share a stem; so do update, updated and updates."""
    assert _stem("patch") == _stem("patches") == _stem("patched")
    assert _stem("update") == _stem("updated") == _stem("updates")
    assert _stem("process") == _stem("processes")


def test_stemming_leaves_short_and_double_s_words_alone() -> None:
    """Short words and words ending in ss keep their final letters."""
    assert _stem("logs") == "logs"
    assert _stem("access") == "access"
    assert _stem("address") == "address"


def test_boilerplate_words_never_count_toward_a_match() -> None:
    """action, confirm, multiple and expected are generic and cannot create a pointer."""
    asd_data = _ism_asd(
        {"id": "ISM-BOILER", "category": "Action", "description": "Confirm multiple expected actions"}
    )
    finding = _finding(
        description="Multiple things", recommendation="No action required; confirm expected result"
    )
    assert map_findings_to_controls([finding], asd_data)[0]["ism"] == []


def test_than_is_a_stop_word_and_never_matches() -> None:
    """'than' is filler: it cannot make up the shared words behind a pointer."""
    asd_data = _ism_asd(
        {"id": "ISM-X", "category": "Zebra", "description": "Quokka rather than wombat"}
    )
    finding = _finding(description="Wombat sighting", recommendation="Better than nothing")
    assert map_findings_to_controls([finding], asd_data)[0]["ism"] == []


def test_inflected_words_now_match_across_finding_and_control() -> None:
    """A patched/updated finding reaches a control that says patches/updates."""
    asd_data = _ism_asd(
        {"id": "ISM-PATCH", "category": "Patch management", "description": "Patches and updates are applied"}
    )
    finding = _finding(
        description="Package vulnerable", recommendation="Updated to a patched version"
    )
    ism = map_findings_to_controls([finding], asd_data)[0]["ism"]
    assert [item["id"] for item in ism] == ["ISM-PATCH"]


def test_matched_on_shows_the_findings_own_words_not_stems() -> None:
    """Shared words are reported as written in the finding, never as clipped stems."""
    asd_data = _ism_asd(
        {"id": "ISM-PATCH", "category": "Patch management", "description": "Patches and updates are applied"}
    )
    finding = _finding(
        description="Package vulnerable", recommendation="Updated to a patched version"
    )
    shared = map_findings_to_controls([finding], asd_data)[0]["ism"][0]["shared"]
    assert shared == ["patched", "updated"]


def test_blocklist_applies_to_inflected_forms(tmp_path: Path) -> None:
    """A blocked word also blocks its inflected forms: 'block' stops 'blocks' and 'blocked'."""
    asd_data: dict[str, Any] = {
        "essential_eight": [
            {
                "strategy": "Application control",
                "controls": [
                    {"id": "ISM-1", "levels": [1], "description": "Blocks hostile unauthorised"},
                ],
            }
        ],
        "ism": [],
    }
    finding = _finding(
        description="Blocked hostile unauthorised", recommendation="", narrative=""
    )
    overrides_file = tmp_path / "overrides.json"
    overrides_file.write_text(
        json.dumps({"strategy_blocklist": {"Application control": ["block"]}})
    )
    without = score_findings([finding], asd_data)
    with_block = score_findings([finding], asd_data, overrides_path=str(overrides_file))
    assert [c["id"] for c in without["Application control"]["related_controls"]] == ["ISM-1"]
    assert with_block["Application control"]["related_controls"] == []


def test_map_findings_no_match_gives_empty_pointers() -> None:
    """A finding that matches nothing still appears, with empty lists."""
    result = map_findings_to_controls([_finding()], _asd_data())
    assert result == [{"id": "C1", "ism": [], "e8": []}]


# --- load_attestation ---

_NOT_ASSESSED: dict[str, Any] = {"status": "Not assessed", "level": None, "reason": ""}


def _attest_asd() -> dict[str, Any]:
    """Build a small ASD fixture holding the strategy names used by attestation tests."""
    return {
        "essential_eight": [
            {"strategy": "Application control", "controls": []},
            {"strategy": "Restrict Microsoft Office macros", "controls": []},
            {"strategy": "Regular backups", "controls": []},
        ],
        "ism": [],
    }


def _write_attestation(tmp_path: Path, content: Any) -> str:
    """Write content as JSON to a temporary attestation file and return its path."""
    path = tmp_path / "e8_attestation.json"
    path.write_text(json.dumps(content), encoding="utf-8")
    return str(path)


def _load(tmp_path: Path, content: Any, caplog: Any) -> dict[str, dict[str, Any]]:
    """Load an attestation file with warnings captured."""
    path = _write_attestation(tmp_path, content)
    with caplog.at_level(logging.WARNING, logger="ravensight.e8_scorer"):
        return load_attestation(path, _attest_asd())


def test_attestation_none_path_returns_defaults_silently(caplog: Any) -> None:
    """A None path returns all Not assessed with no warning."""
    with caplog.at_level(logging.WARNING, logger="ravensight.e8_scorer"):
        result = load_attestation(None, _attest_asd())
    assert result == {name: _NOT_ASSESSED for name in (
        "Application control", "Restrict Microsoft Office macros", "Regular backups"
    )}
    assert caplog.records == []


def test_attestation_missing_file_warns_once(tmp_path: Path, caplog: Any) -> None:
    """A missing file warns once and returns defaults."""
    with caplog.at_level(logging.WARNING, logger="ravensight.e8_scorer"):
        result = load_attestation(str(tmp_path / "absent.json"), _attest_asd())
    assert len(caplog.records) == 1
    assert all(v == _NOT_ASSESSED for v in result.values())


def test_attestation_malformed_json_warns_once(tmp_path: Path, caplog: Any) -> None:
    """Malformed JSON warns once and returns defaults."""
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="ravensight.e8_scorer"):
        result = load_attestation(str(path), _attest_asd())
    assert len(caplog.records) == 1
    assert all(v == _NOT_ASSESSED for v in result.values())


def test_attestation_non_utf8_file_warns_once(tmp_path: Path, caplog: Any) -> None:
    """A non-UTF-8 file warns once and returns defaults."""
    path = tmp_path / "latin1.json"
    path.write_bytes(b"\xff\xfe{}" + "é".encode("latin-1"))
    with caplog.at_level(logging.WARNING, logger="ravensight.e8_scorer"):
        result = load_attestation(str(path), _attest_asd())
    assert len(caplog.records) == 1
    assert all(v == _NOT_ASSESSED for v in result.values())


def test_attestation_non_object_root_warns_once(tmp_path: Path, caplog: Any) -> None:
    """A non-object root warns once and returns defaults."""
    result = _load(tmp_path, ["Application control"], caplog)
    assert len(caplog.records) == 1
    assert all(v == _NOT_ASSESSED for v in result.values())


def test_attestation_valid_attested_stores_int_level(tmp_path: Path, caplog: Any) -> None:
    """An Attested entry stores its level as an int."""
    result = _load(
        tmp_path,
        {"Application control": {"status": "Attested", "level": "ML2", "reason": "Audited"}},
        caplog,
    )
    assert result["Application control"] == {"status": "Attested", "level": 2, "reason": "Audited"}
    assert caplog.records == []


def test_attestation_not_applicable_ignores_level(tmp_path: Path, caplog: Any) -> None:
    """Not applicable stores level None, even if a level is given, without warning."""
    result = _load(
        tmp_path,
        {
            "Application control": {"status": "Not applicable", "reason": "No hosts"},
            "Regular backups": {"status": "Not applicable", "level": "ML3", "reason": "x"},
        },
        caplog,
    )
    assert result["Application control"] == {
        "status": "Not applicable", "level": None, "reason": "No hosts"
    }
    assert result["Regular backups"]["level"] is None
    assert caplog.records == []


def test_attestation_not_applicable_ignores_invalid_level(tmp_path: Path, caplog: Any) -> None:
    """Not applicable with an invalid level still loads with level None and no warning."""
    for bad in ["banana", 5]:
        caplog.clear()
        result = _load(
            tmp_path,
            {"Application control": {"status": "Not applicable", "level": bad, "reason": "x"}},
            caplog,
        )
        assert result["Application control"] == {
            "status": "Not applicable", "level": None, "reason": "x"
        }
        assert caplog.records == []


def test_attestation_level_is_case_insensitive(tmp_path: Path, caplog: Any) -> None:
    """A lower-case level such as ml2 is accepted."""
    result = _load(
        tmp_path,
        {"Application control": {"status": "Attested", "level": "ml2", "reason": ""}},
        caplog,
    )
    assert result["Application control"]["level"] == 2


def test_attestation_invalid_levels_are_skipped(tmp_path: Path, caplog: Any) -> None:
    """Invalid or missing levels leave the strategy Not assessed with one warning each."""
    bad_levels: list[Any] = ["ML0", "ML4", "banana", 1, True, None]
    for bad in bad_levels:
        caplog.clear()
        result = _load(
            tmp_path,
            {"Application control": {"status": "Attested", "level": bad, "reason": ""}},
            caplog,
        )
        assert result["Application control"] == _NOT_ASSESSED
        assert len(caplog.records) == 1
        assert "Application control" in caplog.text
    caplog.clear()
    result = _load(
        tmp_path, {"Application control": {"status": "Attested", "reason": ""}}, caplog
    )
    assert result["Application control"] == _NOT_ASSESSED
    assert len(caplog.records) == 1


def test_attestation_unknown_status_is_skipped(tmp_path: Path, caplog: Any) -> None:
    """An unknown status is skipped with a warning."""
    result = _load(
        tmp_path,
        {"Application control": {"status": "Passed", "level": "ML1", "reason": ""}},
        caplog,
    )
    assert result["Application control"] == _NOT_ASSESSED
    assert len(caplog.records) == 1


def test_attestation_status_match_is_exact(tmp_path: Path, caplog: Any) -> None:
    """Differently cased or spelled statuses are rejected as unknown."""
    for bad in ["attested", "ATTESTED", "not applicable"]:
        caplog.clear()
        result = _load(
            tmp_path,
            {"Application control": {"status": bad, "level": "ML1", "reason": ""}},
            caplog,
        )
        assert result["Application control"] == _NOT_ASSESSED
        assert len(caplog.records) == 1


def test_attestation_unknown_strategy_is_skipped(tmp_path: Path, caplog: Any) -> None:
    """An unknown strategy name is warned about and not added."""
    result = _load(
        tmp_path,
        {"application control": {"status": "Attested", "level": "ML1", "reason": ""}},
        caplog,
    )
    assert "application control" not in result
    assert result["Application control"] == _NOT_ASSESSED
    assert len(caplog.records) == 1


def test_attestation_entry_not_object_is_skipped(tmp_path: Path, caplog: Any) -> None:
    """A non-object entry is skipped with a warning."""
    result = _load(tmp_path, {"Application control": "Attested"}, caplog)
    assert result["Application control"] == _NOT_ASSESSED
    assert len(caplog.records) == 1


def test_attestation_non_string_reason_is_skipped(tmp_path: Path, caplog: Any) -> None:
    """A non-string reason is skipped with a warning."""
    result = _load(
        tmp_path,
        {"Application control": {"status": "Attested", "level": "ML1", "reason": 5}},
        caplog,
    )
    assert result["Application control"] == _NOT_ASSESSED
    assert len(caplog.records) == 1


def test_attestation_empty_reason_allowed(tmp_path: Path, caplog: Any) -> None:
    """An empty reason string is valid."""
    result = _load(
        tmp_path,
        {"Application control": {"status": "Attested", "level": "ML1", "reason": ""}},
        caplog,
    )
    assert result["Application control"]["status"] == "Attested"
    assert caplog.records == []


def test_attestation_mixed_entries_keep_valid_ones(tmp_path: Path, caplog: Any) -> None:
    """Invalid entries are skipped while valid ones are kept."""
    result = _load(
        tmp_path,
        {
            "Application control": {"status": "Attested", "level": "ML3", "reason": "ok"},
            "Regular backups": {"status": "Attested", "level": "ML9", "reason": "bad"},
            "Nonsense": {"status": "Attested", "level": "ML1", "reason": ""},
        },
        caplog,
    )
    assert result["Application control"]["level"] == 3
    assert result["Regular backups"] == _NOT_ASSESSED
    assert len(caplog.records) == 2


def test_attestation_none_asd_data_returns_empty() -> None:
    """No asd_data means no strategies and an empty result."""
    assert load_attestation(None, None) == {}
    assert load_attestation("whatever.json", {}) == {}


def test_attestation_entry_keys_are_exact(tmp_path: Path, caplog: Any) -> None:
    """Every returned value has exactly status, level and reason."""
    result = _load(
        tmp_path,
        {"Application control": {"status": "Attested", "level": "ML1", "reason": "r", "extra": 1}},
        caplog,
    )
    for value in result.values():
        assert set(value) == {"status", "level", "reason"}


_EXAMPLE_FILE = (
    Path(__file__).resolve().parent.parent / "data/defaults/e8_attestation.example.json"
)
_EXAMPLE_ASD: dict[str, Any] = {
    "essential_eight": [
        {"strategy": "Application control", "controls": []},
        {"strategy": "Restrict Microsoft Office macros", "controls": []},
    ],
    "ism": [],
}


def test_attestation_example_file_untouched_claims_nothing(caplog: Any) -> None:
    """Shipping the example file untouched cannot produce a claimed attestation."""
    with caplog.at_level(logging.WARNING, logger="ravensight.e8_scorer"):
        result = load_attestation(str(_EXAMPLE_FILE), _EXAMPLE_ASD)
    assert len(result) == 2
    assert all(v["status"] == "Not assessed" for v in result.values())
    records = [r for r in caplog.records if r.name == "ravensight.e8_scorer"]
    assert len(records) == 2
    assert all("placeholder" in r.getMessage() for r in records)


def test_attestation_example_file_with_prefix_stripped_loads(
    tmp_path: Path, caplog: Any
) -> None:
    """With the EXAMPLE prefix removed the example entries load as claimed."""
    data = json.loads(_EXAMPLE_FILE.read_text(encoding="utf-8"))
    for entry in data.values():
        entry["reason"] = entry["reason"].removeprefix("EXAMPLE: ")
    path = tmp_path / "edited.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="ravensight.e8_scorer"):
        result = load_attestation(str(path), _EXAMPLE_ASD)
    assert caplog.records == []
    assert result["Application control"]["status"] == "Attested"
    assert result["Application control"]["level"] == 1
    assert result["Restrict Microsoft Office macros"]["status"] == "Not applicable"


def test_attestation_reason_starting_with_examples_is_kept(tmp_path: Path, caplog: Any) -> None:
    """A reason starting 'Examples of ...' is not mistaken for the placeholder."""
    result = _load(
        tmp_path,
        {
            "Application control": {
                "status": "Attested",
                "level": "ML1",
                "reason": "Examples of patched hosts: web01, web02",
            }
        },
        caplog,
    )
    assert result["Application control"]["status"] == "Attested"
    assert caplog.records == []


def test_attestation_reason_with_example_mid_string_is_kept(tmp_path: Path, caplog: Any) -> None:
    """A reason containing 'example:' but not starting with it is kept."""
    result = _load(
        tmp_path,
        {
            "Application control": {
                "status": "Attested",
                "level": "ML1",
                "reason": "Evidence, for example: change tickets",
            }
        },
        caplog,
    )
    assert result["Application control"]["status"] == "Attested"
    assert caplog.records == []
