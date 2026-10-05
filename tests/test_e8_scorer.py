"""
Tests for Essential Eight related-control scoring (Build 2b).

The new score_findings returns 'Not assessed' status with related findings and
controls; it never produces pass/fail maturity verdicts.
"""

import json
import logging
from pathlib import Path
from typing import Any

from ravensight.e8_scorer import match_ism_controls, score_findings


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
    findings = [
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


def test_match_ism_controls_still_matches_generic_words() -> None:
    """The ISM matcher does not subtract E8_GENERIC_WORDS; generic words still match."""
    asd_data: dict[str, Any] = {
        "ism": [
            {
                "id": "ISM-LOG",
                "category": "Logging",
                "description": "Access to systems is logged",
            },
        ],
    }
    finding = _finding(narrative="system access denied")
    matched = match_ism_controls([finding], asd_data)
    assert any(control["id"] == "ISM-LOG" for control in matched)
