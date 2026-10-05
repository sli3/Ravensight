"""
Tests for Essential Eight related-control scoring (Build 2b).

The new score_findings returns 'Not assessed' status with related findings and
controls; it never produces pass/fail maturity verdicts.
"""

import json
import logging
from pathlib import Path
from typing import Any

from ravensight.e8_scorer import score_findings


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


def test_two_shared_keywords_relate() -> None:
    """Two overlapping keywords meet the minimum match score."""
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
    # Two keywords relate; blocking one leaves only one and drops below threshold.
    finding = _finding(narrative="Unauthorised applications detected")
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
    """Keywords appearing only in the narrative still contribute to matching."""
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
    finding = _finding(id="C9", narrative="Multi-factor authentication rolled out")
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
