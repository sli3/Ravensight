"""
Tests for Essential Eight scoring with dict findings (Build 1b).

The key behaviour: keywords appearing only in a finding's narrative still
contribute to strategy matching via _normalise_findings.
"""

from typing import Any

from ravensight.e8_scorer import score_findings

ASD_DATA: dict[str, Any] = {
    "essential_eight": [
        {
            "strategy": "Application Control",
            "maturity_level": 1,
            "description": "Unauthorised applications execute on systems",
        },
    ],
    "ism": [],
}


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


def test_keyword_only_in_narrative_still_matches() -> None:
    """A keyword appearing solely in the narrative fails the strategy score."""
    passing = score_findings([_finding()], ASD_DATA)
    assert passing["Application Control"][1] is True

    narrative_hit = _finding(narrative="Unauthorised application executed on host-1")
    failing = score_findings([narrative_hit], ASD_DATA)
    assert failing["Application Control"][1] is False
