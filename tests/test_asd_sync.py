"""
Tests for scripts/asd_sync.py (Build 2b).

No network, no real sleeps — requests.get and RETRY_DELAY_SECONDS are patched.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from scripts import asd_sync


def _build_catalog() -> dict[str, Any]:
    """Build a minimal ISM OSCAL catalog for testing."""
    return {
        "catalog": {
            "metadata": {"version": "v2026.09.4-test"},
            "groups": [
                {
                    "title": "Patch Management",
                    "groups": [
                        {
                            "title": "Software Patches",
                            "controls": [
                                {
                                    "id": "ism-1690",
                                    "class": "ISM-control",
                                    "title": "Patch applications",
                                    "parts": [
                                        {
                                            "name": "statement",
                                            "prose": "Patches for applications are applied.",
                                        }
                                    ],
                                    "props": [
                                        {"name": "essential-eight-applicability", "value": "ML1"},
                                        {"name": "essential-eight-applicability", "value": "ML2"},
                                        {"name": "essential-eight-applicability", "value": "ML3"},
                                    ],
                                },
                                {
                                    "id": "ism-1691",
                                    "class": "ISM-control",
                                    "title": "Patch applications ML1+ML2",
                                    "parts": [
                                        {
                                            "name": "statement",
                                            "prose": "Partial patch coverage.",
                                        }
                                    ],
                                    "props": [
                                        {"name": "essential-eight-applicability", "value": "ML1"},
                                        {"name": "essential-eight-applicability", "value": "ML2"},
                                    ],
                                },
                                {
                                    "id": "ism-1873",
                                    "class": "ISM-control",
                                    "title": "MFA control ML2 only",
                                    "parts": [
                                        {
                                            "name": "statement",
                                            "prose": "Multi-factor authentication control.",
                                        }
                                    ],
                                    "props": [
                                        {"name": "essential-eight-applicability", "value": "ML2"},
                                    ],
                                },
                                {
                                    "id": "ism-principle-gov-01",
                                    "class": "ISM-principle",
                                    "title": "Governance principle",
                                    "parts": [
                                        {"name": "statement", "prose": "A principle."}
                                    ],
                                },
                                {
                                    "id": "ism-9999",
                                    "class": "ISM-control",
                                    "title": "Unmapped E8 control",
                                    "parts": [
                                        {"name": "statement", "prose": "Not in any strategy."}
                                    ],
                                    "props": [
                                        {"name": "essential-eight-applicability", "value": "ML1"},
                                    ],
                                },
                            ],
                        }
                    ],
                }
            ],
        }
    }


def _build_strategy_map() -> dict[str, Any]:
    """Build a strategy map referencing some controls and a missing id."""
    return {
        "strategies": {
            "Patch applications": ["ism-1690", "ism-1691"],
            "Multi-factor authentication": ["ism-1873", "ism-missing"],
        }
    }


@pytest.fixture()
def strategy_map_file(tmp_path: Path) -> Path:
    """Write a temporary strategy map JSON file."""
    path = tmp_path / "e8_strategy_map.json"
    path.write_text(json.dumps(_build_strategy_map()), encoding="utf-8")
    return path


@pytest.fixture()
def patched_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch RETRY_DELAY_SECONDS to 0 for fast tests."""
    monkeypatch.setattr(asd_sync, "RETRY_DELAY_SECONDS", 0)


def _successful_get(url: str, **kwargs: Any) -> MagicMock:
    """Simulate a successful fetch of the test catalog."""
    response = MagicMock()
    response.json.return_value = _build_catalog()
    response.raise_for_status.return_value = None
    return response


def _run_sync(
    output_path: Path,
    strategy_map_file: Path,
    get_impl: Any,
) -> None:
    """Run the sync with the given requests.get implementation."""
    with (
        patch.object(asd_sync.requests, "get", side_effect=get_impl),
        patch.object(
            sys, "argv", ["asd_sync.py", "--output", str(output_path), "--strategy-map", str(strategy_map_file)]
        ),
    ):
        asd_sync.main()


def test_schema_and_shape(
    strategy_map_file: Path, patched_delay: None, tmp_path: Path, caplog: Any
) -> None:
    """Output has schema 2 and expected essential_eight shape and order."""
    output_path = tmp_path / "asd_framework.json"
    with caplog.at_level(logging.WARNING, logger="scripts.asd_sync"):
        _run_sync(output_path, strategy_map_file, _successful_get)

    assert "ism-missing" in caplog.text

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["schema"] == 2
    assert data["ism_source"] == asd_sync.ISM_CATALOG_PRIMARY_URL
    assert data["ism_version"] == "v2026.09.4-test"

    essential_eight = data["essential_eight"]
    assert [entry["strategy"] for entry in essential_eight] == [
        "Patch applications",
        "Multi-factor authentication",
        "Unmapped",
    ]

    patch_apps = essential_eight[0]
    assert len(patch_apps["controls"]) == 2
    assert patch_apps["controls"][0]["id"] == "ISM-1690"
    assert patch_apps["controls"][0]["levels"] == [1, 2, 3]
    assert patch_apps["controls"][1]["id"] == "ISM-1691"
    assert patch_apps["controls"][1]["levels"] == [1, 2]

    mfa = essential_eight[1]
    assert len(mfa["controls"]) == 1
    assert mfa["controls"][0]["id"] == "ISM-1873"
    assert mfa["controls"][0]["levels"] == [2]

    unmapped = essential_eight[2]
    assert len(unmapped["controls"]) == 1
    assert unmapped["controls"][0]["id"] == "ISM-9999"


def test_ism_ids_contains_controls_not_principles(
    strategy_map_file: Path, patched_delay: None, tmp_path: Path
) -> None:
    """ism_ids lists every control id and excludes principles."""
    output_path = tmp_path / "asd_framework.json"
    _run_sync(output_path, strategy_map_file, _successful_get)

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["ism_ids"] == ["ISM-1690", "ISM-1691", "ISM-1873", "ISM-9999"]


def test_primary_then_fallback_fetch_order(
    strategy_map_file: Path, patched_delay: None, tmp_path: Path
) -> None:
    """Primary URL is tried first; fallback is used only when primary fails."""
    output_path = tmp_path / "asd_framework.json"
    call_log: list[str] = []

    def fake_get(url: str, **kwargs: Any) -> MagicMock:
        call_log.append(url)
        response = MagicMock()
        if url == asd_sync.ISM_CATALOG_PRIMARY_URL:
            response.raise_for_status.side_effect = requests.RequestException("primary down")
        else:
            response.json.return_value = _build_catalog()
            response.raise_for_status.return_value = None
        return response

    _run_sync(output_path, strategy_map_file, fake_get)

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["ism_source"] == asd_sync.ISM_CATALOG_FALLBACK_URL
    assert call_log[0] == asd_sync.ISM_CATALOG_PRIMARY_URL
    assert call_log[-1] == asd_sync.ISM_CATALOG_FALLBACK_URL


def test_both_sources_fail_raises(
    strategy_map_file: Path, patched_delay: None, tmp_path: Path
) -> None:
    """Sync raises only when both primary and fallback fail."""
    output_path = tmp_path / "asd_framework.json"

    def fake_get(url: str, **kwargs: Any) -> MagicMock:
        response = MagicMock()
        response.raise_for_status.side_effect = requests.RequestException("down")
        return response

    with pytest.raises(requests.RequestException):
        _run_sync(output_path, strategy_map_file, fake_get)

    assert not output_path.exists()


def test_missing_strategy_map_exits_nonzero(
    patched_delay: None, tmp_path: Path, caplog: Any
) -> None:
    """A missing strategy map logs an error and exits without writing output."""
    output_path = tmp_path / "asd_framework.json"
    missing_map = tmp_path / "no_such_map.json"

    with (
        caplog.at_level(logging.ERROR, logger="scripts.asd_sync"),
        pytest.raises(SystemExit) as exc,
    ):
        _run_sync(output_path, missing_map, _successful_get)

    assert exc.value.code == 1
    assert "Strategy map not found" in caplog.text
    assert not output_path.exists()


def test_total_mapped_controls_dedups_across_strategies(
    patched_delay: None, tmp_path: Path, caplog: Any
) -> None:
    """'Total mapped controls' counts unique control ids, not the per-strategy sum."""
    strategy_map = {
        "strategies": {
            "Patch applications": ["ism-1690", "ism-1691"],
            "Patch operating systems": ["ism-1690"],
        }
    }
    map_file = tmp_path / "e8_strategy_map.json"
    map_file.write_text(json.dumps(strategy_map), encoding="utf-8")
    output_path = tmp_path / "asd_framework.json"

    with caplog.at_level(logging.INFO, logger="scripts.asd_sync"):
        _run_sync(output_path, map_file, _successful_get)

    assert "Total mapped controls:      2" in caplog.text
