"""
asd_sync.py — Fetch ASD ISM OSCAL catalog and build Essential Eight strategy map.

Usage:
    python scripts/asd_sync.py [--output data/asd_framework.json] [--categories ...]
                              [--strategy-map data/defaults/e8_strategy_map.json]
"""

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_PATH = Path("data/asd_framework.json")
DEFAULT_CATEGORIES = [
    "Access Control",
    "System Monitoring",
    "Patch Management",
    "Incident Response",
    "Network Management",
    "System Hardening",
    "Authentication",
    "Logging",
]

ISM_CATALOG_PRIMARY_URL = (
    "https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal/main/ISM_catalog.json"
)
ISM_CATALOG_FALLBACK_URL = (
    "https://www.cyber.gov.au/ism/oscal/latest-version/artifacts/ISM_catalog.json"
)

RETRY_DELAY_SECONDS = 5


def fetch_ism_catalog(
    primary_url: str = ISM_CATALOG_PRIMARY_URL,
    fallback_url: str = ISM_CATALOG_FALLBACK_URL,
) -> tuple[dict[str, Any], str]:
    """Fetch the ASD ISM OSCAL catalog, primary URL first then fallback.

    Args:
        primary_url: Preferred ISM catalog URL.
        fallback_url: Fallback ISM catalog URL.

    Returns:
        Tuple of (parsed catalog, URL that succeeded).

    Raises:
        requests.RequestException: If both URLs fail after retries.
    """
    urls = [primary_url, fallback_url]
    max_attempts = 2

    for url in urls:
        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                logger.info(f"Fetched ISM catalog from {url}")
                return response.json(), url
            except requests.RequestException as e:
                logger.warning(f"Attempt {attempt}/{max_attempts} failed for {url}: {e}")
                if attempt < max_attempts:
                    logger.info(f"Retrying in {RETRY_DELAY_SECONDS} seconds...")
                    time.sleep(RETRY_DELAY_SECONDS)

    raise requests.RequestException(
        f"Failed to fetch ISM catalog from both {primary_url} and {fallback_url}"
    )


def load_strategy_map(path: Path) -> dict[str, list[str]]:
    """Load the Essential Eight strategy map from JSON.

    Args:
        path: Path to e8_strategy_map.json.

    Returns:
        Dict mapping strategy name to list of lower-case control ids.

    Raises:
        SystemExit: If the map is missing, unreadable, or malformed.
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error(f"Strategy map not found: {path}")
        raise SystemExit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse strategy map {path}: {e}")
        raise SystemExit(1)

    strategies = data.get("strategies")
    if not isinstance(strategies, dict):
        logger.error(f"Strategy map {path} has no 'strategies' object")
        raise SystemExit(1)

    return {strategy: [str(cid).casefold() for cid in controls] for strategy, controls in strategies.items()}


def _extract_e8_levels(control: dict[str, Any]) -> list[int]:
    """Extract Essential Eight maturity levels from a control's props."""
    levels: set[int] = set()
    for prop in control.get("props", []):
        if isinstance(prop, dict) and prop.get("name") == "essential-eight-applicability":
            value = prop.get("value", "")
            if value in ("ML1", "ML2", "ML3"):
                levels.add(int(value[-1]))
    return sorted(levels)


def walk_control_tree(obj: Any, category: str = "") -> list[dict[str, Any]]:
    """Recursively walk the OSCAL catalog groups and extract controls.

    Args:
        obj: Group/control dictionary or list from the catalog.
        category: The top-level group title for categorising controls.

    Returns:
        List of dictionaries with control id, category, description, e8_levels, and kind.
    """
    results: list[dict[str, Any]] = []

    if isinstance(obj, list):
        for item in obj:
            results.extend(walk_control_tree(item, category))
        return results

    if not isinstance(obj, dict):
        return results

    title = obj.get("title", "")
    if title:
        current_category = title
    else:
        current_category = category

    # Recursively process nested groups
    nested_groups = obj.get("groups", [])
    if nested_groups:
        nested_results = walk_control_tree(nested_groups, current_category)
        results.extend(nested_results)

    # Process controls at this level
    controls = obj.get("controls", [])
    for control in controls:
        control_id = str(control.get("id", ""))
        if not control_id:
            continue

        description = extract_control_description(control)
        results.append({
            "id": control_id.upper(),
            "category": current_category,
            "description": description,
            "e8_levels": _extract_e8_levels(control),
            "kind": "control" if control.get("class") == "ISM-control" else "principle",
        })

    return results


def extract_control_description(control: dict[str, Any]) -> str:
    """Extract the prose description from a control's statement part.

    Args:
        control: Control dictionary from OSCAL catalog.

    Returns:
        Prose text from statement or control title as fallback.
    """
    parts = control.get("parts", [])
    for part in parts:
        if part.get("name") == "statement":
            prose = part.get("prose", "")
            if prose:
                return prose

    # Fallback to control title
    title = control.get("title", "")
    if title:
        return title

    return ""


def filter_controls_by_category(
    controls: list[dict[str, Any]], categories: list[str]
) -> list[dict[str, Any]]:
    """Filter controls to include only those matching category keywords.

    Args:
        controls: List of all extracted controls.
        categories: List of category keywords for matching.

    Returns:
        Filtered list of controls (id, category, description only).
    """
    filtered = []
    category_patterns = [cat.lower() for cat in categories]

    for control in controls:
        if control.get("kind") != "control":
            continue
        category = control["category"].lower()
        if any(pattern in category for pattern in category_patterns):
            filtered.append({
                "id": control["id"],
                "category": control["category"],
                "description": control["description"],
            })

    return filtered


def _build_essential_eight(
    strategy_map: dict[str, list[str]],
    controls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the essential_eight list in map order, plus an Unmapped entry.

    Args:
        strategy_map: Strategy name -> list of lower-case control ids.
        controls: All catalogue controls with e8_levels, kind, etc.

    Returns:
        List of strategy entries in map order; Unmapped appended when needed.
    """
    control_by_id = {str(c["id"]).casefold(): c for c in controls if c.get("kind") == "control"}
    mapped_ids: set[str] = set()
    result: list[dict[str, Any]] = []

    for strategy, ids in strategy_map.items():
        strategy_controls: list[dict[str, Any]] = []
        for cid in ids:
            control = control_by_id.get(cid)
            if control is None:
                logger.warning(f"Strategy '{strategy}' references unknown control {cid}")
                continue
            levels = control.get("e8_levels", [])
            if not levels:
                logger.warning(f"Strategy '{strategy}' references control {cid} with no E8 levels")
                continue
            strategy_controls.append({
                "id": control["id"].upper(),
                "levels": levels,
                "description": control["description"],
            })
            mapped_ids.add(cid)

        result.append({
            "strategy": strategy,
            "controls": strategy_controls,
        })

    unmapped: list[dict[str, Any]] = []
    for control in controls:
        if control.get("kind") != "control":
            continue
        cid = str(control["id"]).casefold()
        levels = control.get("e8_levels", [])
        if levels and cid not in mapped_ids:
            unmapped.append({
                "id": control["id"].upper(),
                "levels": levels,
                "description": control["description"],
            })

    if unmapped:
        result.append({
            "strategy": "Unmapped",
            "controls": unmapped,
        })

    return result


def save_output(data: dict[str, Any], output_path: Path) -> None:
    """Save combined data to JSON file.

    Args:
        data: Combined Essential Eight and ISM data dictionary.
        output_path: Destination file path.
    """
    with output_path.open("w") as f:
        json.dump(data, f, indent=2)
    logger.info(f"Output written to {output_path}")


def _find_strategy_map(repo_root: Path, arg_path: str | None) -> Path:
    """Resolve the strategy map path from argument or default locations."""
    if arg_path is not None:
        return Path(arg_path)

    candidates = [
        repo_root / "data" / "defaults" / "e8_strategy_map.json",
        repo_root / "defaults" / "e8_strategy_map.json",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    return candidates[0]


def main() -> None:
    """CLI entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    repo_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(
        description="Sync ASD ISM OSCAL catalog with Essential Eight strategy map."
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        help=f"Output file path (default: {DEFAULT_OUTPUT_PATH})",
    )
    parser.add_argument(
        "--categories",
        nargs="*",
        default=DEFAULT_CATEGORIES,
        help=f"Category keywords for filtering (default: {', '.join(DEFAULT_CATEGORIES)})",
    )
    parser.add_argument(
        "--strategy-map",
        default=None,
        help="Path to e8_strategy_map.json (default: data/defaults/e8_strategy_map.json)",
    )

    args = parser.parse_args()

    output_path = Path(args.output)
    strategy_map_path = _find_strategy_map(repo_root, args.strategy_map)

    if not strategy_map_path.is_file():
        logger.error(f"Strategy map not found: {strategy_map_path}")
        raise SystemExit(1)

    try:
        strategy_map = load_strategy_map(strategy_map_path)
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Failed to load strategy map {strategy_map_path}: {e}")
        raise SystemExit(1)

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        logger.info("Fetching ISM catalog")
        catalog, source_url = fetch_ism_catalog()

        logger.info("Walking control tree...")
        all_controls = walk_control_tree(
            catalog.get("catalog", {}).get("groups", []),
            category="",
        )
        total_controls = len(all_controls)

        logger.info("Filtering controls by category keywords...")
        ism_controls = filter_controls_by_category(all_controls, args.categories)

        logger.info(
            f"Found {len(ism_controls)} matching ISM controls "
            f"(filtered from {total_controls} total)"
        )

        essential_eight = _build_essential_eight(strategy_map, all_controls)
        ism_ids = sorted({
            c["id"].upper()
            for c in all_controls
            if c.get("kind") == "control"
        })

        output_data = {
            "schema": 2,
            "generated_at": iso_timestamp(),
            "ism_source": source_url,
            "ism_version": catalog.get("catalog", {}).get("metadata", {}).get("version", ""),
            "essential_eight": essential_eight,
            "ism": ism_controls,
            "ism_ids": ism_ids,
        }

        save_output(output_data, output_path)

        strategy_count = len(essential_eight)
        mapped_count = len({
            control["id"]
            for entry in essential_eight if entry["strategy"] != "Unmapped"
            for control in entry["controls"]
        })
        unmapped_count = sum(
            len(entry["controls"])
            for entry in essential_eight
            if entry["strategy"] == "Unmapped"
        )

        logger.info(
            f"Essential Eight strategies: {strategy_count}\n"
            f"Total mapped controls:      {mapped_count}\n"
            f"Unmapped controls:          {unmapped_count}\n"
            f"ISM controls fetched:       {len(ism_controls)} (filtered from {total_controls} total)\n"
            f"Output written to:          {output_path}"
        )

    except requests.RequestException as e:
        logger.error(f"Failed to fetch ISM catalog: {e}")
        raise
    except Exception as e:
        logger.error(f"Sync failed: {e}")
        raise


def iso_timestamp() -> str:
    """Generate ISO 8601 timestamp for output."""
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "_build_essential_eight",
    "extract_control_description",
    "fetch_ism_catalog",
    "filter_controls_by_category",
    "load_strategy_map",
    "main",
    "save_output",
    "walk_control_tree",
]


if __name__ == "__main__":
    main()
