"""
mitre_sync.py — Fetch MITRE ATT&CK Enterprise data and save local lookup file.

Usage:
    python mitre_sync.py                    # sync to data/mitre_attack.json (default)
    python mitre_sync.py --source <url>     # custom source URL
    python mitre_sync.py --dry-run          # fetch but don't write
"""

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

DEFAULT_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def fetch_stix_bundle(source_url: str) -> dict[str, Any]:
    """
    Fetch MITRE ATT&CK STIX bundle from GitHub.

    Args:
        source_url: URL to the enterprise-attack.json file.

    Returns:
        Parsed STIX bundle as dictionary.

    Raises:
        requests.RequestException: If fetch fails after retries.
    """
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.get(source_url, timeout=60)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.warning(f"Attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt == max_retries - 1:
                raise
            logger.info(f"Retrying in {30 * (attempt + 1)} seconds...")
            time.sleep(30 * (attempt + 1))
    raise RuntimeError("fetch_stix_bundle: no attempts made")


def parse_attack_data(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Parse STIX bundle and extract tactics/techniques into lookup format.

    Args:
        bundle: Raw STIX bundle dictionary.

    Returns:
        Simplified lookup dict with tactics and techniques lists.
    """
    data: dict[str, Any] = {
        "tactics": [],
        "techniques": [],
        "subtechniques": [],
    }

    if not bundle.get("objects"):
        logger.warning("No STIX objects found in bundle")
        return data

    for obj in bundle["objects"]:
        obj_type = obj.get("type")

        if obj_type == "x-mitre-tactic":
            # Tactic object — all fields are direct on the STIX 2.1 object
            tactic_id = obj.get("id", "")
            tactic_name = obj.get("name", "")
            description = obj.get("description", "")
            shortname = obj.get("x_mitre_shortname", "")
            data["tactics"].append({
                "id": tactic_id,
                "name": tactic_name,
                "description": description,
                "shortname": shortname,
            })

        elif obj_type == "attack-pattern":
            # Technique or subtechnique object
            name = obj.get("name", "")
            description = obj.get("description", "")

            # Check if this is a subtechnique
            is_subtechnique = obj.get("x_mitre_is_subtechnique", False)

            # Extract technique ID from external_references (e.g., T1059)
            ext_refs = obj.get("external_references", [])
            technique_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            # Extract tactic association from kill_chain_phases
            kill_chain_phases = obj.get("kill_chain_phases", [])
            tactic_ref = ""
            for phase in kill_chain_phases:
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactic_ref = phase.get("phase_name", "")
                    break

            if technique_id and tactic_ref:
                tactic_name_label = tactic_ref.split("/")[-1] if "/" in tactic_ref else tactic_ref

                if is_subtechnique:
                    data["subtechniques"].append({
                        "id": technique_id,
                        "name": name,
                        "description": description,
                        "tactic_id": tactic_ref,
                        "tactic_name": tactic_name_label,
                    })
                else:
                    data["techniques"].append({
                        "id": technique_id,
                        "name": name,
                        "description": description,
                        "tactic_id": tactic_ref,
                        "tactic_name": tactic_name_label,
                    })

    return data


def save_lookup_file(data: dict[str, Any], output_path: Path) -> None:
    """
    Save parsed MITRE data to JSON file.

    Args:
        data: Parsed tactics/techniques dictionary.
        output_path: Destination file path.
    """
    with output_path.open("w") as f:
        json.dump(data, f, indent=2)
    logger.info(f"MITRE data written to {output_path}")


def sync_mitre(source_url: str, output_path: Path, dry_run: bool = False) -> None:
    """
    Sync MITRE ATT&CK Enterprise data to local lookup file.

    Args:
        source_url: URL to the STIX bundle JSON.
        output_path: Local file path for saved data.
        dry_run: If True, fetch but don't write output.
    """
    logger.info(f"Fetching from {source_url}")
    bundle = fetch_stix_bundle(source_url)

    logger.info("Parsing STIX bundle...")
    parsed_data = parse_attack_data(bundle)

    tactic_count = len(parsed_data["tactics"])
    tech_count = len(parsed_data["techniques"])
    subtech_count = len(parsed_data["subtechniques"])
    total_items = tactic_count + tech_count + subtech_count

    logger.info(
        f"Parsed {tactic_count} tactics, "
        f"{tech_count} techniques, "
        f"{subtech_count} subtechniques "
        f"({total_items} total)"
    )

    if not dry_run:
        save_lookup_file(parsed_data, output_path)
    else:
        logger.info("Dry run — no file written")


def main() -> None:
    """CLI entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    parser = argparse.ArgumentParser(
        description="Sync MITRE ATT&CK Enterprise data to local lookup file."
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE_URL,
        help=f"STIX bundle URL (default: {DEFAULT_SOURCE_URL})",
    )
    parser.add_argument(
        "--output",
        default=Path("data/mitre_attack.json"),
        help="Output file path (default: data/mitre_attack.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch data but don't write output file",
    )

    args = parser.parse_args()

    # Ensure output directory exists
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    # Run sync
    try:
        sync_mitre(
            source_url=args.source,
            output_path=Path(args.output),
            dry_run=args.dry_run,
        )
    except Exception as e:
        logger.error(f"Sync failed: {e}")
        raise


if __name__ == "__main__":
    main()
