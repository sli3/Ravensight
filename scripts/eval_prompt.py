"""
eval_prompt.py — prompt calibration harness for Build 1d.

Runs the fixture alert set through analyser.analyse() against the live local
LLM several times and scores each run against eight known failure modes
(F1–F8): wrong vendor naming, scan misreadings, hallucinated ports/paths,
over-escalated benign syscheck/dpkg language, stray MITRE output,
over-reaching recommendations and unsupported fidelity claims. Works both as
`uv run python scripts/eval_prompt.py` and `uv run python -m scripts.eval_prompt`.
Importing this module has no side effects; everything runs under main().
"""

import argparse
import inspect
import itertools
import json
import logging
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import tomllib

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ravensight import (  # noqa: F401  (wazuh_client: future fetch path)
    analyser,
    wazuh_client,
)
from ravensight.evidence import render_evidence

logger = logging.getLogger(__name__)

FIXTURE_AGENTS = {"fw-a": {"platform": "freebsd", "vendor": "OPNsense"}}

NEGATORS = frozenset(
    {
        "no",
        "not",
        "never",
        "without",
        "nor",
        "neither",
        "cannot",
        "unlikely",
        "absent",
        "lacks",
        "lacking",
        "none",
        "nothing",
    }
)


def _load_config(path: str) -> dict:
    """Load a TOML config file, returning the parsed dict."""
    with open(path, "rb") as f:
        return tomllib.load(f)


def _ping_llm(base_url: str) -> bool:
    """Return True when the LLM server answers GET {base_url}/models with 200."""
    req = urllib.request.Request(base_url.rstrip("/") + "/models")
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _load_fixtures(dirpath: str) -> list[dict]:
    """Load every parseable *.json file in dirpath as one alert dict each."""
    alerts: list[dict] = []
    for path in sorted(Path(dirpath).glob("*.json")):
        try:
            alerts.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as e:
            logger.debug(f"Skipping unparseable fixture {path}: {e}")
    return alerts


def _make_platform_agents_tmpfile() -> str:
    """Write the fixture agent-name map to a temp JSON file; caller unlinks."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(FIXTURE_AGENTS, f)
        return f.name


def _unnegated_count(text_lower: str, term: str) -> int:
    """Return the number of non-negated occurrences of term in lower-cased text."""

    def _is_negated(
        tokens: list[tuple[str, int, int]],
        index: int,
        position: int,
        clause: str,
    ) -> bool:
        start = max(0, index - 4)
        for token, _, _ in tokens[start:index]:
            if token in NEGATORS or token.endswith(("n't", "n’t")):
                return True
        window = [token for token, _, _ in tokens[start:index]]
        for pair in itertools.pairwise(window):
            if pair in (("rather", "than"), ("instead", "of")):
                return True
        before = clause[:position].rstrip()
        return before.endswith((" rather than", " instead of")) or before in (
            "rather than",
            "instead of",
        )

    count = 0
    for clause in re.split(r"[.!?;\n]", text_lower):
        tokens: list[tuple[str, int, int]] = []
        for match in re.finditer(r"\S+", clause):
            raw = match.group()
            cleaned = raw.strip(".,;:()[]{}'\"‘“” ")
            if cleaned:
                tokens.append((cleaned, match.start(), match.end()))
        if " " in term:
            for match in re.finditer(re.escape(term), clause):
                phrase_start = match.start()
                idx = -1
                for i, (_, start, end) in enumerate(tokens):
                    if end <= phrase_start:
                        idx = i
                    else:
                        break
                if not _is_negated(tokens, idx + 1, phrase_start, clause):
                    count += 1
        else:
            for i, (token, start, _) in enumerate(tokens):
                if term in token and not _is_negated(tokens, i, start, clause):
                    count += 1
    return count


def _score_clusters(
    clusters: list[dict],
    rendered_evidence_by_id: dict[str, str],
    mitre_tags: list | None = None,
) -> dict[str, Any]:
    """Score one analysis run against the F1–F8 failure modes."""
    scores: dict[str, Any] = {
        "F1": 0, "F2": 0, "F3": 0, "F4": 0, "F5": 0, "F6": 0, "F7": 0, "F8": 0,
    }
    any_mitre = bool(mitre_tags)
    for cluster in clusters:
        text = f"{cluster.get('narrative', '')} {cluster.get('recommendation', '')}"
        lowered = text.lower()
        evidence_text = rendered_evidence_by_id.get(cluster.get("id", ""), "")
        ev_lowered = evidence_text.lower()
        if _unnegated_count(lowered, "pfsense") > 0:
            scores["F1"] += 1
        evidence_dict = cluster.get("evidence") or {}
        if "firewall" in evidence_dict and any(
            _unnegated_count(lowered, term) > 0
            for term in ("scan", "external interface")
        ):
            scores["F2"] += 1
        for port in re.findall(r"\bports?\s+(\d+)", lowered):
            if port not in ev_lowered:
                scores["F3"] += 1
        for token in lowered.split():
            token = token.rstrip(".,;:)]}'\\ ")
            if token.startswith("/") and token not in ev_lowered:
                scores["F3"] += 1
        if "syscheck" in evidence_dict and any(
            _unnegated_count(lowered, term) > 0
            for term in ("alter", "tamper", "restore", "malicious", "compromis")
        ):
            scores["F4"] += 1
        if "dpkg" in evidence_dict and any(
            _unnegated_count(lowered, term) > 0
            for term in ("interrupt", "incomplete", "fail", "broken")
        ):
            scores["F5"] += 1
        if "mitre" in lowered:
            any_mitre = True
        if any(
            _unnegated_count(lowered, term) > 0
            for term in ("restore", "forensic", "isolat", "reimage", "incident response")
        ):
            scores["F7"] += 1
        scores["F8"] += len(cluster.get("flags") or [])
    scores["F6"] = 1 if any_mitre else 0
    return scores


def _supports_platform_agents_path() -> bool:
    """True when this checkout's analyse() accepts platform_agents_path."""
    return "platform_agents_path" in inspect.signature(analyser.analyse).parameters


def main() -> None:
    """Parse args, run the calibration loop and print the score table."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--fixtures", default="tests/fixtures")
    parser.add_argument("--json", default=None)
    args = parser.parse_args()

    config = _load_config(args.config)
    base_url = config["llm"]["base_url"]
    if not base_url.startswith(("http://", "https://")):
        print(f"llm.base_url has no scheme ({base_url!r}) — aborting", file=sys.stderr)
        sys.exit(2)
    if not _ping_llm(base_url):
        print(f"LLM server at {base_url} did not answer /models — aborting", file=sys.stderr)
        sys.exit(2)

    alerts = _load_fixtures(args.fixtures)
    if not alerts:
        print(f"No fixture alerts loaded from {args.fixtures} — aborting", file=sys.stderr)
        sys.exit(2)

    supports = _supports_platform_agents_path()
    tmp_path = _make_platform_agents_tmpfile()
    rows: list[dict[str, Any]] = []
    try:
        for _ in range(args.runs):
            kwargs: dict[str, Any] = {
                "baseline": {},
                "llm_config": config["llm"],
                "embedder": None,
                "mitre_path": config.get("mitre", {}).get("path"),
                "platform_hints_path": config.get("platform", {}).get("hints_path"),
                "asd_path": config.get("asd", {}).get("path"),
                "lookback_hours": None,
            }
            if supports:
                kwargs["platform_agents_path"] = tmp_path
            try:
                result = analyser.analyse(alerts, **kwargs)
            except Exception as e:  # noqa: BLE001 — any analyse() failure is a scored ERROR row
                logger.warning(f"analyse() failed: {type(e).__name__}: {e}")
                rows.append({"error": f"{type(e).__name__}: {e}"})
                continue
            clusters = result.get("findings", [])
            rendered_by_id = {
                c.get("id", ""): render_evidence(c.get("evidence"))
                for c in clusters
            }
            row = _score_clusters(
                clusters, rendered_by_id, mitre_tags=result.get("mitre_tags")
            )
            row["error"] = None
            row["clusters"] = [
                {
                    "id": finding.get("id", ""),
                    "hosts": finding.get("hosts", []),
                    "narrative": finding.get("narrative", ""),
                    "recommendation": finding.get("recommendation", ""),
                    "evidence": render_evidence(finding.get("evidence")),
                    "flags": list(finding.get("flags") or []),
                }
                for finding in clusters
                if str(finding.get("id", "")).startswith("C")
            ]
            rows.append(row)
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    print(f"{'run':>4} | F1 | F2 | F3 | F4 | F5 | F6 | F7 | F8")
    print("-" * 44)
    for i, row in enumerate(rows, start=1):
        if row.get("error"):
            print(f"{i:>4} | ERROR: {row['error']}")
        else:
            print(
                f"{i:>4} | {row['F1']} | {row['F2']} | {row['F3']} | "
                f"{row['F4']} | {row['F5']} | {row['F6']} | {row['F7']} | "
                f"{row['F8']}"
            )
    ok_rows = [r for r in rows if not r.get("error")]
    if ok_rows:
        means = {
            name: sum(r[name] for r in ok_rows) / len(ok_rows)
            for name in ("F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8")
        }
        print("-" * 44)
        print(
            "mean | "
            + " | ".join(
                f"{means[name]:.1f}"
                for name in ("F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8")
            )
        )
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
