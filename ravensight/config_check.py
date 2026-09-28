"""
config_check.py — static configuration validation for Ravensight.

Pure analysis in find_problems(); side effects (logging + exit) live in validate()
so the rules can be unit-tested without touching main.
"""
from __future__ import annotations

import logging
import sys
from typing import Any

# Required keys per section, checked only when the section exists.
_REQUIRED_KEYS: dict[str, tuple[str, ...]] = {
    "wazuh": ("host", "user", "password", "indexer_password"),
    "llm": ("base_url", "api_key", "model"),
    "reports": ("output_dir",),
    "baseline": ("path",),
}

# Keys that must be a genuine int (bool is explicitly rejected).
_INT_KEYS: dict[str, tuple[str, ...]] = {
    "wazuh": ("indexer_port", "port"),
    "embeddings": ("chroma_port",),
    "trending": ("window_days",),
    "llm": ("max_tokens",),
}

_PLACEHOLDER_HINT = (
    "set your real value in config.toml (or in .env if you run Ravensight "
    "with Docker), then run again."
)

# Sections skipped entirely (placeholders, keys, typing) in report-only mode.
_REPORT_ONLY_SKIP = ("wazuh", "llm")


def _placeholder_problems(config: dict[str, Any], report_only: bool) -> list[str]:
    """Collect placeholder problems, walking nested tables and lists of tables."""
    problems: list[str] = []

    def walk(path: list[str], table: dict[str, Any]) -> None:
        for key in sorted(table):
            value = table[key]
            if isinstance(value, str):
                if "YOUR_" not in value:
                    continue
                if not path:
                    # Placeholder at a section root — TOML cannot produce this shape,
                    # but emit a defensible message rather than dropping it silently.
                    problems.append(
                        f"Config error: [{key}] is still a placeholder — {_PLACEHOLDER_HINT}"
                    )
                else:
                    problems.append(
                        f"Config error: [{'.'.join(path)}].{key} is still a placeholder — "
                        f"{_PLACEHOLDER_HINT}"
                    )
            elif isinstance(value, dict):
                walk(path + [key], value)
            elif isinstance(value, list):
                # List of tables: keep the parent path as the section prefix.
                for item in value:
                    if isinstance(item, dict):
                        walk(path, item)

    for section in sorted(config):
        if report_only and section in _REPORT_ONLY_SKIP:
            continue
        if isinstance(config[section], dict):
            walk([section], config[section])
    return problems


def _required_key_problems(
    config: dict[str, Any], required: set[str]
) -> list[str]:
    """Collect missing/empty required-key problems for sections that exist."""
    problems: list[str] = []
    for section in sorted(required):
        if section not in config or not isinstance(config[section], dict):
            continue  # missing sections are reported separately
        for key in sorted(_REQUIRED_KEYS[section]):
            value = config[section].get(key)
            if value is None or (isinstance(value, str) and not value.strip()):
                problems.append(
                    f"Config error: [{section}] is missing required key '{key}' "
                    "(or it is empty) — see config.example.toml."
                )
    return problems


def _type_problems(config: dict[str, Any], report_only: bool) -> list[str]:
    """Collect wrong-type problems; bool is never accepted for int keys."""
    problems: list[str] = []
    for section in sorted(_INT_KEYS):
        if report_only and section in _REPORT_ONLY_SKIP:
            continue
        if section not in config or not isinstance(config[section], dict):
            continue
        for key in sorted(_INT_KEYS[section]):
            if key not in config[section]:
                continue
            value = config[section][key]
            if type(value) is not int:
                problems.append(
                    f"Config error: [{section}].{key} has the wrong type — "
                    f"expected int, got {type(value).__name__}"
                )
    if not report_only and isinstance(config.get("llm"), dict):
        if "temperature" in config["llm"]:
            value = config["llm"]["temperature"]
            if type(value) is not int and type(value) is not float:
                problems.append(
                    "Config error: [llm].temperature has the wrong type — "
                    f"expected int or float, got {type(value).__name__}"
                )
    return problems


def find_problems(config: dict[str, Any], report_only: bool) -> list[str]:
    """Return every configuration problem found, in a deterministic order."""
    if report_only:
        required = {"reports", "baseline"}
    else:
        required = {"wazuh", "llm", "reports", "baseline"}

    problems: list[str] = []
    for section in sorted(required):
        if section not in config:
            problems.append(f"Missing required config section: [{section}]")

    problems.extend(_placeholder_problems(config, report_only))
    problems.extend(_required_key_problems(config, required))
    problems.extend(_type_problems(config, report_only))
    return problems


def validate(config: dict[str, Any], report_only: bool) -> None:
    """Log every problem at CRITICAL and exit 1; return silently when clean."""
    problems = find_problems(config, report_only)
    for problem in problems:
        logging.critical(problem)
    if problems:
        logging.critical(
            f"Config check failed: {len(problems)} problem(s) — fix them and run again."
        )
        sys.exit(1)
