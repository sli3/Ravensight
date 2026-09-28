"""
Tests for ravensight.config_check and its wiring into main.

No live Wazuh Indexer, LLM server or ChromaDB is required: fetch_alerts and
analyse are monkeypatched to raise the exceptions under test, and the config
file points reports/baseline at tmp_path so no real state is touched.
"""

import logging
import sys
from pathlib import Path
from typing import Any

import httpx
import openai
import pytest
import requests

import main
from ravensight import analyser, config_check, wazuh_client


def _valid_config() -> dict[str, Any]:
    """Build an example-shaped config with real-looking values for every required key."""
    return {
        "wazuh": {
            "host": "wazuh.example.local",
            "port": 55000,
            "user": "wazuh-wui",
            "password": "real-password",
            "indexer_host": "indexer.example.local",
            "indexer_port": 9200,
            "indexer_user": "admin",
            "indexer_password": "real-indexer-password",
        },
        "llm": {
            "base_url": "http://llm.example.local:8000/v1",
            "api_key": "local",
            "model": "llama-3.1-8b",
            "max_tokens": 2048,
            "temperature": 0.2,
        },
        "reports": {"output_dir": "/tmp/reports"},
        "baseline": {"path": "/tmp/baseline.json"},
    }


def test_placeholder_in_required_section_reported() -> None:
    """A placeholder in [wazuh] is reported with its dotted key path."""
    config = _valid_config()
    config["wazuh"]["host"] = "YOUR_WAZUH_MANAGER_IP"

    problems = config_check.find_problems(config, report_only=False)

    assert any("[wazuh].host" in p for p in problems)


def test_placeholder_value_not_printed() -> None:
    """The placeholder value itself never leaks into a problem message."""
    config = _valid_config()
    config["wazuh"]["host"] = "YOUR_WAZUH_MANAGER_IP"

    problems = config_check.find_problems(config, report_only=False)

    assert all("YOUR_WAZUH_MANAGER_IP" not in p for p in problems)


def test_placeholder_message_mentions_env() -> None:
    """The placeholder message points the user at .env for Docker runs."""
    config = _valid_config()
    config["wazuh"]["host"] = "YOUR_WAZUH_MANAGER_IP"

    problems = config_check.find_problems(config, report_only=False)

    assert any(".env" in p for p in problems)


def test_optional_section_placeholder_reported() -> None:
    """Placeholders in the optional [embeddings] section are also reported."""
    config = _valid_config()
    config["embeddings"] = {"chroma_host": "YOUR_CHROMA_SERVER_IP"}

    problems = config_check.find_problems(config, report_only=False)

    assert any("[embeddings].chroma_host" in p for p in problems)


def test_nested_placeholder_uses_dotted_path() -> None:
    """A placeholder inside a nested table uses the full dotted section path."""
    config = _valid_config()
    config["extra"] = {"a": {"b": "YOUR_FOO_BAR"}}

    problems = config_check.find_problems(config, report_only=False)

    assert any("[extra.a].b" in p for p in problems)


def test_all_problems_reported_together() -> None:
    """Placeholder, missing key and wrong type all surface in a single call."""
    config = _valid_config()
    config["wazuh"]["host"] = "YOUR_WAZUH_MANAGER_IP"
    del config["llm"]["model"]
    config["wazuh"]["port"] = "55000"

    problems = config_check.find_problems(config, report_only=False)

    assert any("[wazuh].host" in p for p in problems)
    assert any("'model'" in p for p in problems)
    assert any("[wazuh].port" in p and "wrong type" in p for p in problems)
    assert len(problems) >= 3


def test_missing_required_key() -> None:
    """Omitting [llm].model names the key in the message."""
    config = _valid_config()
    del config["llm"]["model"]

    problems = config_check.find_problems(config, report_only=False)

    assert any("[llm] is missing required key 'model'" in p for p in problems)


def test_empty_value_treated_as_missing() -> None:
    """A whitespace-only [wazuh].host counts as missing."""
    config = _valid_config()
    config["wazuh"]["host"] = "   "

    problems = config_check.find_problems(config, report_only=False)

    assert any("[wazuh] is missing required key 'host'" in p for p in problems)


def test_indexer_password_required() -> None:
    """[wazuh].indexer_password is a required key with standard wording."""
    config = _valid_config()
    del config["wazuh"]["indexer_password"]

    problems = config_check.find_problems(config, report_only=False)

    assert any("[wazuh] is missing required key 'indexer_password'" in p for p in problems)


def test_wrong_type_port() -> None:
    """A string [wazuh].port is rejected with a wrong-type message."""
    config = _valid_config()
    config["wazuh"]["port"] = "55000"

    problems = config_check.find_problems(config, report_only=False)

    assert any(
        "[wazuh].port has the wrong type — expected int, got str" in p
        for p in problems
    )


def test_bool_rejected_for_int_key() -> None:
    """A bool [wazuh].port is rejected — bool must not pass as an int."""
    config = _valid_config()
    config["wazuh"]["port"] = True

    problems = config_check.find_problems(config, report_only=False)

    assert any(
        "[wazuh].port has the wrong type — expected int, got bool" in p
        for p in problems
    )


def test_valid_config_passes() -> None:
    """An example-shaped config with real values produces no problems."""
    problems = config_check.find_problems(_valid_config(), report_only=False)

    assert problems == []


def test_report_only_skips_wazuh_llm() -> None:
    """Report-only mode requires only [reports] and [baseline], and skips wazuh/llm checks."""
    minimal = {
        "reports": {"output_dir": "/tmp/reports"},
        "baseline": {"path": "/tmp/baseline.json"},
    }
    assert config_check.find_problems(minimal, report_only=True) == []

    with_placeholders = dict(minimal)
    with_placeholders["wazuh"] = {"host": "YOUR_WAZUH_HOST"}
    with_placeholders["llm"] = {"base_url": "http://YOUR_LLM_HOST/v1"}
    problems = config_check.find_problems(with_placeholders, report_only=True)

    assert all("YOUR_WAZUH_HOST" not in p for p in problems)
    assert all("YOUR_LLM_HOST" not in p for p in problems)


def test_validate_exits_1(caplog: Any) -> None:
    """validate() logs each problem plus a final summary and exits 1."""
    config = _valid_config()
    del config["llm"]["model"]
    caplog.set_level(logging.CRITICAL)

    with pytest.raises(SystemExit) as exc:
        config_check.validate(config, report_only=False)

    assert exc.value.code == 1
    assert any(
        rec.levelno == logging.CRITICAL and "Config check failed:" in rec.message
        for rec in caplog.records
    )


_CONFIG_TEMPLATE = """
[reports]
output_dir = "{tmp}/reports"

[baseline]
path = "{tmp}/baseline.json"

[wazuh]
host = "x"
port = 55000
user = "u"
password = "p"
indexer_host = "x"
indexer_port = 9200
indexer_user = "admin"
indexer_password = "p"

[llm]
base_url = "http://example.invalid/v1"
api_key = "local"
model = "any"
"""


def _write_config(tmp_path: Path) -> Path:
    """Write a valid throwaway config into tmp_path and return its path."""
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(_CONFIG_TEMPLATE.format(tmp=tmp_path), encoding="utf-8")
    return cfg_path


def test_fetch_alerts_connection_error_clean_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: Any
) -> None:
    """A ConnectionError yields one clean critical line, exit 1, no traceback at INFO."""

    def fail_fetch(self: Any, **kwargs: Any) -> Any:
        """Raise as an unreachable Wazuh Indexer would."""
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(wazuh_client.Client, "fetch_alerts", fail_fetch)
    monkeypatch.setattr(
        sys, "argv", ["main.py", "--config", str(_write_config(tmp_path)), "--hours", "1", "--level", "1"]
    )
    caplog.set_level(logging.CRITICAL)

    with pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 1
    criticals = [rec for rec in caplog.records if rec.levelno == logging.CRITICAL]
    assert len(criticals) == 1
    assert "Wazuh Indexer unreachable" in criticals[0].message
    assert "check [wazuh] indexer_host and indexer_port" in criticals[0].message
    assert not criticals[0].exc_info


def test_fetch_alerts_http_401_rejected_login_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: Any
) -> None:
    """An HTTP 401 raises a rejected-login message naming the indexer credentials."""

    def fail_fetch(self: Any, **kwargs: Any) -> Any:
        """Raise a 401 HTTPError exactly as response.raise_for_status() would."""
        response = requests.Response()
        response.status_code = 401
        response.url = "http://example.invalid/wazuh-alerts-4.x-*/_search"
        response.raise_for_status()

    monkeypatch.setattr(wazuh_client.Client, "fetch_alerts", fail_fetch)
    monkeypatch.setattr(
        sys, "argv", ["main.py", "--config", str(_write_config(tmp_path)), "--hours", "1", "--level", "1"]
    )
    caplog.set_level(logging.CRITICAL)

    with pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 1
    assert any(
        "rejected the login (HTTP 401)" in rec.message
        and "indexer_user and indexer_password" in rec.message
        for rec in caplog.records
        if rec.levelno == logging.CRITICAL
    )


def test_fetch_alerts_debug_includes_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: Any
) -> None:
    """At --log-level DEBUG the same failure logs with exc_info populated."""

    def fail_fetch(self: Any, **kwargs: Any) -> Any:
        """Raise as an unreachable Wazuh Indexer would."""
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(wazuh_client.Client, "fetch_alerts", fail_fetch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--config", str(_write_config(tmp_path)), "--hours", "1", "--level", "1", "--log-level", "DEBUG"],
    )
    caplog.set_level(logging.DEBUG)

    with pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 1
    criticals = [rec for rec in caplog.records if rec.levelno == logging.CRITICAL]
    assert criticals
    assert any(rec.exc_info is not None for rec in criticals)


def test_analyse_api_connection_error_clean_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: Any
) -> None:
    """An openai.APIConnectionError yields an unreachable-server message and exit 1."""

    def fail_analyse(*args: Any, **kwargs: Any) -> Any:
        """Raise as an unreachable LLM server would."""
        request = httpx.Request("POST", "http://example.invalid/v1/chat/completions")
        raise openai.APIConnectionError(request=request)

    monkeypatch.setattr(wazuh_client.Client, "fetch_alerts", lambda self, **kwargs: [])
    monkeypatch.setattr(analyser, "analyse", fail_analyse)
    monkeypatch.setattr(
        sys, "argv", ["main.py", "--config", str(_write_config(tmp_path)), "--hours", "1", "--level", "1"]
    )
    caplog.set_level(logging.CRITICAL)

    with pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 1
    criticals = [rec for rec in caplog.records if rec.levelno == logging.CRITICAL]
    assert len(criticals) == 1
    assert "LLM server unreachable" in criticals[0].message
    assert "[llm] base_url" in criticals[0].message
    assert not criticals[0].exc_info


def test_analyse_api_status_error_clean_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: Any
) -> None:
    """An openai.APIStatusError yields an HTTP-status message naming key and model."""

    def fail_analyse(*args: Any, **kwargs: Any) -> Any:
        """Raise as an LLM server rejecting the request would."""
        request = httpx.Request("POST", "http://example.invalid/v1/chat/completions")
        response = httpx.Response(401, request=request)
        raise openai.APIStatusError(message="invalid api key", response=response, body=None)

    monkeypatch.setattr(wazuh_client.Client, "fetch_alerts", lambda self, **kwargs: [])
    monkeypatch.setattr(analyser, "analyse", fail_analyse)
    monkeypatch.setattr(
        sys, "argv", ["main.py", "--config", str(_write_config(tmp_path)), "--hours", "1", "--level", "1"]
    )
    caplog.set_level(logging.CRITICAL)

    with pytest.raises(SystemExit) as exc:
        main.main()

    assert exc.value.code == 1
    criticals = [rec for rec in caplog.records if rec.levelno == logging.CRITICAL]
    assert len(criticals) == 1
    assert "LLM server returned HTTP 401" in criticals[0].message
    assert "api_key and model" in criticals[0].message
    assert not criticals[0].exc_info
