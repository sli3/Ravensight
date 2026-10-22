"""
Tests for ravensight.config_check and its wiring into main.

No live Wazuh Indexer, LLM server or ChromaDB is required: fetch_alerts and
analyse are monkeypatched to raise the exceptions under test, and the config
file points reports/baseline at tmp_path so no real state is touched.
"""

import logging
import sys
from pathlib import Path
from typing import Any, cast

import httpx
import openai
import pytest
import requests

import main
from ravensight import analyser, baseline, config_check, reporter, wazuh_client


def _valid_config() -> dict[str, Any]:
    """Build an example-shaped config with real-looking values for every required key."""
    return {
        "wazuh": {
            "host": "wazuh.example.local",
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


def test_placeholder_message_names_config_toml_only() -> None:
    """The placeholder message names config.toml and never mentions .env or Docker."""
    config = _valid_config()
    config["wazuh"]["host"] = "YOUR_WAZUH_MANAGER_IP"

    problems = config_check.find_problems(config, report_only=False)

    assert problems
    assert all("config.toml" in p for p in problems)
    assert all(".env" not in p and "Docker" not in p for p in problems)


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


def test_legacy_manager_api_keys_are_accepted() -> None:
    """A config still holding the legacy user, password and int port has no problems."""
    config = _valid_config()
    config["wazuh"].update({"port": 55000, "user": "wazuh-wui", "password": "old-password"})

    assert config_check.find_problems(config, report_only=False) == []


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
    assert criticals[0].message.endswith(
        "check [wazuh] indexer_host and indexer_port in config.toml"
    )
    assert ".env" not in criticals[0].message
    assert "Docker" not in criticals[0].message
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
    criticals = [rec for rec in caplog.records if rec.levelno == logging.CRITICAL]
    assert any(
        "rejected the login (HTTP 401)" in rec.message
        and rec.message.endswith("check [wazuh] indexer_user and indexer_password in config.toml")
        for rec in criticals
    )
    assert all(".env" not in rec.message and "Docker" not in rec.message for rec in criticals)


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
        raise openai.APIConnectionError(request=cast(Any, request))

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
    assert criticals[0].message.endswith("check [llm] base_url in config.toml")
    assert ".env" not in criticals[0].message
    assert "Docker" not in criticals[0].message
    assert not criticals[0].exc_info


def test_analyse_api_status_error_clean_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: Any
) -> None:
    """An openai.APIStatusError yields an HTTP-status message naming key and model."""

    def fail_analyse(*args: Any, **kwargs: Any) -> Any:
        """Raise as an LLM server rejecting the request would."""
        request = httpx.Request("POST", "http://example.invalid/v1/chat/completions")
        response = httpx.Response(401, request=request)
        raise openai.APIStatusError(message="invalid api key", response=cast(Any, response), body=None)

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


@pytest.mark.parametrize("value", [1, 0, "true", "false", 1.0])
def test_non_bool_indexer_verify_tls_rejected(value: Any) -> None:
    """A non-bool indexer_verify_tls is reported, including int 1 and the string true."""
    config = _valid_config()
    config["wazuh"]["indexer_verify_tls"] = value

    problems = config_check.find_problems(config, report_only=False)

    assert any("[wazuh].indexer_verify_tls" in p and "expected bool" in p for p in problems)


def test_non_string_indexer_ca_path_gives_one_error() -> None:
    """A non-string indexer_ca_path gives exactly one error."""
    config = _valid_config()
    config["wazuh"]["indexer_ca_path"] = 5

    problems = config_check.find_problems(config, report_only=False)

    assert len(problems) == 1
    assert "[wazuh].indexer_ca_path" in problems[0]
    assert "expected str" in problems[0]


def test_missing_indexer_ca_path_file_reported(tmp_path: Path) -> None:
    """A CA path that does not exist is reported with the path."""
    config = _valid_config()
    missing = tmp_path / "nope.pem"
    config["wazuh"]["indexer_ca_path"] = str(missing)

    problems = config_check.find_problems(config, report_only=False)

    assert problems == [f"Config error: [wazuh].indexer_ca_path does not exist: {missing}"]


def test_existing_ca_file_and_directory_accepted(tmp_path: Path) -> None:
    """An existing CA file or directory is accepted."""
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("x")
    for target in (ca_file, tmp_path):
        config = _valid_config()
        config["wazuh"]["indexer_ca_path"] = str(target)
        assert config_check.find_problems(config, report_only=False) == []


def test_blank_indexer_ca_path_accepted() -> None:
    """A blank indexer_ca_path counts as unset."""
    config = _valid_config()
    config["wazuh"]["indexer_ca_path"] = "  "

    assert config_check.find_problems(config, report_only=False) == []


def test_valid_indexer_tls_values_are_clean() -> None:
    """Valid bool and empty-string values produce no problems."""
    config = _valid_config()
    config["wazuh"]["indexer_verify_tls"] = True
    config["wazuh"]["indexer_ca_path"] = ""

    assert config_check.find_problems(config, report_only=False) == []


def test_indexer_tls_checks_skipped_in_report_only() -> None:
    """The indexer TLS checks do not run in report-only mode."""
    config = _valid_config()
    config["wazuh"]["indexer_verify_tls"] = "true"
    config["wazuh"]["indexer_ca_path"] = 5

    assert config_check.find_problems(config, report_only=True) == []


@pytest.mark.parametrize("report_only", [False, True])
@pytest.mark.parametrize("value", [True, False])
def test_bool_json_output_accepted(value: bool, report_only: bool) -> None:
    """A bool [reports].json_output produces no problems in either mode."""
    config = _valid_config()
    config["reports"]["json_output"] = value

    assert config_check.find_problems(config, report_only=report_only) == []


@pytest.mark.parametrize("report_only", [False, True])
@pytest.mark.parametrize("value", ["true", 1])
def test_non_bool_json_output_reported(value: Any, report_only: bool) -> None:
    """A non-bool [reports].json_output is reported in normal and report-only mode."""
    config = _valid_config()
    config["reports"]["json_output"] = value

    problems = config_check.find_problems(config, report_only=report_only)

    expected = (
        "Config error: [reports].json_output has the wrong type — "
        f"expected bool, got {type(value).__name__}"
    )
    assert problems == [expected]


def _capture_generate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """Replace Reporter.generate with a fake that records its kwargs and returns a path."""
    captured: dict[str, Any] = {}

    def fake_generate(self: Any, data: Any, **kwargs: Any) -> Path:
        """Record the keyword arguments and return a report path."""
        captured.update(kwargs)
        return tmp_path / "report.md"

    monkeypatch.setattr(reporter.Reporter, "generate", fake_generate)
    return captured


def test_full_run_passes_run_params_to_generate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full run hands hours, agent, level and model to Reporter.generate as run_params."""
    captured = _capture_generate(monkeypatch, tmp_path)
    monkeypatch.setattr(wazuh_client.Client, "fetch_alerts", lambda self, **kwargs: [])
    monkeypatch.setattr(
        analyser, "analyse", lambda *args, **kwargs: {"summary": "s", "findings": [], "recommendations": []}
    )
    monkeypatch.setattr(analyser, "extract_alert_clusters", lambda alerts: [])
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--config", str(_write_config(tmp_path)), "--hours", "6", "--agent", "web01", "--level", "9"],
    )

    main.main()

    assert captured["run_params"] == {"hours": 6, "agent": "web01", "level": 9, "model": "any"}


def test_full_run_baseline_gets_run_params_without_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The model goes only to the report: the baseline update still gets hours, agent, level."""
    captured = _capture_generate(monkeypatch, tmp_path)
    seen: dict[str, Any] = {}

    def fake_update(self: Any, analysis: Any, clusters: Any = None, run_params: Any = None) -> None:
        """Record the run_params the baseline manager receives."""
        seen["run_params"] = run_params

    monkeypatch.setattr(baseline.Manager, "update", fake_update)
    monkeypatch.setattr(wazuh_client.Client, "fetch_alerts", lambda self, **kwargs: [])
    monkeypatch.setattr(
        analyser, "analyse", lambda *args, **kwargs: {"summary": "s", "findings": [], "recommendations": []}
    )
    monkeypatch.setattr(analyser, "extract_alert_clusters", lambda alerts: [])
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--config", str(_write_config(tmp_path)), "--hours", "6", "--agent", "web01", "--level", "9"],
    )

    main.main()

    assert seen["run_params"] == {"hours": 6, "agent": "web01", "level": 9}
    assert captured["run_params"]["model"] == "any"
    assert captured["run_params"] is not seen["run_params"]


def test_report_only_does_not_pass_run_params(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A --report-only run passes no run_params, so the JSON run key is null."""
    captured = _capture_generate(monkeypatch, tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["main.py", "--config", str(_write_config(tmp_path)), "--report-only"]
    )

    main.main()

    assert "trends" in captured
    assert "run_params" not in captured
