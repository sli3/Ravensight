"""Validate the shape of data/defaults/platform_agents.example.json."""

import json
from pathlib import Path


def test_platform_agents_example_is_valid_json() -> None:
    """The example agents map is a JSON object of str → {platform, vendor}."""
    path = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "defaults"
        / "platform_agents.example.json"
    )
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    for name, info in data.items():
        assert isinstance(name, str)
        assert isinstance(info, dict)
        assert "platform" in info and isinstance(info["platform"], str)
        assert "vendor" in info and isinstance(info["vendor"], str)
