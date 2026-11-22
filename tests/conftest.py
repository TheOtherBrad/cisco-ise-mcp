"""Shared fixtures: every test runs against an isolated, empty registry home."""

import os

import pytest


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    """Point the registry at a throwaway dir and clear any namespaced secrets."""
    monkeypatch.setenv("CISCO_ISE_MCP_HOME", str(tmp_path))
    for key in list(os.environ):
        if key.startswith("CISCO_ISE__"):
            monkeypatch.delenv(key, raising=False)
    from cisco_ise_mcp import config
    return config


def read_audit(home):
    """Parsed JSON entries from today's daily audit log under ``home/logs``."""
    import json
    from datetime import datetime
    from pathlib import Path
    path = Path(home) / "logs" / f"{datetime.now().astimezone():%Y-%m-%d}.log"
    return [json.loads(line.split(" ", 1)[1]) for line in path.read_text().splitlines()]
