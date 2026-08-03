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
