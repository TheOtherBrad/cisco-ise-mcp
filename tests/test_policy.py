"""Policy/hardening tests: destructive-tool gate (#3), dc_query guard (#6),
refresh URL allowlist (#4), and the auth abstraction (PR3)."""

import asyncio
import importlib.util
from pathlib import Path

import pytest


# ── Destructive-tool classification & schema marking (Finding #3) ──

def test_is_destructive_classification():
    from cisco_ise_mcp import server
    assert server._is_destructive("ise_ers_delete", {}) is True
    assert server._is_destructive("ise_ers_list", {}) is False
    assert server._is_destructive("ise_ers_request", {"method": "DELETE"}) is True
    assert server._is_destructive("ise_ers_request", {"method": "GET"}) is False
    assert server._is_destructive("ise_openapi_patch_rollback", {}) is True
    assert server._is_destructive("ise_openapi_cert_trusted_delete", {}) is True
    assert server._is_destructive("ise_mnt_coa_disconnect", {}) is True
    assert server._is_destructive("ise_mnt_session_delete_by_id", {}) is True
    assert server._is_destructive("ise_mnt_request", {"method": "DELETE"}) is True
    assert server._is_destructive("ise_mnt_request", {"method": "GET"}) is False
    assert server._is_destructive("ise_dc_query", {}) is False


def test_destructive_tools_get_confirm_and_label():
    from cisco_ise_mcp import server
    by_name = {t.name: t for t in server.all_tools()}
    dele = by_name["ise_ers_delete"]
    schema = server.compat.tool_input_schema(dele)
    assert "confirm" in schema["properties"]
    assert dele.description.startswith("[DESTRUCTIVE]")
    # A read tool is not marked.
    assert "confirm" not in server.compat.tool_input_schema(by_name["ise_ers_list"]).get("properties", {})


# ── Runtime gate: blocked > allow-flag > confirm (Finding #3) ──

def _call(name, args):
    from cisco_ise_mcp import server
    res = asyncio.run(server.call_tool(name, args))
    return res.data


def test_gate_denies_when_flag_off(cfg, monkeypatch):
    monkeypatch.delenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", raising=False)
    out = _call("ise_ers_delete", {"resource": "endpoint", "id": "1", "confirm": True})
    assert out["error"] == "destructive_disabled"


def test_gate_requires_confirm_even_when_enabled(cfg, monkeypatch):
    monkeypatch.setenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", "1")
    out = _call("ise_ers_delete", {"resource": "endpoint", "id": "1"})
    assert out["error"] == "confirmation_required"


def test_gate_blocked_tool_overrides_allow(cfg, monkeypatch):
    monkeypatch.setenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", "1")
    monkeypatch.setenv("CISCO_ISE_MCP_BLOCKED_TOOLS", "ise_ers_delete")
    out = _call("ise_ers_delete", {"resource": "endpoint", "id": "1", "confirm": True})
    assert out["error"] == "disabled_by_policy"


def test_gate_pass_reaches_dispatch_and_audits(cfg, tmp_path, monkeypatch):
    # No deployment configured, so dispatch fails with a config error — but the gate
    # has been passed, so we get a real error (not a gate refusal) plus attempt+error
    # audit lines.
    monkeypatch.setenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", "1")
    out = _call("ise_ers_delete", {"resource": "endpoint", "id": "1", "confirm": True})
    assert out.get("error") not in ("destructive_disabled", "confirmation_required", "disabled_by_policy")
    import json
    statuses = [json.loads(l)["status"]
                for l in (Path(tmp_path) / "audit.log").read_text().splitlines()]
    assert "attempt" in statuses and "error" in statuses


def test_denied_call_is_audited(cfg, tmp_path, monkeypatch):
    monkeypatch.delenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", raising=False)
    _call("ise_ers_delete", {"resource": "endpoint", "id": "1", "confirm": True})
    import json
    statuses = [json.loads(l)["status"]
                for l in (Path(tmp_path) / "audit.log").read_text().splitlines()]
    assert "denied" in statuses


# ── Transport-aware error verbosity (Finding #7) ──

def test_error_payload_verbose_local_redacted_remote():
    from cisco_ise_mcp import server
    exc = RuntimeError("secret host 10.1.1.1 unreachable")
    server.set_transport("local")
    local = server._error_payload(exc)
    assert "10.1.1.1" in local["error"]
    server.set_transport("remote")
    remote = server._error_payload(exc)
    assert "10.1.1.1" not in remote["error"] and "error_id" in remote
    server.set_transport("local")  # restore


# ── ise_dc_query guard (Finding #6) ──

def test_validate_raw_select_rules():
    from cisco_ise_mcp.dataconnect.client import validate_raw_select
    allowed = {"RADIUS_AUTHENTICATIONS"}
    # OK: catalog view and DUAL.
    validate_raw_select("SELECT * FROM radius_authentications", allowed)
    validate_raw_select("SELECT 1 FROM DUAL", allowed)
    for bad in [
        "SELECT * FROM radius_authentications -- drop",
        "SELECT * FROM radius_authentications /* x */",
        "SELECT 1 FROM DUAL; SELECT 1 FROM DUAL",
        "SELECT * FROM user_views",
        "DELETE FROM radius_authentications",
    ]:
        with pytest.raises(ValueError):
            validate_raw_select(bad, allowed)


# ── refresh_catalog URL allowlist (Finding #4) ──

def _load_refresh():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "_refresh_catalog", root / "scripts" / "refresh_catalog.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_check_url_enforces_https_and_host():
    mod = _load_refresh()
    mod._check_url("https://pubhub.devnetcloud.com/media/x.yaml")
    mod._check_url("https://developer.cisco.com/docs/dataconnect/database-views/")
    with pytest.raises(RuntimeError):
        mod._check_url("http://pubhub.devnetcloud.com/media/x.yaml")  # not https
    with pytest.raises(RuntimeError):
        mod._check_url("https://evil.example.com/x.yaml")  # unlisted host


# ── auth abstraction (PR3) ──

def test_null_authenticator_allows_all():
    from cisco_ise_mcp.auth import NullAuthenticator
    p = NullAuthenticator().authenticate({})
    assert p is not None and p.source == "stdio"


def test_allowlist_permit_deny_and_failclosed():
    from cisco_ise_mcp.auth import AllowListAuthenticator
    a = AllowListAuthenticator(allow={"good"}, deny={"bad"})
    assert a.authenticate({"token": "good"}) is not None
    assert a.authenticate({"token": "bad"}) is None
    assert a.authenticate({"token": "unknown"}) is None
    assert AllowListAuthenticator(allow=set()).authenticate({"token": "x"}) is None


def test_build_authenticator_selects_mode(cfg, monkeypatch):
    from cisco_ise_mcp import auth
    monkeypatch.delenv(auth._ENV_MODE, raising=False)
    assert isinstance(auth.build_authenticator(), auth.NullAuthenticator)
    monkeypatch.setenv(auth._ENV_MODE, "allowlist")
    assert isinstance(auth.build_authenticator(), auth.AllowListAuthenticator)
