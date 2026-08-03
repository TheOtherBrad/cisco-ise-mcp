"""Security hardening: TLS defaults/warnings, URL-encoding, row cap, audit trail."""

import pytest


# ── verify_ssl now defaults ON, and OFF is surfaced as a warning ──

def test_add_defaults_verify_ssl_on(cfg):
    cfg.add_deployment(name="Prod", host="1.1.1.1", ers_username="a")
    assert cfg.get_deployment_config("prod")["verify_ssl"] is True


def test_verify_ssl_off_is_warned(cfg):
    res = cfg.add_deployment(name="Lab", host="1.1.1.1", ers_username="a", verify_ssl=False)
    assert any("TLS verification is OFF" in w for w in res["warnings"])


def test_validate_warns_when_verify_off(cfg, monkeypatch):
    cfg.add_deployment(name="Lab", host="1.1.1.1", ers_username="a",
                       verify_ssl=False, dataconnect_enabled=False)
    monkeypatch.setattr(cfg, "_keyring_get", lambda s, k: "pw")
    v = cfg.validate_deployment("lab")
    assert any("verify_ssl is OFF" in w for w in v["warnings"])


# ── keyring-unavailable is distinguished from no-password ──

def test_missing_secret_notes_keyring_error(cfg, monkeypatch):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a")

    def _boom(slug, key):
        cfg._LAST_KEYRING_ERROR = "NoKeyringError: no backend"
        return None

    monkeypatch.setattr(cfg, "_keyring_get", _boom)
    with pytest.raises(cfg.ConfigError) as ei:
        cfg._get_deployment_secret("radius-only", "ise_password", "RADIUS Only")
    assert "keyring could not be read" in str(ei.value)


# ── ERS/OpenAPI URL-encoding & traversal guards ──

def test_ers_get_by_name_encodes_slashes():
    from cisco_ise_mcp.openapi.client import ISEErSClient
    c = ISEErSClient(host="h", username="u", password="p")
    # Build the URL the same way the client does, without a live call.
    from urllib.parse import quote
    name = "../../admin/secret"
    assert quote(name, safe="") == "..%2F..%2Fadmin%2Fsecret"


def test_ers_request_rejects_traversal():
    import asyncio
    from cisco_ise_mcp.openapi.client import ISEErSClient
    c = ISEErSClient(host="h", username="u", password="p")
    with pytest.raises(ValueError):
        asyncio.run(c.request("GET", "ers/config/../../etc"))


def test_ers_request_requires_ers_prefix():
    import asyncio
    from cisco_ise_mcp.openapi.client import ISEErSClient
    c = ISEErSClient(host="h", username="u", password="p")
    with pytest.raises(ValueError):
        asyncio.run(c.request("GET", "api/v1/anything"))


# ── Data Connect raw-query row cap ──

def test_build_query_still_bounded():
    from cisco_ise_mcp.dataconnect.client import build_query
    sql, binds = build_query("radius_authentications", {"limit": 999999})
    assert binds["maxrows"] == 10000


# ── audit classifier ──

def test_audit_classifies_mutations():
    from cisco_ise_mcp import server
    assert server._is_mutating("ise_ers_create", {}) is True
    assert server._is_mutating("ise_ers_delete", {}) is True
    assert server._is_mutating("ise_ers_list", {}) is False
    assert server._is_mutating("ise_ers_request", {"method": "post"}) is True
    assert server._is_mutating("ise_ers_request", {"method": "get"}) is False
    assert server._is_mutating("ise_add_deployment", {}) is True
    assert server._is_mutating("ise_dc_query", {}) is False
    assert server._is_mutating("ise_mnt_session_delete_by_id", {}) is True


def test_audit_record_redacts_and_appends(cfg, tmp_path, monkeypatch):
    monkeypatch.setenv("CISCO_ISE_MCP_HOME", str(tmp_path))
    from cisco_ise_mcp import audit
    audit.record("ise_ers_create", {"resource": "endpoint", "data": {"mac": "x"}},
                 deployment="prod", status="ok")
    import json
    line = json.loads((tmp_path / "audit.log").read_text().splitlines()[0])
    assert line["action"] == "ise_ers_create"
    assert line["arguments"]["data"] == "<redacted>"
    assert line["deployment"] == "prod"


# ── Data Connect thin-mode TLS context (Finding #1) ──

import ssl as _ssl


def _dc_client(**kw):
    from cisco_ise_mcp.dataconnect.client import ISEDataConnectClient
    return ISEDataConnectClient(host="h", password="p", **kw)


def test_dc_pinned_without_cert_or_wallet_refuses():
    """verify_ssl on, os_trust off, no cert/wallet -> refuse (no OS-store fallback)."""
    c = _dc_client(verify_ssl=True, os_trust=False, cert_path="", wallet_path="")
    with pytest.raises(ValueError) as ei:
        c._thin_ssl_context()
    assert "os_trust" in str(ei.value)


def test_dc_pinned_cert_disables_hostname(tmp_path, monkeypatch):
    """A real pinned cert IS the identity -> hostname check off, chain required."""
    cafile = tmp_path / "dc.pem"
    cafile.write_text("dummy")  # contents parsed by load_verify_locations (stubbed)
    monkeypatch.setattr(_ssl.SSLContext, "load_verify_locations", lambda self, cafile=None: None)
    c = _dc_client(verify_ssl=True, os_trust=False, cert_path=str(cafile))
    ctx = c._thin_ssl_context()
    assert ctx.check_hostname is False
    assert ctx.verify_mode == _ssl.CERT_REQUIRED


def test_dc_os_trust_keeps_hostname_on():
    """CA-store trust must keep the hostname check on (else any CA cert passes)."""
    c = _dc_client(verify_ssl=True, os_trust=True)
    ctx = c._thin_ssl_context()
    assert ctx.check_hostname is True
    assert ctx.verify_mode == _ssl.CERT_REQUIRED


def test_dc_verify_off_is_cert_none():
    c = _dc_client(verify_ssl=False)
    ctx = c._thin_ssl_context()
    assert ctx.verify_mode == _ssl.CERT_NONE


# ── Passthrough surface confinement (Finding #2) ──

def test_mnt_request_rejects_traversal_and_off_surface():
    import asyncio
    from cisco_ise_mcp.monitoring.client import ISEMonitoringClient
    c = ISEMonitoringClient(host="h", username="u", password="p")
    with pytest.raises(ValueError):
        asyncio.run(c.request("GET", "admin/API/mnt/../../etc"))
    with pytest.raises(ValueError):
        asyncio.run(c.request("GET", "admin/API/config"))  # off-surface
    with pytest.raises(ValueError):
        asyncio.run(c.request("GET", "api/v1/anything"))


def test_openapi_request_requires_api_prefix():
    import asyncio
    from cisco_ise_mcp.openapi.tools_openapi import ISEOpenAPIClient
    c = ISEOpenAPIClient(host="h", username="u", password="p")
    with pytest.raises(ValueError):
        asyncio.run(c.request("GET", "api/v1/../../etc"))
    with pytest.raises(ValueError):
        asyncio.run(c.request("GET", "ers/config/endpoint"))  # off-surface
    with pytest.raises(ValueError):
        asyncio.run(c.request("GET", "admin/API/mnt/Version"))
