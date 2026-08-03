"""Monitoring (MAPI) enable flag, Data Connect OS-trust, and refresh auto-gating."""

import importlib.util
import ssl
from argparse import Namespace
from pathlib import Path

import pytest


def _load_refresh():
    """Load scripts/refresh_catalog.py as a throwaway module (for _resolve_want)."""
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "_refresh_catalog_test", root / "scripts" / "refresh_catalog.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Monitoring (MAPI / MnT) ──────────────────────────────────────────────────

def test_add_defaults_monitoring_off(cfg):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a")
    assert cfg.list_deployments()[0]["monitoring_enabled"] is False


def test_add_can_enable_monitoring(cfg):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a",
                       monitoring_enabled=True)
    assert cfg.list_deployments()[0]["monitoring_enabled"] is True


def test_absent_monitoring_key_is_enabled(cfg):
    # Legacy registry: a deployment with no monitoring_enabled key counts as ENABLED.
    cfg.add_deployment(name="Old One", host="1.1.1.1", ers_username="a")
    reg = cfg.load_registry()
    reg["deployments"]["old-one"].pop("monitoring_enabled", None)
    cfg.save_registry(reg)
    assert cfg.list_deployments()[0]["monitoring_enabled"] is True


def test_monitoring_surface_refused_when_disabled(cfg, monkeypatch):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a")
    monkeypatch.setenv("CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD", "pw")
    with pytest.raises(cfg.ConfigError) as ei:
        cfg.get_deployment_config("radius-only", surface="monitoring")
    msg = str(ei.value)
    assert "MAPI" in msg and "--enable-monitoring" in msg


def test_monitoring_surface_ok_when_enabled(cfg, monkeypatch):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a",
                       monitoring_enabled=True)
    monkeypatch.setenv("CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD", "pw")
    c = cfg.get_deployment_config("radius-only", surface="monitoring")
    assert c["ise_password"] == "pw" and c["monitoring_enabled"] is True


def test_update_toggles_monitoring(cfg):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a")
    res = cfg.update_deployment("radius-only", monitoring_enabled=True)
    assert "monitoring_enabled" in res["changed"]
    assert cfg.list_deployments()[0]["monitoring_enabled"] is True
    cfg.update_deployment("radius-only", monitoring_enabled=False)
    assert cfg.list_deployments()[0]["monitoring_enabled"] is False


# ── Data Connect OS trust ────────────────────────────────────────────────────

def test_os_trust_skips_cert_requirement(cfg):
    cfg.add_deployment(name="CA Lab", host="1.1.1.1", ers_username="a",
                       dataconnect_os_trust=True)  # no cert_path
    v = cfg.validate_deployment("ca-lab")
    assert not any("cert_path" in f for f in v["missing_fields"])
    assert v["dataconnect_os_trust"] is True


def test_os_trust_surfaced_in_config(cfg):
    cfg.add_deployment(name="CA Lab", host="1.1.1.1", ers_username="a",
                       dataconnect_os_trust=True)
    assert cfg.get_deployment_config("ca-lab")["dataconnect_os_trust"] is True


def test_no_os_trust_still_requires_cert(cfg):
    cfg.add_deployment(name="Self Lab", host="1.1.1.1", ers_username="a")  # DC on, no cert
    v = cfg.validate_deployment("self-lab")
    assert any("cert_path" in f for f in v["missing_fields"])


def test_update_toggles_os_trust(cfg):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a",
                       dataconnect_cert_path="/opt/r.pem")
    res = cfg.update_deployment("radius-only", dataconnect_os_trust=True)
    assert "dataconnect.os_trust" in res["changed"]
    assert cfg.get_deployment_config("radius-only")["dataconnect_os_trust"] is True


def test_update_accepts_new_fields(cfg):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a")
    # Neither field should be rejected as "Unknown field".
    res = cfg.update_deployment("radius-only", monitoring_enabled=True,
                                dataconnect_os_trust=True)
    assert res["status"] == "updated"


def test_dc_client_os_trust_builds_context_without_cert():
    from cisco_ise_mcp.dataconnect.client import ISEDataConnectClient
    # A bogus cert path is ignored when os_trust is on; context still validates.
    client = ISEDataConnectClient(host="h", cert_path="/does/not/exist.pem",
                                  os_trust=True, verify_ssl=True)
    ctx = client._thin_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    # os_trust binds to the hostname (CA-signed cert must carry the node SAN);
    # only the pinned-cert path disables hostname checking.
    assert ctx.check_hostname is True


def test_dc_client_pinned_cert_disables_hostname_check(tmp_path, monkeypatch):
    from cisco_ise_mcp.dataconnect.client import ISEDataConnectClient
    # A REAL pinned cert IS the identity, so hostname matching is off. (Cert
    # parsing is stubbed so the test needs no on-disk CA material.)
    cafile = tmp_path / "dc.pem"
    cafile.write_text("dummy")
    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", lambda self, cafile=None: None)
    client = ISEDataConnectClient(host="h", cert_path=str(cafile),
                                  os_trust=False, verify_ssl=True)
    ctx = client._thin_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is False


def test_dc_client_pinned_without_cert_refuses():
    from cisco_ise_mcp.dataconnect.client import ISEDataConnectClient
    # verify_ssl on, os_trust off, and no pinned cert/wallet: refuse rather than
    # silently trust the OS CA store with hostname checking disabled (CWE-297).
    client = ISEDataConnectClient(host="h", cert_path="/does/not/exist.pem",
                                  os_trust=False, verify_ssl=True)
    with pytest.raises(ValueError):
        client._thin_ssl_context()


# ── Catalog refresh auto-gating (scripts/refresh_catalog.py:_resolve_want) ────

def test_refresh_only_overrides_registry():
    mod = _load_refresh()
    assert mod._resolve_want(Namespace(only="ers", all_surfaces=False)) == {"ers"}


def test_refresh_all_forces_everything():
    mod = _load_refresh()
    assert mod._resolve_want(Namespace(only=None, all_surfaces=True)) == {
        "ers", "openapi", "monitoring", "dc"}


def test_refresh_auto_gates_by_registry(cfg):
    mod = _load_refresh()
    # No DC, no MAPI -> only the always-on surfaces.
    cfg.add_deployment(name="Bare", host="1.1.1.1", ers_username="a",
                       dataconnect_enabled=False)
    assert mod._resolve_want(Namespace(only=None, all_surfaces=False)) == {"ers", "openapi"}
    # A DC-enabled deployment pulls in 'dc'.
    cfg.add_deployment(name="With DC", host="2.2.2.2", ers_username="a",
                       dataconnect_cert_path="/x.pem")
    assert "dc" in mod._resolve_want(Namespace(only=None, all_surfaces=False))
    # Enabling MAPI pulls in 'monitoring'.
    cfg.update_deployment("bare", monitoring_enabled=True)
    assert "monitoring" in mod._resolve_want(Namespace(only=None, all_surfaces=False))
