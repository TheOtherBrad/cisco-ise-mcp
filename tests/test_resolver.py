"""Deployment selection: number / 'Deployment N' / name / slug, and error paths."""

import pytest


def _seed(cfg):
    cfg.add_deployment(name="RADIUS Only", host="10.1.1.1")
    cfg.add_deployment(name="TACACS Only", host="10.2.1.1")
    cfg.add_deployment(name="VPN Only", host="10.3.1.1")


def test_by_number_forms(cfg):
    _seed(cfg)
    assert cfg.resolve_deployment("1") == "radius-only"
    assert cfg.resolve_deployment("#2") == "tacacs-only"
    assert cfg.resolve_deployment("Deployment 3") == "vpn-only"
    assert cfg.resolve_deployment(" deployment  2 ") == "tacacs-only"


def test_by_name_case_insensitive(cfg):
    _seed(cfg)
    assert cfg.resolve_deployment("vpn only") == "vpn-only"
    assert cfg.resolve_deployment("RADIUS Only") == "radius-only"


def test_by_slug(cfg):
    _seed(cfg)
    assert cfg.resolve_deployment("tacacs-only") == "tacacs-only"


def test_none_uses_default(cfg):
    _seed(cfg)
    cfg.set_default("vpn-only")
    assert cfg.resolve_deployment(None) == "vpn-only"


def test_none_uses_single(cfg):
    cfg.add_deployment(name="Solo Lab", host="1.1.1.1")
    assert cfg.resolve_deployment(None) == "solo-lab"
    assert cfg.resolve_deployment("") == "solo-lab"


def test_out_of_range(cfg):
    _seed(cfg)
    with pytest.raises(cfg.ConfigError):
        cfg.resolve_deployment("9")


def test_unknown_name(cfg):
    _seed(cfg)
    with pytest.raises(cfg.ConfigError):
        cfg.resolve_deployment("nope")


def test_empty_registry_message(cfg):
    with pytest.raises(cfg.ConfigError) as ei:
        cfg.resolve_deployment(None)
    assert "No ISE deployments" in str(ei.value)


def test_ambiguous_without_default(cfg):
    _seed(cfg)
    reg = cfg.load_registry()
    reg["default"] = None
    cfg.save_registry(reg)
    with pytest.raises(cfg.ConfigError) as ei:
        cfg.resolve_deployment(None)
    assert "more than one" in str(ei.value).lower()
