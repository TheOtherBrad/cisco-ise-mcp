"""Secret resolution precedence: env var -> *_FILE -> keyring, plus error hints."""

import pytest


def test_env_beats_file_and_keyring(cfg, tmp_path, monkeypatch):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a")
    monkeypatch.setattr(cfg, "_keyring_get", lambda slug, key: "from-keyring")
    f = tmp_path / "pw.txt"
    f.write_text("from-file\n")
    monkeypatch.setenv("CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD_FILE", str(f))
    monkeypatch.setenv("CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD", "from-env")
    assert cfg._resolve_secret("radius-only", "ise_password") == "from-env"


def test_file_beats_keyring(cfg, tmp_path, monkeypatch):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a")
    monkeypatch.setattr(cfg, "_keyring_get", lambda slug, key: "from-keyring")
    f = tmp_path / "pw.txt"
    f.write_text("from-file\n")
    monkeypatch.setenv("CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD_FILE", str(f))
    assert cfg._resolve_secret("radius-only", "ise_password") == "from-file"


def test_keyring_fallback(cfg, monkeypatch):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a")
    monkeypatch.setattr(cfg, "_keyring_get", lambda slug, key: "from-keyring")
    assert cfg._resolve_secret("radius-only", "ise_password") == "from-keyring"


def test_env_var_name_slug_mapping(cfg, monkeypatch):
    cfg.add_deployment(name="Data Center 1", host="1.1.1.1", ers_username="a")
    monkeypatch.setattr(cfg, "_keyring_get", lambda slug, key: None)
    monkeypatch.setenv("CISCO_ISE__DATA_CENTER_1__ISE_PASSWORD", "x")
    assert cfg._resolve_secret("data-center-1", "ise_password") == "x"


def test_required_missing_raises_with_fix(cfg, monkeypatch):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a")
    monkeypatch.setattr(cfg, "_keyring_get", lambda slug, key: None)
    with pytest.raises(cfg.ConfigError) as ei:
        cfg._get_deployment_secret("radius-only", "ise_password", "RADIUS Only", required=True)
    assert "set-credential radius-only" in str(ei.value)


def test_not_required_returns_none(cfg, monkeypatch):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a")
    monkeypatch.setattr(cfg, "_keyring_get", lambda slug, key: None)
    assert cfg._get_deployment_secret("radius-only", "ise_password", "RADIUS Only", required=False) is None


def test_dataconnect_surface_requires_only_dc_password(cfg, monkeypatch):
    cfg.add_deployment(name="RADIUS Only", host="1.1.1.1", ers_username="a",
                       dataconnect_cert_path="/tmp/r.pem")
    monkeypatch.setattr(cfg, "_keyring_get", lambda slug, key: None)
    # ERS password is unset, but a Data Connect call must not demand it.
    monkeypatch.setenv("CISCO_ISE__RADIUS_ONLY__DATACONNECT_PASSWORD", "dcpw")
    c = cfg.get_deployment_config("radius-only", surface="dataconnect")
    assert c["dataconnect_password"] == "dcpw"
