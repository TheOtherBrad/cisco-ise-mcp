"""Registry CRUD, ordering, atomic writes, and validation behavior."""

import pytest


def test_add_first_sets_default(cfg):
    r = cfg.add_deployment(name="RADIUS Only", host="10.1.1.1", ers_username="a")
    assert r["slug"] == "radius-only"
    assert r["is_default"] is True
    assert cfg.get_default() == "radius-only"


def test_order_and_numbering_persist(cfg):
    cfg.add_deployment(name="A One", host="1.1.1.1")
    cfg.add_deployment(name="B Two", host="2.2.2.2")
    cfg.add_deployment(name="C Three", host="3.3.3.3")
    deps = cfg.list_deployments()  # reloaded fresh from disk
    assert [d["number"] for d in deps] == [1, 2, 3]
    assert [d["slug"] for d in deps] == ["a-one", "b-two", "c-three"]


def test_atomic_write_leaves_no_tmp(cfg):
    cfg.add_deployment(name="X One", host="1.1.1.1")
    leftovers = list(cfg.get_home().glob(".deployments.*"))
    assert leftovers == []


def test_make_default_flag(cfg):
    cfg.add_deployment(name="A One", host="1.1.1.1")
    cfg.add_deployment(name="B Two", host="2.2.2.2", make_default=True)
    assert cfg.get_default() == "b-two"


def test_remove_repairs_default(cfg):
    cfg.add_deployment(name="A One", host="1.1.1.1")  # auto-default
    cfg.add_deployment(name="B Two", host="2.2.2.2")
    cfg.remove_deployment("1", confirm=True)
    assert cfg.get_default() == "b-two"


def test_remove_requires_confirm(cfg):
    cfg.add_deployment(name="A One", host="1.1.1.1")
    with pytest.raises(cfg.ConfigError):
        cfg.remove_deployment("a-one", confirm=False)


def test_duplicate_rejected(cfg):
    cfg.add_deployment(name="A One", host="1.1.1.1")
    with pytest.raises(cfg.ConfigError):
        cfg.add_deployment(name="A One", host="9.9.9.9")


def test_numeric_names_rejected(cfg):
    with pytest.raises(cfg.ConfigError):
        cfg.add_deployment(name="2", host="1.1.1.1")
    with pytest.raises(cfg.ConfigError):
        cfg.add_deployment(name="Deployment 3", host="1.1.1.1")


def test_missing_fields_aggregated(cfg):
    with pytest.raises(cfg.ConfigError) as ei:
        cfg.add_deployment(name="", host="")
    msg = str(ei.value)
    assert "name" in msg and "host" in msg


def test_bad_port_reported(cfg):
    with pytest.raises(cfg.ConfigError) as ei:
        cfg.add_deployment(name="A One", host="1.1.1.1", ers_port="notaport")
    assert "ers_port" in str(ei.value)


def test_corrupt_registry_raises(cfg):
    path = cfg.get_registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not valid json ]")
    with pytest.raises(cfg.ConfigError):
        cfg.load_registry()


def test_cert_path_roundtrips_windows_style(cfg):
    win = r"C:\cisco-ise-mcp\radius-dataconnect.pem"
    cfg.add_deployment(name="RADIUS Only", host="10.1.1.1", dataconnect_cert_path=win)
    c = cfg.get_deployment_config("radius-only")
    assert c["dataconnect_cert_path"] == win  # separators preserved unchanged


def test_dataconnect_host_defaults_to_admin_host(cfg):
    # No dataconnect_host given -> Data Connect reuses the admin host (back-compat).
    cfg.add_deployment(name="RADIUS Only", host="10.1.1.1")
    c = cfg.get_deployment_config("radius-only")
    assert c["dataconnect_host"] == "10.1.1.1"
    d = cfg.list_deployments()[0]
    assert d["dataconnect_host"] == "10.1.1.1"
    assert d["dataconnect_host_explicit"] is False


def test_dataconnect_host_override_used_for_mnt(cfg):
    # A distinct MnT node is honored for Data Connect but not for the admin host.
    cfg.add_deployment(name="Campus", host="10.1.1.1", dataconnect_host="10.1.1.5")
    c = cfg.get_deployment_config("campus")
    assert c["ise_host"] == "10.1.1.1"        # ERS/OpenAPI stay on the PAN
    assert c["dataconnect_host"] == "10.1.1.5"  # Data Connect targets the MnT node
    d = cfg.list_deployments()[0]
    assert d["dataconnect_host"] == "10.1.1.5"
    assert d["dataconnect_host_explicit"] is True


def test_legacy_registry_without_dc_host_falls_back(cfg):
    # Simulate a pre-existing registry whose dataconnect block has no 'host' key.
    cfg.add_deployment(name="Old One", host="10.9.9.9")
    reg = cfg.load_registry()
    reg["deployments"]["old-one"]["dataconnect"].pop("host", None)
    cfg.save_registry(reg)
    c = cfg.get_deployment_config("old-one")
    assert c["dataconnect_host"] == "10.9.9.9"


def test_ensure_registry_creates_blank(cfg):
    import json
    path = cfg.ensure_registry()
    assert path.is_file()
    assert json.loads(path.read_text()) == {"version": 2, "default": None, "deployments": {}}
    assert cfg.list_deployments() == []


def test_ensure_registry_preserves_existing(cfg):
    cfg.add_deployment(name="A One", host="1.1.1.1")
    cfg.ensure_registry()  # must NOT blank an existing registry
    assert [d["slug"] for d in cfg.list_deployments()] == ["a-one"]
