"""update_deployment: partial patches, slug stability, and error checking."""

import io

import pytest


class _FakeTTY(io.StringIO):
    def isatty(self):
        return True


def _seed(cfg):
    cfg.add_deployment(name="TACACS Only", host="10.2.1.1", ers_username="ers-admin",
                       dataconnect_enabled=False)
    return "tacacs-only"


def test_partial_update_changes_only_named_fields(cfg):
    slug = _seed(cfg)
    res = cfg.update_deployment(slug, host="10.2.1.5", dataconnect_enabled=True,
                                dataconnect_cert_path="/opt/ise/t.pem")
    assert res["status"] == "updated"
    assert set(res["changed"]) == {"host", "dataconnect.enabled", "dataconnect.cert_path"}
    c = cfg.get_deployment_config(slug)
    assert c["ise_host"] == "10.2.1.5"
    assert c["dataconnect_cert_path"] == "/opt/ise/t.pem"
    # untouched fields keep their values
    assert c["ise_username"] == "ers-admin"
    assert c["ise_ers_port"] == 443


def test_noop_update_reports_unchanged(cfg):
    slug = _seed(cfg)
    res = cfg.update_deployment(slug, host="10.2.1.1")  # same as seeded
    assert res["status"] == "unchanged"
    assert res["changed"] == []


def test_update_by_number_and_name_selectors(cfg):
    _seed(cfg)
    assert cfg.update_deployment("1", host="10.2.2.2")["slug"] == "tacacs-only"
    assert cfg.update_deployment("TACACS Only", host="10.2.3.3")["slug"] == "tacacs-only"


def test_rename_same_slug_is_label_only(cfg):
    slug = _seed(cfg)
    # Different case/spacing -> same slug -> allowed without reslug, identity kept.
    res = cfg.update_deployment(slug, name="tacacs only")
    assert res["slug"] == "tacacs-only"
    assert res["name"] == "tacacs only"
    assert "name" in res["changed"]


def test_rename_changing_slug_requires_reslug(cfg):
    slug = _seed(cfg)
    with pytest.raises(cfg.ReslugRequired) as ei:
        cfg.update_deployment(slug, name="TACACS Primary")
    assert ei.value.old_slug == "tacacs-only"
    assert ei.value.new_slug == "tacacs-primary"


def test_reslug_migrates_slug_and_credentials(cfg, monkeypatch):
    slug = _seed(cfg)
    cfg.add_deployment(name="VPN Only", host="10.3.1.1")  # second entry to prove ordering
    # Pretend a keyring password exists for the old slug; capture the migration calls.
    moved, deleted = [], []
    monkeypatch.setattr(cfg, "_keyring_get",
                        lambda s, k: "secret" if (s == "tacacs-only" and k == "ise_password") else None)
    monkeypatch.setattr(cfg, "set_credential", lambda s, k, v: moved.append((s, k, v)))
    monkeypatch.setattr(cfg, "delete_credentials", lambda s: deleted.append(s))

    res = cfg.update_deployment("1", name="TACACS Primary", reslug=True)
    assert res["slug"] == "tacacs-primary"
    assert res["previous_slug"] == "tacacs-only"
    assert res["number"] == 1  # position preserved
    assert set(res["changed"]) >= {"name", "slug"}
    assert moved == [("tacacs-primary", "ise_password", "secret")]
    assert deleted == ["tacacs-only"]
    slugs = [d["slug"] for d in cfg.list_deployments()]
    assert slugs == ["tacacs-primary", "vpn-only"]


def test_reslug_warns_on_env_var_secret(cfg, monkeypatch):
    slug = _seed(cfg)
    monkeypatch.setattr(cfg, "_keyring_get", lambda s, k: None)
    monkeypatch.setenv("CISCO_ISE__TACACS_ONLY__ISE_PASSWORD", "x")
    res = cfg.update_deployment(slug, name="TACACS Primary", reslug=True)
    assert res["slug"] == "tacacs-primary"
    assert any("CISCO_ISE__TACACS_PRIMARY__ISE_PASSWORD" in w for w in res.get("warnings", []))


def test_reslug_updates_default_pointer(cfg, monkeypatch):
    slug = _seed(cfg)  # first add -> becomes default
    monkeypatch.setattr(cfg, "_keyring_get", lambda s, k: None)
    assert cfg.get_default() == "tacacs-only"
    cfg.update_deployment(slug, name="TACACS Primary", reslug=True)
    assert cfg.get_default() == "tacacs-primary"


def test_rename_collision_rejected(cfg):
    cfg.add_deployment(name="RADIUS Only", host="10.1.1.1")
    cfg.add_deployment(name="TACACS Only", host="10.2.1.1")
    with pytest.raises(cfg.ConfigError):
        cfg.update_deployment("tacacs-only", name="RADIUS Only")


def test_invalid_values_rejected(cfg):
    slug = _seed(cfg)
    for bad in ({"dataconnect_mode": "bogus"}, {"host": ""}, {"ers_port": "nope"}):
        with pytest.raises(cfg.ConfigError):
            cfg.update_deployment(slug, **bad)


def test_unknown_field_rejected(cfg):
    slug = _seed(cfg)
    with pytest.raises(cfg.ConfigError) as ei:
        cfg.update_deployment(slug, bogus_field="x")
    assert "Unknown field" in str(ei.value)


def test_unknown_deployment_rejected(cfg):
    with pytest.raises(cfg.ConfigError):
        cfg.update_deployment("does-not-exist", host="1.2.3.4")


def test_empty_string_clears_cert_path(cfg):
    cfg.add_deployment(name="RADIUS Only", host="10.1.1.1", dataconnect_cert_path="/opt/r.pem")
    res = cfg.update_deployment("radius-only", dataconnect_cert_path="")
    assert "dataconnect.cert_path" in res["changed"]
    assert cfg.get_deployment_config("radius-only")["dataconnect_cert_path"] == ""


def test_update_sets_dataconnect_host(cfg):
    slug = _seed(cfg)  # admin host 10.2.1.1
    res = cfg.update_deployment(slug, dataconnect_host="10.2.1.9")
    assert "dataconnect.host" in res["changed"]
    c = cfg.get_deployment_config(slug)
    assert c["ise_host"] == "10.2.1.1"        # admin host untouched
    assert c["dataconnect_host"] == "10.2.1.9"


def test_update_clears_dataconnect_host_reverts_to_admin(cfg):
    slug = _seed(cfg)
    cfg.update_deployment(slug, dataconnect_host="10.2.1.9")
    res = cfg.update_deployment(slug, dataconnect_host="")
    assert "dataconnect.host" in res["changed"]
    # Cleared -> Data Connect falls back to the admin host again.
    assert cfg.get_deployment_config(slug)["dataconnect_host"] == "10.2.1.1"


# ── CLI prompt path: renaming without --reslug asks to proceed ──

def test_cli_update_prompt_yes_reslugs(cfg, monkeypatch):
    from cisco_ise_mcp import cli
    cfg.add_deployment(name="TACACS Only", host="10.2.1.1", ers_username="a", dataconnect_enabled=False)
    monkeypatch.setattr(cfg, "_keyring_get", lambda s, k: None)
    monkeypatch.setattr(cli.sys, "stdin", _FakeTTY())   # interactive
    monkeypatch.setattr("builtins.input", lambda *a, **k: "y")
    rc = cli.main(["update", "tacacs-only", "--name", "TACACS Primary"])
    assert rc == 0
    assert [d["slug"] for d in cfg.list_deployments()] == ["tacacs-primary"]


def test_cli_update_prompt_no_aborts(cfg, monkeypatch):
    from cisco_ise_mcp import cli
    cfg.add_deployment(name="TACACS Only", host="10.2.1.1", ers_username="a", dataconnect_enabled=False)
    monkeypatch.setattr(cfg, "_keyring_get", lambda s, k: None)
    monkeypatch.setattr(cli.sys, "stdin", _FakeTTY())
    monkeypatch.setattr("builtins.input", lambda *a, **k: "n")
    rc = cli.main(["update", "tacacs-only", "--name", "TACACS Primary"])
    assert rc == 0
    # aborted -> slug unchanged
    assert [d["slug"] for d in cfg.list_deployments()] == ["tacacs-only"]


def test_cli_update_noninteractive_blocks_reslug(cfg, monkeypatch):
    from cisco_ise_mcp import cli
    cfg.add_deployment(name="TACACS Only", host="10.2.1.1", ers_username="a", dataconnect_enabled=False)
    monkeypatch.setattr(cfg, "_keyring_get", lambda s, k: None)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())  # isatty() False
    rc = cli.main(["update", "tacacs-only", "--name", "TACACS Primary"])
    assert rc == 1
    assert [d["slug"] for d in cfg.list_deployments()] == ["tacacs-only"]
