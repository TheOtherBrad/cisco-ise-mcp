#!/usr/bin/env python3
"""
Validate the Cisco ISE MCP server — both tool/dispatch coverage and runtime
prerequisites (task 2: "validate all required skills are available").

Offline only: no connection to ISE is made. Asserts that every tool resolves to
a real catalog entry / path / view, that the curated Open API paths template
correctly, and that the Python prerequisites import.

Exit code 0 = all checks passed, 1 = one or more failed.
"""

from __future__ import annotations

import importlib
import os
import re
import tempfile

_FAILS: list[str] = []
_PASSES = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global _PASSES
    if ok:
        _PASSES += 1
    else:
        _FAILS.append(f"{name}{' — ' + detail if detail else ''}")


def _check_deployments() -> None:
    """Offline checks for the multi-deployment config layer (isolated temp HOME)."""
    import shutil

    from cisco_ise_mcp import config

    tmp = tempfile.mkdtemp(prefix="ise-mcp-validate-")
    prev_home = os.environ.get("CISCO_ISE_MCP_HOME")
    prev_pw = os.environ.pop("CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD", None)
    os.environ["CISCO_ISE_MCP_HOME"] = tmp
    _orig_keyring_get = config._keyring_get
    config._keyring_get = lambda slug, key: None  # hermetic: never touch the real OS keyring
    try:
        check("deploy: empty registry", config.list_deployments() == [])
        check("ensure_registry: creates blank file",
              config.ensure_registry().is_file() and config.list_deployments() == [])

        config.add_deployment(name="RADIUS Only", host="10.1.1.1", ers_username="ers-admin",
                              dataconnect_cert_path="/tmp/r.pem")
        config.add_deployment(name="TACACS Only", host="10.2.1.1", ers_username="ers-admin",
                              dataconnect_enabled=False)
        config.add_deployment(name="VPN Only", host="10.3.1.1", ers_username="ers-admin",
                              dataconnect_cert_path="/tmp/v.pem")
        deps = config.list_deployments()
        check("deploy: count==3", len(deps) == 3, str(len(deps)))
        check("deploy: stable numbering", [d["number"] for d in deps] == [1, 2, 3])
        check("deploy: first is default", deps[0]["is_default"] and deps[0]["slug"] == "radius-only")

        check("resolve: by number", config.resolve_deployment("2") == "tacacs-only")
        check("resolve: 'Deployment N'", config.resolve_deployment("Deployment 3") == "vpn-only")
        check("resolve: by name (ci)", config.resolve_deployment("radius only") == "radius-only")
        check("resolve: by slug", config.resolve_deployment("vpn-only") == "vpn-only")
        check("resolve: default when None", config.resolve_deployment(None) == "radius-only")

        for bad, label in [("9", "out-of-range"), ("nope", "unknown-name")]:
            try:
                config.resolve_deployment(bad)
                check(f"resolve: {label} raises", False)
            except config.ConfigError:
                check(f"resolve: {label} raises", True)

        try:
            config.add_deployment(name="2", host="1.1.1.1")
            check("add: numeric name rejected", False)
        except config.ConfigError:
            check("add: numeric name rejected", True)
        try:
            config.add_deployment(name="RADIUS Only", host="1.1.1.1")
            check("add: duplicate rejected", False)
        except config.ConfigError:
            check("add: duplicate rejected", True)
        try:
            config.add_deployment(name="", host="")
            check("add: aggregates missing fields", False)
        except config.ConfigError as exc:
            msg = str(exc)
            check("add: aggregates missing fields", "name" in msg and "host" in msg)

        try:
            config.get_deployment_config("radius-only", surface="ers")
            check("config: missing ERS pw raises", False)
        except config.ConfigError as exc:
            check("config: missing ERS pw raises", "set-credential" in str(exc))

        os.environ["CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD"] = "envpw"
        cfg = config.get_deployment_config("radius-only", surface="ers")
        check("config: env secret precedence", cfg.get("ise_password") == "envpw")
        check("config: flat shape for clients",
              cfg["ise_host"] == "10.1.1.1" and "ise_ers_port" in cfg and "verify_ssl" in cfg)
        del os.environ["CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD"]

        v = config.validate_deployment("tacacs-only")
        check("validate: aggregates missing", v["dataconnect_enabled"] is False
              and "ise_password (ERS / Open API)" in v["missing_credentials"])

        # ── update: partial patch, slug stability, error checking ──
        u = config.update_deployment("tacacs-only", host="10.2.9.9", dataconnect_enabled=True,
                                     dataconnect_cert_path="/tmp/t2.pem")
        check("update: only named fields change",
              set(u["changed"]) == {"host", "dataconnect.enabled", "dataconnect.cert_path"})
        check("update: persisted",
              config.get_deployment_config("tacacs-only")["ise_host"] == "10.2.9.9")
        check("update: no-op detected",
              config.update_deployment("tacacs-only", host="10.2.9.9")["changed"] == [])
        # rename that changes the slug requires reslug; label-only rename does not
        try:
            config.update_deployment("2", name="TACACS Primary")
            check("update: rename w/o reslug blocked", False)
        except config.ReslugRequired:
            check("update: rename w/o reslug blocked", True)
        lbl = config.update_deployment("2", name="tacacs only")  # same slug -> label only
        check("update: label-only rename keeps slug",
              lbl["slug"] == "tacacs-only" and "name" in lbl["changed"])
        ren = config.update_deployment("2", name="TACACS Primary", reslug=True)
        check("update: reslug changes slug + keeps number",
              ren["slug"] == "tacacs-primary" and ren["number"] == 2
              and ren.get("previous_slug") == "tacacs-only")
        slugs_now = [d["slug"] for d in config.list_deployments()]
        check("update: reslug swaps old->new",
              "tacacs-primary" in slugs_now and "tacacs-only" not in slugs_now)
        for bad in ({"dataconnect_mode": "bogus"}, {"host": ""}, {"bogus_field": "x"}):
            try:
                config.update_deployment("tacacs-only", **bad)
                check(f"update: rejects {list(bad)[0]}", False)
            except config.ConfigError:
                check(f"update: rejects {list(bad)[0]}", True)

        config.remove_deployment("1", confirm=True)
        deps2 = config.list_deployments()
        check("remove: round-trip + renumber",
              len(deps2) == 2 and [d["number"] for d in deps2] == [1, 2])
        check("remove: default repaired", config.get_default() == deps2[0]["slug"])
        try:
            config.remove_deployment("vpn-only", confirm=False)
            check("remove: requires confirm", False)
        except config.ConfigError:
            check("remove: requires confirm", True)
    finally:
        config._keyring_get = _orig_keyring_get
        if prev_home is None:
            os.environ.pop("CISCO_ISE_MCP_HOME", None)
        else:
            os.environ["CISCO_ISE_MCP_HOME"] = prev_home
        if prev_pw is not None:
            os.environ["CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD"] = prev_pw
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    # ── 1. Imports / startup ──
    try:
        import cisco_ise_mcp.server as server
        from cisco_ise_mcp import _mcpcompat as compat
        from cisco_ise_mcp import catalog, routing
        from cisco_ise_mcp.openapi.tools import list_ers_tools
        from cisco_ise_mcp.openapi.tools_openapi import list_openapi_tools, _resolve
        from cisco_ise_mcp.monitoring.tools import list_monitoring_tools, _resolve as _mnt_resolve
        from cisco_ise_mcp.dataconnect.tools import list_dataconnect_tools
        from cisco_ise_mcp.dataconnect.client import build_query
        check("server + modules import", True)
    except Exception as exc:  # noqa: BLE001
        print(f"FATAL: import failed: {exc}")
        return 1

    tools = server.all_tools()
    names = [t.name for t in tools]
    check("no duplicate tool names", len(names) == len(set(names)),
          f"{len(names) - len(set(names))} dupes")

    ers = catalog.get_ers_resources()
    oa_index = catalog.get_openapi_index()
    mnt_index = catalog.get_monitoring_index()
    views = catalog.get_dc_views(include_internal=True)

    # ── 2/3. ERS tools resolve to catalog resources ──
    ers_generic = {
        "ise_ers_resources", "ise_ers_request", "ise_ers_list", "ise_ers_get",
        "ise_ers_get_by_name", "ise_ers_search", "ise_ers_create", "ise_ers_update",
        "ise_ers_patch", "ise_ers_delete",
    }
    for t in list_ers_tools():
        if t.name in ers_generic:
            continue
        parts = t.name.split("_", 3)
        check(f"ERS:{t.name}", len(parts) == 4 and parts[3] in ers, "no catalog resource")

    # ── 4. Open API tools resolve to a (method, path); placeholders covered ──
    for t in list_openapi_tools():
        if t.name == "ise_openapi_request":
            continue
        key = t.name[len("ise_openapi_"):]
        entry = oa_index.get(key)
        check(f"OpenAPI:{t.name} in catalog", entry is not None)
        if entry:
            placeholders = set(re.findall(r"\{(\w+)\}", entry["path"]))
            props = set(compat.tool_input_schema(t).get("properties", {}))
            check(f"OpenAPI:{t.name} params", placeholders <= props,
                  f"missing {placeholders - props}")

    # ── 5. Data Connect view tools resolve to a catalog view ──
    for t in list_dataconnect_tools():
        if t.name.startswith("ise_dc_view_"):
            key = t.name[len("ise_dc_view_"):]
            check(f"DC:{t.name}", key in views, "no catalog view")

    # ── 4b. Monitoring (MnT) tools resolve to a (method, path); placeholders covered ──
    for t in list_monitoring_tools():
        if t.name == "ise_mnt_request":
            continue
        key = t.name[len("ise_mnt_"):]
        entry = mnt_index.get(key)
        check(f"MnT:{t.name} in catalog", entry is not None)
        if entry:
            check(f"MnT:{t.name} path base", entry["path"].startswith("/admin/API/mnt/"),
                  f"got {entry['path']}")
            placeholders = set(re.findall(r"\{(\w+)\}", entry["path"]))
            props = set(compat.tool_input_schema(t).get("properties", {}))
            check(f"MnT:{t.name} params", placeholders <= props,
                  f"missing {placeholders - props}")

    # ── Deployment selector present on every non-meta tool ──
    missing_dep = [t.name for t in tools if t.name not in server._META_NAMES
                   and "deployment" not in compat.tool_input_schema(t).get("properties", {})]
    check("every non-meta tool exposes 'deployment'", not missing_dep, f"{len(missing_dep)} missing")

    # ── 6. Dispatch unit checks (no network) ──
    expect = {
        "ise_openapi_radius_policy_set_list": ("GET", "/api/v1/policy/network-access/policy-set"),
        "ise_openapi_tacacs_policy_set_list": ("GET", "/api/v1/policy/device-admin/policy-set"),
        "ise_openapi_cert_trusted_list": ("GET", "/api/v1/certs/trusted-certificate"),
        "ise_openapi_deployment_node_list": ("GET", "/api/v1/deployment/node"),
        "ise_openapi_patch_list": ("GET", "/api/v1/patch"),
    }
    for tool, (em, ep) in expect.items():
        m, p, _, _ = _resolve(tool, {})
        check(f"dispatch:{tool}", (m, p) == (em, ep), f"got {m} {p}")

    # MnT dispatch (3-tuple: method, path, params) + placeholder fill
    mnt_expect = {
        "ise_mnt_active_session_count": ({}, "GET", "/admin/API/mnt/Session/ActiveCount"),
        "ise_mnt_session_by_mac": ({"mac": "AA:BB:CC:DD:EE:FF"}, "GET",
                                   "/admin/API/mnt/Session/MACAddress/AA:BB:CC:DD:EE:FF"),
    }
    for tool, (args, em, ep) in mnt_expect.items():
        m, p, _ = _mnt_resolve(tool, args)
        check(f"dispatch:{tool}", (m, p) == (em, ep), f"got {m} {p}")

    # SQL builder: valid order + bound value + reserved-word quoting
    sql, binds = build_query("radius_authentications",
                             {"filter_column": "username", "filter_value": "a'b",
                              "order_by": "-timestamp", "days_back": 1, "limit": 5},
                             time_col="TIMESTAMP")
    check("sql: FETCH FIRST", "FETCH FIRST :maxrows ROWS ONLY" in sql)
    check("sql: order before fetch", "ORDER BY" in sql and sql.index("ORDER BY") < sql.index("FETCH FIRST"))
    check("sql: value bound (no injection)", binds.get("fval") == "a'b" and "a'b" not in sql)
    check('sql: reserved word quoted', '"TIMESTAMP"' in sql)

    # Routing sanity — precedence-aware (Open API > ERS > Data Connect > Monitor API)
    _rec = routing.recommend
    check("route: reporting→dc",
          _rec("how many failed authentications last week")["primary_surface"] == "data_connect")
    check("route: create→ers",
          _rec("create a new internal user")["primary_surface"] == "ers")
    check("route: config-state read→ers over dc",
          _rec("list network devices")["primary_surface"] == "ers")
    check("route: policy set→openapi",
          _rec("show all policy sets")["primary_surface"] == "openapi")
    _nd = _rec("list network devices")
    check("route: surface_precedence exposed",
          _nd.get("surface_precedence") == ["openapi", "ers", "data_connect", "monitoring"])
    check("route: fallback_order present + falls back to dc",
          isinstance(_nd.get("fallback_order"), list) and _nd["fallback_order"]
          and _nd["fallback_order"][-1] == "data_connect")

    # ── Multi-deployment config layer (isolated temp HOME) ──
    _check_deployments()

    # ── 7. Runtime prerequisites ──
    for mod in ("mcp", "httpx", "oracledb", "python-dotenv".replace("python-", "").replace("-", "")):
        try:
            importlib.import_module(mod if mod != "dotenv" else "dotenv")
            check(f"prereq import: {mod}", True)
        except Exception as exc:  # noqa: BLE001
            check(f"prereq import: {mod}", False, str(exc))
    # keyring is optional (only needed for OS-keyring credential storage)
    try:
        importlib.import_module("keyring")
        keyring_ok = "available"
    except Exception:  # noqa: BLE001
        keyring_ok = "NOT installed (optional — needed only for OS-keyring credentials)"
    # Oracle client: oracledb thin mode needs no Instant Client; thick mode does.
    try:
        import oracledb
        thick = False
        try:
            oracledb.init_oracle_client()
            thick = True
        except Exception:  # noqa: BLE001
            thick = False
        oracle_note = f"oracledb {oracledb.__version__} (thin mode OK{'; thick/Instant Client available' if thick else ''})"
    except Exception as exc:  # noqa: BLE001
        oracle_note = f"oracledb missing: {exc}"

    # ── Report ──
    total = _PASSES + len(_FAILS)
    print("=" * 60)
    print(f"Cisco ISE MCP — validation: {_PASSES}/{total} checks passed")
    print("-" * 60)
    print(f"tools: {len(tools)} total "
          f"(ers={sum(n.startswith('ise_ers_') for n in names)}, "
          f"openapi={sum(n.startswith('ise_openapi_') for n in names)}, "
          f"mnt={sum(n.startswith('ise_mnt_') for n in names)}, "
          f"dc={sum(n.startswith('ise_dc_') for n in names)}, "
          f"meta={sum(n in server._META_NAMES for n in names)})")
    print(f"keyring: {keyring_ok}")
    print(f"oracle:  {oracle_note}")
    print(f"catalog: {catalog.get_meta().get('counts')} (ISE {catalog.get_meta().get('ise_version')})")
    if _FAILS:
        print("-" * 60)
        print(f"FAILURES ({len(_FAILS)}):")
        for f in _FAILS:
            print(f"  ✗ {f}")
        print("=" * 60)
        return 1
    print("All checks passed.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
