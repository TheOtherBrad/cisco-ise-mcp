"""Security and token-optimization regression tests (v1.1.0 and later)."""

import asyncio

import pytest


def _call(name, args):
    from cisco_ise_mcp import server
    return asyncio.run(server.call_tool(name, args)).data


# ── strict boolean interpretation of confirm/reslug/probe ──

@pytest.mark.parametrize("value", ["false", "False", "0", "", "no", "off", 0, 1, 1.5, [], {}, "maybe"])
def test_c1_flag_falsy_values(value):
    from cisco_ise_mcp import server
    assert server._flag(value) is False


@pytest.mark.parametrize("value", [True, "true", "TRUE", " yes ", "1", "on"])
def test_c1_flag_truthy_values(value):
    from cisco_ise_mcp import server
    assert server._flag(value) is True


def test_c1_flag_default_only_when_omitted():
    from cisco_ise_mcp import server
    assert server._flag(None, default=True) is True
    assert server._flag(None) is False
    assert server._flag("false", default=True) is False


@pytest.mark.parametrize("confirm", ["false", "0", "", "no"])
def test_c1_string_false_does_not_authorize_destructive(cfg, monkeypatch, confirm):
    # With schema validation on, a string confirm is refused up front; with
    # the validation kill-switch off, the strict _flag() gate still refuses.
    monkeypatch.setenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", "1")
    args = {"resource": "endpoint", "id": "1", "confirm": confirm}
    assert _call("ise_ers_delete", args)["error"] == "invalid_arguments"
    monkeypatch.setenv("CISCO_ISE_MCP_VALIDATE_ARGS", "0")
    assert _call("ise_ers_delete", args)["error"] == "confirmation_required"


def test_c1_string_false_does_not_remove_deployment(cfg):
    cfg.add_deployment(name="Lab One", host="10.0.0.1", ers_username="u")
    out = _call("ise_remove_deployment", {"deployment": "lab-one", "confirm": "false"})
    assert "lab-one" in cfg.load_registry()["deployments"], out


# ── destructive classifier hardening + blocklist first ──

@pytest.mark.parametrize("name,args", [
    ("ise_mnt_coa_reauth", {}),
    ("ise_mnt_coa_disconnect", {}),
    ("ise_mnt_request", {"method": "GET", "path": "/admin/API/mnt/CoA/Disconnect/n/aa/0"}),
    ("ise_mnt_request", {"method": "GET", "path": "admin/API/mnt/CoA/Reauth/n/aa/0"}),
    ("ise_mnt_request", {"method": "GET", "path": "/admin/API/mnt/%43oA/Reauth/n/aa/0"}),
    ("ise_mnt_request", {"method": "POST", "path": "/admin/API/mnt/Session/Delete/MACAddress/aa"}),
    ("ise_openapi_request", {"method": "POST", "path": "/api/v1/backup-restore/config/restore"}),
    ("ise_openapi_request", {"method": "POST", "path": "/api/v1/patch/install"}),
    ("ise_openapi_request", {"method": "POST", "path": "api/v1/hotpatch/rollback"}),
    ("ise_openapi_request", {"method": "PUT", "path": "/api/v1/certs/system-certificate/import"}),
    ("ise_openapi_request", {"method": "POST", "path": "/api/v1/certs/trusted-certificate/import"}),
    ("ise_openapi_request", {"method": "DELETE", "path": "/api/v1/anything"}),
    ("ise_openapi_patch_install", {}),
    ("ise_openapi_hotpatch_install", {}),
    ("ise_openapi_cert_system_import", {}),
    ("ise_openapi_cert_trusted_import", {}),
])
def test_c2_high_impact_calls_are_destructive(name, args):
    from cisco_ise_mcp import server
    assert server._is_destructive(name, args) is True
    assert server._maybe_destructive(name) is True


@pytest.mark.parametrize("name,args", [
    ("ise_mnt_request", {"method": "GET", "path": "/admin/API/mnt/Session/ActiveCount"}),
    ("ise_mnt_session_by_mac", {"mac": "aa"}),
    ("ise_openapi_request", {"method": "GET", "path": "/api/v1/patch/install"}),
    ("ise_openapi_request", {"method": "GET", "path": "/api/v1/backup-restore/config/last-backup-status"}),
    ("ise_openapi_request", {"method": "POST", "path": "/api/v1/policy/network-access/policy-set"}),
    ("ise_openapi_backup_create", {}),
    ("ise_openapi_cert_system_export", {}),
])
def test_c2_safe_calls_not_destructive(name, args):
    from cisco_ise_mcp import server
    assert server._is_destructive(name, args) is False


def test_c2_coa_is_audited_as_mutating():
    from cisco_ise_mcp import server
    assert server._is_mutating("ise_mnt_coa_reauth", {}) is True
    assert server._is_mutating(
        "ise_mnt_request", {"method": "GET", "path": "/admin/API/mnt/CoA/Reauth/a/b/c"}) is True
    assert server._is_mutating("ise_mnt_active_session_count", {}) is False


def test_c2_coa_reauth_gated(cfg, monkeypatch):
    monkeypatch.delenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", raising=False)
    out = _call("ise_mnt_coa_reauth", {"node": "n", "mac": "aa", "type": "0", "confirm": True})
    assert out["error"] == "read_only_mode"


def test_c2_blocklist_applies_to_read_tools(cfg, monkeypatch):
    monkeypatch.setenv("CISCO_ISE_MCP_BLOCKED_TOOLS", "ise_dc_query, ise_capabilities")
    assert _call("ise_capabilities", {})["error"] == "disabled_by_policy"
    assert _call("ise_dc_query", {"sql": "SELECT 1 FROM DUAL"})["error"] == "disabled_by_policy"
    # Unblocked tools still work.
    assert _call("ise_route", {"query": "x"})["primary_surface"] == "unknown"


def test_c2_blocked_mutation_is_audited(cfg, tmp_path, monkeypatch):
    import json
    from pathlib import Path
    monkeypatch.setenv("CISCO_ISE_MCP_BLOCKED_TOOLS", "ise_ers_create")
    out = _call("ise_ers_create", {"resource": "endpoint", "data": {}})
    assert out["error"] == "disabled_by_policy"
    from conftest import read_audit
    lines = read_audit(tmp_path)
    assert lines[-1]["status"] == "denied" and lines[-1]["tool"] == "ise_ers_create"


# ── ise_dc_query SQL guard hardening ──

def _guard(sql):
    from cisco_ise_mcp import catalog
    from cisco_ise_mcp.dataconnect.client import validate_raw_select
    from cisco_ise_mcp.limits import resolve_policy
    views = catalog.get_dc_views(include_internal=True)
    return validate_raw_select(
        sql, {v["view"].upper() for v in views.values()},
        fact_views=catalog.get_fact_view_names(),
        view_time_cols={v["view"].upper(): v.get("time_col") for v in views.values()},
        policy=resolve_policy("dataconnect", "t", None))


_TB = "\"TIMESTAMP\" >= SYSTIMESTAMP - NUMTODSINTERVAL(7,'DAY')"


@pytest.mark.parametrize("sql", [
    # Previously-accepted bypasses (re-verified 2026-11-06)
    "SELECT * FROM NETWORK_DEVICES n, ALL_USERS u WHERE n.name = u.username",
    "SELECT * FROM network_devices,all_users WHERE 1=1",
    "SELECT * FROM network_devices n , sys.dba_users d WHERE n.name = d.username",
    "SELECT UTL_INADDR.GET_HOST_ADDRESS('x') FROM DUAL",
    "SELECT utl_http.request('http://evil') FROM dual",
    "SELECT DBMS_LOB.SUBSTR(x,1,1) FROM network_devices",
    "SELECT HTTPURITYPE('http://evil').getclob() FROM dual",
    "SELECT XMLTYPE('<a/>') FROM dual",
    "SELECT * FROM network_devices@remote",
    "SELECT * FROM network_devices @ remote",
    "SELECT * FROM sys.network_devices",
    "SELECT * FROM \"SYS\".\"NETWORK_DEVICES\"",
    "SELECT * FROM sys . network_devices",
    "SELECT * FROM network_devices FOR UPDATE",
    "SELECT * FROM network_devices FOR  UPDATE NOWAIT",
    "SELECT * FROM network_devices n JOIN sys.users u ON n.name = u.name",
    "SELECT * FROM network_devices WHERE name IN (SELECT username FROM all_users)",
    "SELECT * FROM (SELECT * FROM all_users)",
    "SELECT otherschema.fn(1) FROM dual",
    # Fake time predicate via a string literal
    "SELECT * FROM radius_authentications WHERE 'TIMESTAMP >' = 'TIMESTAMP >'",
    # Literal tricks
    "SELECT q'[x]' FROM dual",
    "SELECT 'unterminated FROM dual",
])
def test_c3_rejected(sql):
    with pytest.raises(ValueError):
        _guard(sql)


@pytest.mark.parametrize("sql", [
    "SELECT 1 AS OK FROM DUAL",
    "SELECT * FROM network_devices",
    "SELECT name, ip_mask FROM network_devices nd WHERE nd.name LIKE 'SW%'",
    f"SELECT username, COUNT(*) FROM radius_authentications WHERE {_TB} GROUP BY username FETCH FIRST 50 ROWS ONLY",
    f"SELECT ra.username, nd.name FROM radius_authentications ra JOIN network_devices nd ON nd.ip_mask = ra.nas_ip_address WHERE ra.{_TB}",
    f"SELECT ra.username FROM radius_authentications ra, network_devices nd WHERE nd.ip_mask = ra.nas_ip_address AND ra.{_TB}",
    f"WITH recent AS (SELECT * FROM radius_authentications WHERE {_TB}) SELECT username, COUNT(*) FROM recent GROUP BY username",
    f"SELECT EXTRACT(HOUR FROM \"TIMESTAMP\") h, COUNT(*) FROM radius_authentications WHERE {_TB} GROUP BY EXTRACT(HOUR FROM \"TIMESTAMP\")",
    f"SELECT TRIM(BOTH ' ' FROM username) FROM radius_authentications WHERE {_TB}",
    "SELECT * FROM network_devices WHERE name = 'it''s from @ sys.x( FOR UPDATE'",
    "SELECT * FROM (SELECT name FROM network_devices) t WHERE t.name IS NOT NULL",
    "SELECT * FROM network_devices ORDER BY name FETCH FIRST 10 ROWS ONLY;",
    "SELECT TO_CHAR(SYSDATE,'YYYY') y, NVL(name,'x') FROM network_devices",
])
def test_c3_accepted(sql):
    out = _guard(sql)
    assert out.upper().startswith(("SELECT", "WITH"))


def test_c3_union_behaviour_unchanged():
    """Pre-existing heuristic: a UNION of two views is counted as a comma join and
    refused. Behaviour intentionally unchanged."""
    from cisco_ise_mcp.dataconnect.client import RawQueryRejected
    with pytest.raises(RawQueryRejected):
        _guard("SELECT name FROM network_devices UNION SELECT name FROM security_groups")


def test_c3_tool_example_is_accepted():
    """The example shipped in ise_dc_query's own schema must pass the guard."""
    from cisco_ise_mcp.dataconnect.tools import list_dataconnect_tools
    from cisco_ise_mcp import _mcpcompat as compat
    tool = next(t for t in list_dataconnect_tools() if t.name == "ise_dc_query")
    example = compat.tool_input_schema(tool)["properties"]["sql"]["description"]
    _guard(example.split("e.g. ", 1)[1])


# ── MnT path-param encoding + strict passthrough paths ──

@pytest.mark.parametrize("prefix,surface,path", [
    ("ers/", "ERS", "ers/config/%2e%2e/admin"),
    ("ers/", "ERS", "ers/config/endpoint%2Fx"),
    ("ers/", "ERS", "ers/config/endpoint%252e%252e"),
    ("ers/", "ERS", "ers\\config\\endpoint"),
    ("ers/", "ERS", "ers/config/endpoint?filter=x"),
    ("ers/", "ERS", "ers/config/endpoint#x"),
    ("ers/", "ERS", "ers/config/endpoint\r\nHost: evil"),
    ("ers/", "ERS", "ers/config/../../api/v1"),
    ("ers/", "ERS", "ers/./config"),
    ("api/", "Open API", "api/v1/%2E%2E/%2E%2E/admin"),
    ("admin/API/mnt/", "MnT", "admin/API/mnt/Session/%2e%2e/%2e%2e/x"),
    ("admin/API/mnt/", "MnT", "api/v1/node"),
])
def test_c4_passthrough_path_rejected(prefix, surface, path):
    from cisco_ise_mcp.url_safety import check_passthrough_path
    with pytest.raises(ValueError):
        check_passthrough_path(path, prefix, surface)


@pytest.mark.parametrize("prefix,path,expected", [
    ("ers/", "/ers/config/endpoint/abc-123/deregister", "ers/config/endpoint/abc-123/deregister"),
    ("api/", "/api/v1/certs/system-certificate/ise-1.lab.local", "api/v1/certs/system-certificate/ise-1.lab.local"),
    ("admin/API/mnt/", "/admin/API/mnt/Session/MACAddress/AA:BB:CC:DD:EE:FF",
     "admin/API/mnt/Session/MACAddress/AA:BB:CC:DD:EE:FF"),
    ("api/", "api/v1/endpoint/name%20with%20space", "api/v1/endpoint/name%20with%20space"),
])
def test_c4_passthrough_path_allowed(prefix, path, expected):
    from cisco_ise_mcp.url_safety import check_passthrough_path
    assert check_passthrough_path(path, prefix, "x") == expected


def _capture_mnt(monkeypatch, name, args):
    """Run an MnT tool against a mock transport; return the requested URL."""
    import httpx
    from cisco_ise_mcp.monitoring import tools as mt, client as mc
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, text="<ok/>", headers={"Content-Type": "application/xml"})

    orig = httpx.AsyncClient.__init__

    def init(self, *a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        orig(self, *a, **kw)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", init)
    client = mc.ISEMonitoringClient(host="ise.lab", username="u", password="p", verify_ssl=False)

    async def go():
        try:
            return await mt._dispatch(client, name, args)
        finally:
            await client.close()
    asyncio.run(go())
    return seen.get("url")


def test_c4_mnt_params_encoded(monkeypatch):
    url = _capture_mnt(monkeypatch, "ise_mnt_session_by_username", {"username": "bob?x=1/../../y#z"})
    assert url == "https://ise.lab/admin/API/mnt/Session/UserName/bob%3Fx%3D1%2F..%2F..%2Fy%23z"


def test_c4_mnt_mac_unchanged(monkeypatch):
    url = _capture_mnt(monkeypatch, "ise_mnt_session_by_mac", {"mac": "AA:BB:CC:DD:EE:FF"})
    assert url == "https://ise.lab/admin/API/mnt/Session/MACAddress/AA:BB:CC:DD:EE:FF"


def test_c4_mnt_passthrough_rejects_encoded(monkeypatch):
    with pytest.raises(ValueError):
        _capture_mnt(monkeypatch, "ise_mnt_request",
                     {"method": "GET", "path": "/admin/API/mnt/Session/%2e%2e/x"})


def test_c4_mnt_passthrough_allows_plain(monkeypatch):
    url = _capture_mnt(monkeypatch, "ise_mnt_request",
                       {"method": "GET", "path": "/admin/API/mnt/Session/ActiveCount"})
    assert url.endswith("/admin/API/mnt/Session/ActiveCount")


# ── argument validation against inputSchema ──

@pytest.mark.parametrize("name,args,where", [
    ("ise_dc_query", {}, "(arguments)"),                                   # missing required
    ("ise_dc_query", {"sql": 123}, "sql"),                                 # wrong type
    ("ise_dc_view", {"view": "not_a_view"}, "view"),                       # enum
    ("ise_ers_list", {"resource": "endpoint", "page": "1"}, "page"),        # string for integer
    ("ise_ers_request", {"method": "TRACE", "path": "ers/config"}, "method"),
    ("ise_dc_view", {"view": "network_devices", "filter_op": "DROP"}, "filter_op"),
    ("ise_remove_deployment", {"deployment": "x", "confirm": "yes"}, "confirm"),
])
def test_c5_invalid_arguments_refused(cfg, name, args, where):
    out = _call(name, args)
    assert out["error"] == "invalid_arguments"
    assert any(d.startswith(where) for d in out["details"]), out


def test_c5_values_not_echoed(cfg):
    out = _call("ise_dc_query", {"sql": ["SECRET-VALUE"]})
    assert "SECRET-VALUE" not in str(out)


def test_c5_integer_deployment_selector_accepted(cfg):
    cfg.add_deployment(name="Lab One", host="10.0.0.1", ers_username="u")
    out = _call("ise_test_deployment", {"deployment": 1, "probe": False})
    assert out.get("error") != "invalid_arguments"
    assert out.get("slug") == "lab-one", out


def test_c5_valid_calls_pass(cfg):
    assert "routing_rule" in _call("ise_capabilities", {})
    assert _call("ise_route", {"query": "list network devices"})["primary_surface"] == "ers"
    assert isinstance(_call("ise_dc_list_views", {}), list)


def test_c5_kill_switch(cfg, monkeypatch):
    monkeypatch.setenv("CISCO_ISE_MCP_VALIDATE_ARGS", "0")
    out = _call("ise_dc_view", {"view": "not_a_view"})
    assert out.get("error") != "invalid_arguments"


def test_c5_every_schema_is_valid_draft_2020_12():
    from jsonschema import Draft202012Validator
    from cisco_ise_mcp import server, _mcpcompat as compat
    for t in server.all_tools():
        Draft202012Validator.check_schema(compat.tool_input_schema(t))


# ── isError on refusals and errors ──

def _res(name, args):
    from cisco_ise_mcp import server
    return asyncio.run(server.call_tool(name, args))


@pytest.mark.parametrize("name,args,env", [
    ("ise_dc_query", {}, {}),                                                   # invalid args
    ("ise_ers_delete", {"resource": "endpoint", "id": "1", "confirm": True}, {}),  # gate refusal
    ("ise_capabilities", {}, {"CISCO_ISE_MCP_BLOCKED_TOOLS": "ise_capabilities"}),  # blocklist
    ("ise_not_a_tool", {}, {}),                                                 # unknown tool
    ("ise_ers_list", {"resource": "endpoint"}, {}),                             # exception: no deployment
])
def test_c6_failures_flagged(cfg, monkeypatch, name, args, env):
    monkeypatch.delenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    r = _res(name, args)
    assert r.is_error is True and "error" in r.data


def test_c6_limit_exceeded_flagged(cfg, monkeypatch):
    from cisco_ise_mcp import server
    from cisco_ise_mcp.limits import LimitExceeded

    async def boom(name, arguments):
        raise LimitExceeded({"error": "rate_limited", "surface": "ers"})
    monkeypatch.setattr(server, "handle_ers_tool", boom)
    r = _res("ise_ers_list", {"resource": "endpoint"})
    assert r.is_error is True and r.data["error"] == "rate_limited"


@pytest.mark.parametrize("name,args", [
    ("ise_capabilities", {}), ("ise_route", {"query": "x"}), ("ise_list_deployments", {}),
    ("ise_dc_list_views", {}), ("ise_dc_describe", {"view": "network_devices"}),
])
def test_c6_success_not_flagged(cfg, name, args):
    assert _res(name, args).is_error is False


def test_c6_sdk_native_shape():
    from cisco_ise_mcp import _mcpcompat as compat
    ok = compat.to_call_result(compat.text_result({"a": 1}))
    err = compat.to_call_result(compat.error_result({"error": "x"}))
    if compat.MCP_MAJOR >= 2:
        assert ok.is_error in (None, False)
        assert err.is_error is True and err.structured_content is None
    else:
        assert isinstance(ok, list)                      # unchanged v1 success shape
        assert err.isError is True and err.content[0].text
    dumped = err.model_dump(by_alias=True, exclude_none=True)
    assert dumped["isError"] is True


# ── tool annotations ──

def _ann(tool):
    return tool.annotations.model_dump(by_alias=True, exclude_none=True)


def test_c7_every_tool_annotated_consistently():
    from cisco_ise_mcp import server
    for t in server.all_tools():
        a = _ann(t)
        assert "readOnlyHint" in a, t.name
        if server._maybe_destructive(t.name):
            assert a["readOnlyHint"] is False and a["destructiveHint"] is True, t.name
            assert t.description.startswith("[DESTRUCTIVE]")
        if a["readOnlyHint"]:
            assert "destructiveHint" not in a, t.name
            assert "confirm" not in server.compat.tool_input_schema(t)["properties"], t.name


@pytest.mark.parametrize("name,read_only,destructive,idempotent", [
    ("ise_capabilities", True, None, None),
    ("ise_dc_query", True, None, None),
    ("ise_dc_view_radius_authentications", True, None, None),
    ("ise_ers_list", True, None, None),
    ("ise_ers_get_endpoint", True, None, None),
    ("ise_openapi_backup_last_status", True, None, None),
    ("ise_mnt_active_session_count", True, None, None),
    ("ise_ers_create", False, False, False),
    ("ise_ers_update", False, False, True),
    ("ise_ers_delete", False, True, True),
    ("ise_openapi_patch_install", False, True, False),
    ("ise_mnt_coa_reauth", False, True, False),
    ("ise_openapi_request", False, True, False),
    ("ise_add_deployment", False, False, False),
    ("ise_remove_deployment", False, True, False),
])
def test_c7_specific_annotations(name, read_only, destructive, idempotent):
    from cisco_ise_mcp import server
    t = {x.name: x for x in server.all_tools()}[name]
    a = _ann(t)
    assert a["readOnlyHint"] is read_only
    assert a.get("destructiveHint") is destructive
    assert a.get("idempotentHint") is idempotent
    assert a["openWorldHint"] is False


def test_c7_catalog_diff_is_open_world():
    from cisco_ise_mcp import server
    t = {x.name: x for x in server.all_tools()}["ise_catalog_diff"]
    assert _ann(t)["openWorldHint"] is True


# ── TLS — SSLContext, TLS 1.2 floor, trust_env=False ──

def _make_ca_and_leaf(tmp_path, san="ise.lab.local"):
    """Generate a throwaway CA + server cert/key (PEM files) for local handshakes."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test ISE Root")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(1)
          .not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                       content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(2)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_pem = tmp_path / "ca.pem"
    ca_pem.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    chain = tmp_path / "leaf.pem"
    chain.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    keyf = tmp_path / "leaf.key"
    keyf.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return ca_pem, chain, keyf


def _handshake(client_ctx, server_ctx, server_hostname):
    """In-memory TLS handshake; returns None on success or the SSLError."""
    import ssl
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    cli = client_ctx.wrap_bio(c_in, c_out, server_hostname=server_hostname)
    srv = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(20):
        done = 0
        for side, out, peer_in in ((cli, c_out, s_in), (srv, s_out, c_in)):
            try:
                side.do_handshake()
                done += 1
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as exc:
                return exc
            data = out.read()
            if data:
                peer_in.write(data)
        if done == 2:
            return None
    return RuntimeError("handshake did not complete")


def _server_ctx(chain, keyf, max_version=None):
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(chain, keyf)
    if max_version:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # deliberately weak server
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            ctx.maximum_version = max_version
    return ctx


def test_c8_admin_tls_verify_returns_hardened_context(tmp_path):
    import ssl
    from cisco_ise_mcp.config import admin_tls_verify
    ca, _, _ = _make_ca_and_leaf(tmp_path)
    assert admin_tls_verify(False, str(ca)) is False
    for ctx in (admin_tls_verify(True, ""), admin_tls_verify(True, str(ca))):
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
        assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_c8_private_ca_handshake_and_hostname_binding(tmp_path):
    from cisco_ise_mcp.config import admin_tls_verify
    ca, chain, keyf = _make_ca_and_leaf(tmp_path, san="ise.lab.local")
    assert _handshake(admin_tls_verify(True, str(ca)), _server_ctx(chain, keyf), "ise.lab.local") is None
    # Same trusted CA, wrong name -> refused (hostname checking still on).
    assert _handshake(admin_tls_verify(True, str(ca)), _server_ctx(chain, keyf), "evil.example") is not None
    # certifi roots alone do not trust the private CA.
    assert _handshake(admin_tls_verify(True, ""), _server_ctx(chain, keyf), "ise.lab.local") is not None


def test_c8_tls11_server_refused(tmp_path):
    import ssl
    from cisco_ise_mcp.config import admin_tls_verify
    ca, chain, keyf = _make_ca_and_leaf(tmp_path)
    try:
        srv = _server_ctx(chain, keyf, max_version=ssl.TLSVersion.TLSv1_1)
    except (ValueError, ssl.SSLError):
        pytest.skip("local OpenSSL cannot offer TLS 1.1")
    assert _handshake(admin_tls_verify(True, str(ca)), srv, "ise.lab.local") is not None


def test_c8_bad_ca_paths_still_fail_fast(tmp_path):
    from cisco_ise_mcp.config import ConfigError, admin_tls_verify
    with pytest.raises(ConfigError):
        admin_tls_verify(True, str(tmp_path / "missing.pem"))
    junk = tmp_path / "junk.pem"
    junk.write_text("not a cert")
    with pytest.raises(ConfigError):
        admin_tls_verify(True, str(junk))


def test_c8_no_deprecation_warning_and_trust_env_off(tmp_path):
    import warnings
    from cisco_ise_mcp.openapi.client import ISEErSClient
    from cisco_ise_mcp.openapi.tools_openapi import ISEOpenAPIClient
    from cisco_ise_mcp.monitoring.client import ISEMonitoringClient
    ca, _, _ = _make_ca_and_leaf(tmp_path)

    async def build():
        ers = ISEErSClient(host="h", username="u", password="p", ca_cert_path=str(ca))
        clients = [await ers._get_client(),
                   ISEOpenAPIClient(host="h", username="u", password="p", ca_cert_path=str(ca))._client,
                   ISEMonitoringClient(host="h", username="u", password="p", ca_cert_path=str(ca))._client]
        out = [c.trust_env for c in clients]
        for c in clients:
            await c.aclose()
        return out

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert asyncio.run(build()) == [False, False, False]


def test_c8_dataconnect_tls_floor(tmp_path):
    import ssl
    from cisco_ise_mcp.dataconnect.client import ISEDataConnectClient
    ca, _, _ = _make_ca_and_leaf(tmp_path)
    pinned = ISEDataConnectClient(host="h", cert_path=str(ca), verify_ssl=True)._thin_ssl_context()
    os_trust = ISEDataConnectClient(host="h", os_trust=True, verify_ssl=True)._thin_ssl_context()
    for ctx in (pinned, os_trust):
        assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


# ── refresh never executes a script from the current directory ──

def test_c9_refresh_ignores_planted_cwd_script(tmp_path, monkeypatch):
    from pathlib import Path
    from cisco_ise_mcp import cli
    planted = tmp_path / "scripts" / "refresh_catalog.py"
    planted.parent.mkdir()
    planted.write_text("raise SystemExit('planted script executed')\n")
    monkeypatch.chdir(tmp_path)
    found = cli._find_refresh_script()
    repo_script = Path(cli.__file__).resolve().parents[2] / "scripts" / "refresh_catalog.py"
    assert found == repo_script and found != planted.resolve()


# ── shorter repeated schema text — required guidance must survive ──

def _tool(name):
    from cisco_ise_mcp import server
    return {t.name: t for t in server.all_tools()}[name]


def _props(name):
    from cisco_ise_mcp import _mcpcompat as compat
    return compat.tool_input_schema(_tool(name))["properties"]


def test_c11_deployment_prop_still_explains_selector():
    d = _props("ise_ers_list")["deployment"]["description"].lower()
    for fact in ("name", "slug", "number", "omit", "default"):
        assert fact in d, fact


def test_c11_confirm_prop_keeps_operator_gate():
    d = _props("ise_ers_delete")["confirm"]["description"]
    assert "true" in d and "CISCO_ISE_MCP_ALLOW_DESTRUCTIVE" in d


def test_c11_dc_filter_props_keep_limits():
    p = _props("ise_dc_view")
    days = p["days_back"]["description"]
    assert "7" in days and "90" in days
    assert "10000" in p["limit"]["description"]
    assert p["filter_op"]["enum"] == ["EQ", "NEQ", "CONTAINS", "LIKE", "GT", "LT", "GTE", "LTE"]


def test_c11_add_deployment_keeps_guided_flow_and_security_notes():
    t = _tool("ise_add_deployment")
    d = t.description
    for fact in ("password", "Data Connect", "dataconnect_host", "dataconnect_cert_path",
                 "dataconnect_os_trust", "monitoring_enabled", "MnT Admin"):
        assert fact in d, fact
    p = _props("ise_add_deployment")
    assert "self-signed" in p["verify_ssl"]["description"].lower()
    assert "certifi" in p["ca_cert_path"]["description"]
    assert "CISCO_ISE_MCP_DC_MAX_CONCURRENT" in p["dc_max_concurrent"]["description"]


def test_c11_update_deployment_keeps_reslug_and_password_rules():
    d = _tool("ise_update_deployment").description
    for fact in ("reslug", "password", "set-credential"):
        assert fact.lower() in d.lower(), fact
    assert "''" in _props("ise_update_deployment")["ca_cert_path"]["description"]


# ── trim ERS hypermedia (link / paging objects) ──

_ERS_LIST = {"SearchResult": {
    "total": 2,
    "previousPage": {"rel": "previous", "href": "https://ise/ers/config/endpoint?page=1", "type": "application/json"},
    "nextPage": {"rel": "next", "href": "https://ise/ers/config/endpoint?page=3", "type": "application/json"},
    "resources": [
        {"id": "id1", "name": "n1", "description": "d1",
         "link": {"rel": "self", "href": "https://ise/ers/config/endpoint/id1", "type": "application/json"}},
        {"id": "id2", "name": "n2", "description": "",
         "link": {"rel": "self", "href": "https://ise/ers/config/endpoint/id2", "type": "application/json"}},
    ]}}
_ERS_GET = {"ERSEndPoint": {"id": "id1", "name": "n1", "mac": "AA:BB:CC:DD:EE:FF",
                            "customAttributes": {"customAttributes": {"link": "user-data"}},
                            "link": {"rel": "self", "href": "https://ise/ers/config/endpoint/id1",
                                     "type": "application/json"}}}


def _ers_call(monkeypatch, payload, fn):
    import httpx
    from cisco_ise_mcp.openapi.client import ISEErSClient

    def handler(request):
        return httpx.Response(200, json=payload)
    orig = httpx.AsyncClient.__init__

    def init(self, *a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        orig(self, *a, **kw)
    monkeypatch.setattr(httpx.AsyncClient, "__init__", init)
    c = ISEErSClient(host="ise", username="u", password="p", verify_ssl=False)

    async def go():
        try:
            return await fn(c)
        finally:
            await c.close()
    return asyncio.run(go())


def test_c12_list_trimmed(monkeypatch):
    monkeypatch.delenv("CISCO_ISE_MCP_RAW_ERS", raising=False)
    out = _ers_call(monkeypatch, _ERS_LIST, lambda c: c.ers_get("endpoint", page=2, size=2))
    sr = out["SearchResult"]
    assert sr["total"] == 2 and sr["has_next"] is True and sr["has_previous"] is True
    assert "nextPage" not in sr and "previousPage" not in sr
    assert sr["resources"] == [{"id": "id1", "name": "n1", "description": "d1"},
                               {"id": "id2", "name": "n2", "description": ""}]


def test_c12_single_object_trimmed_but_user_data_kept(monkeypatch):
    out = _ers_call(monkeypatch, _ERS_GET, lambda c: c.ers_get("endpoint", resource_id="id1"))
    ep = out["ERSEndPoint"]
    assert "link" not in ep and ep["mac"] == "AA:BB:CC:DD:EE:FF"
    # A non-hypermedia field that happens to be named 'link' is NOT removed.
    assert ep["customAttributes"]["customAttributes"]["link"] == "user-data"


def test_c12_last_page_has_next_false(monkeypatch):
    last = {"SearchResult": {"total": 1, "resources": [{"id": "x", "name": "y"}]}}
    out = _ers_call(monkeypatch, last, lambda c: c.ers_get("endpoint"))
    assert out["SearchResult"]["has_next"] is False and out["SearchResult"]["has_previous"] is False


def test_c12_passthrough_get_trimmed(monkeypatch):
    out = _ers_call(monkeypatch, _ERS_LIST, lambda c: c.request("GET", "ers/config/endpoint"))
    assert "link" not in out["SearchResult"]["resources"][0]


def test_c12_passthrough_write_untouched(monkeypatch):
    out = _ers_call(monkeypatch, _ERS_GET, lambda c: c.request("PUT", "ers/config/endpoint/id1", json={}))
    assert "link" in out["ERSEndPoint"]


def test_c12_kill_switch(monkeypatch):
    monkeypatch.setenv("CISCO_ISE_MCP_RAW_ERS", "1")
    out = _ers_call(monkeypatch, _ERS_LIST, lambda c: c.ers_get("endpoint"))
    assert out == _ERS_LIST


def test_c12_size_reduction():
    import json, copy
    from cisco_ise_mcp.openapi.client import trim_ers
    big = copy.deepcopy(_ERS_LIST)
    big["SearchResult"]["resources"] = [
        {"id": f"{i:08d}-aaaa-bbbb-cccc-ddddeeeeffff", "name": f"sw-{i}", "description": "",
         "link": {"rel": "self", "type": "application/json",
                  "href": f"https://ise.lab:443/ers/config/networkdevice/{i:08d}-aaaa-bbbb-cccc-ddddeeeeffff"}}
        for i in range(100)]
    before = len(json.dumps(big, separators=(",", ":")))
    after = len(json.dumps(trim_ers(big), separators=(",", ":")))
    assert after < before * 0.5


# ── logging goes to stderr, never stdout ──

def test_c14_logging_to_stderr_keeps_stdout_clean(tmp_path):
    """Run the real stdio server with INFO logging and force a warning: stdout
    must contain only JSON-RPC lines, and the warning must reach stderr."""
    import json, os, subprocess, sys
    env = {**os.environ, "CISCO_ISE_MCP_HOME": str(tmp_path), "CISCO_ISE_MCP_LOG_LEVEL": "INFO"}
    # A registry without a 'limits' block triggers config's one-time INFO notice.
    (tmp_path / "deployments.json").write_text(json.dumps({"version": 2, "default": "a", "deployments": {
        "a": {"name": "A", "host": "192.0.2.1", "ers_username": "u", "dataconnect": {"enabled": False}}}}))
    p = subprocess.Popen([sys.executable, "-m", "cisco_ise_mcp"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         # Reaches config.get_config (which logs the one-time INFO limits notice)
         # and then fails offline: Data Connect is disabled for this deployment.
         "params": {"name": "ise_dc_view", "arguments": {"view": "network_devices"}}},
    ]
    out, err = p.communicate("".join(json.dumps(m) + "\n" for m in msgs), timeout=30)
    lines = [l for l in out.splitlines() if l.strip()]
    assert len(lines) == 2
    for l in lines:
        assert json.loads(l)["jsonrpc"] == "2.0"
    assert "INFO cisco_ise_mcp.config" in err and "no 'limits' block" in err


def test_c14_invalid_level_falls_back(monkeypatch):
    import logging
    from cisco_ise_mcp import server
    root = logging.getLogger()
    saved = root.handlers[:], root.level
    root.handlers.clear()
    try:
        monkeypatch.setenv("CISCO_ISE_MCP_LOG_LEVEL", "NOT_A_LEVEL")
        server._configure_logging()
        assert root.level == logging.WARNING
        assert all(getattr(h, "stream", None) is not __import__("sys").stdout for h in root.handlers)
    finally:
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])


# ── parser-based SQL guard  ──

@pytest.mark.parametrize("sql", [
    # ' inside a double-quoted identifier fooled the former regex literal blanker
    """SELECT username "'" FROM all_users, (SELECT 1 "'" FROM dual) x""",
    """SELECT (SELECT 1 FROM dual) a, u.username "'" FROM all_users@remote_link u, dual "'" """,
    """SELECT 1 "'", DBMS_RANDOM.VALUE v, 2 "'" FROM dual""",
    # HIGH: allow-list gaps
    "SELECT * FROM (all_users u JOIN dual d ON 1=1)",
    "SELECT * FROM network_devices n JOIN (all_users) u ON 1=1",
    "SELECT * FROM network_devices n CROSS APPLY all_users",
    "SELECT * FROM network_devices n OUTER APPLY (SELECT * FROM all_users) u",
    "SELECT * FROM network_devices SAMPLE (10) s, all_users u WHERE s.name = u.username",
    "SELECT * FROM network_devices AS OF TIMESTAMP SYSTIMESTAMP n, all_users u WHERE n.name = u.username",
    "SELECT u.username FROM (WITH all_users AS (SELECT 1 x FROM dual) SELECT x FROM all_users) t, all_users u WHERE t.x = 1",
    "SELECT * FROM all_users WHERE EXISTS (WITH all_users AS (SELECT 1 x FROM dual) SELECT 1 FROM all_users)",
    "WITH a AS (SELECT * FROM all_users) SELECT * FROM a",
    'SELECT "MDSYS"."SDO_UTIL"."TO_WKTGEOMETRY"(NULL) FROM dual',
    'SELECT "OTHERSCHEMA"."F"(1) FROM network_devices',
    "SELECT * FROM TABLE(some_func()) t",
    "SELECT * FROM \"T\"@\"L\"",
    "SELECT nq'[x]' FROM dual",
    "SELECT * FROM network_devices; SELECT * FROM all_users",
    "SELECT sys_context('USERENV','IP_ADDRESS') FROM dual",
    "SELECT * FROM network_devices WHERE EXISTS (SELECT 1 FROM all_users)",
    "SELECT (SELECT username FROM all_users WHERE ROWNUM = 1) FROM dual",
    "SELECT * FROM network_devices UNION ALL SELECT * FROM all_users",
    "SELECT * FROM v$session",
    "SELECT * FROM ( (all_users) )",
    "SELECT * FROM JSON_TABLE('[]', '$[*]' COLUMNS (a PATH '$')) j",
])
def test_c17_review_bypasses_rejected(sql):
    with pytest.raises(ValueError):
        _guard(sql)


@pytest.mark.parametrize("sql", [
    # LOW: former false positives now accepted
    "SELECT * FROM network_devices WHERE name = 'q'",
    "SELECT nd.name FROM network_devices nd, security_groups sg WHERE nd.name(+) = sg.name",
    "WITH r (n) AS (SELECT name FROM network_devices) SELECT n FROM r",
    'SELECT "a--b" FROM network_devices',
    "SELECT name AS system_name FROM network_devices",
    """SELECT username "'" FROM network_devices""",
    "SELECT N'x' FROM dual",
    "SELECT COUNT(*) AS ordinal, name AS order_total FROM network_devices GROUP BY name",
    "SELECT * FROM network_devices CONNECT BY PRIOR name = name START WITH 1=1",
    "SELECT LISTAGG(name) WITHIN GROUP (ORDER BY name) FROM network_devices",
    "SELECT CAST(name AS VARCHAR2(10)) FROM network_devices ORDER BY 1 OFFSET 5 ROWS FETCH NEXT 5 ROWS ONLY",
])
def test_c17_former_false_positives_accepted(sql):
    _guard(sql)


def test_c17_literal_cannot_satisfy_time_predicate():
    from cisco_ise_mcp.dataconnect.client import RawQueryRejected
    with pytest.raises(RawQueryRejected):
        _guard("""SELECT * FROM radius_authentications WHERE 'x "TIMESTAMP" >' = 'y'""")


def test_c17_timing_on_large_input():
    import time
    for sql in ["SELECT " + "1+" * 3000 + "1 FROM dual",
                "SELECT * FROM network_devices WHERE name IN (" + ",".join(["'a'"] * 5000) + ")",
                "SELECT " + "(" * 200 + "1" + ")" * 200 + " FROM dual"]:
        t = time.perf_counter()
        try:
            _guard(sql)
        except (ValueError, RecursionError):
            pass
        assert time.perf_counter() - t < 2.0


# ── ';' params / '//' segments in passthroughs; MnT dot params ──

@pytest.mark.parametrize("prefix,surface,path", [
    ("admin/API/mnt/", "MnT", "/admin/API/mnt/CoA;x/Reauth/psn1/00:11:22:33:44:55/0"),
    ("api/", "Open API", "/api/v1/patch;a/install"),
    ("api/", "Open API", "/api/v1/patch//install"),
    ("ers/", "ERS", "ers/config//endpoint"),
])
def test_c18_semicolon_and_empty_segments_rejected(prefix, surface, path):
    from cisco_ise_mcp.url_safety import check_passthrough_path
    with pytest.raises(ValueError):
        check_passthrough_path(path, prefix, surface)


def test_c18_trailing_slash_still_allowed():
    from cisco_ise_mcp.url_safety import check_passthrough_path
    assert check_passthrough_path("/ers/config/endpoint/", "ers/", "ERS") == "ers/config/endpoint/"


@pytest.mark.parametrize("value", [".", "..", "", " "])
def test_c18_mnt_dot_params_rejected(monkeypatch, value):
    with pytest.raises(ValueError):
        _capture_mnt(monkeypatch, "ise_mnt_session_by_mac", {"mac": value})


def test_c18_mnt_passthrough_semicolon_refused_end_to_end(cfg, monkeypatch):
    monkeypatch.setenv("CISCO_ISE__A__ISE_PASSWORD", "x")
    cfg.add_deployment(name="A", host="192.0.2.1", ers_username="u",
                       monitoring_enabled=True, dataconnect_enabled=False)
    r = _res("ise_mnt_request", {"method": "GET",
                                 "path": "/admin/API/mnt/CoA;x/Reauth/p/00:11:22:33:44:55/0"})
    assert r.is_error and "';' are not allowed" in r.data["error"]
