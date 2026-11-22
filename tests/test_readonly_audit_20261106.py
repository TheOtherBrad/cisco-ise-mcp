"""Read-only default and daily audit logs."""

import asyncio

import pytest


def _res(name, args):
    from cisco_ise_mcp import server
    return asyncio.run(server.call_tool(name, args))


def _names(tools):
    return {t.name for t in tools}


@pytest.fixture
def ro(cfg, monkeypatch):
    monkeypatch.delenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", raising=False)
    monkeypatch.delenv("CISCO_ISE_MCP_BLOCKED_TOOLS", raising=False)
    return cfg


# ── Read-only default ──

def test_d1_default_lists_no_write_tools(ro):
    from cisco_ise_mcp import server
    vis = server.visible_tools()
    for t in vis:
        # ise_set_default_deployment only selects the default (local, non-ISE).
        if t.name != "ise_set_default_deployment":
            ann = t.annotations.model_dump(by_alias=True, exclude_none=True)
            assert ann["readOnlyHint"] is True, t.name
        assert "confirm" not in server.compat.tool_input_schema(t)["properties"], t.name
    names = _names(vis)
    for hidden in ("ise_ers_create", "ise_ers_update", "ise_ers_patch", "ise_ers_delete",
                   "ise_openapi_repo_create", "ise_openapi_backup_restore", "ise_openapi_patch_install",
                   "ise_mnt_coa_reauth", "ise_mnt_session_delete_by_id",
                   "ise_add_deployment", "ise_update_deployment", "ise_remove_deployment"):
        assert hidden not in names
    for kept in ("ise_ers_list", "ise_dc_query", "ise_openapi_backup_last_status",
                 "ise_set_default_deployment", "ise_list_deployments", "ise_test_deployment",
                 "ise_ers_request", "ise_openapi_request", "ise_mnt_request"):
        assert kept in names


@pytest.mark.parametrize("p", ["ise_ers_request", "ise_openapi_request", "ise_mnt_request"])
def test_d1_passthroughs_get_only_in_read_only(ro, p):
    from cisco_ise_mcp import server
    t = {x.name: x for x in server.visible_tools()}[p]
    assert server.compat.tool_input_schema(t)["properties"]["method"]["enum"] == ["GET"]


@pytest.mark.parametrize("name,args", [
    ("ise_ers_create", {"resource": "endpoint", "data": {}}),
    ("ise_ers_update", {"resource": "endpoint", "id": "1", "data": {}}),
    ("ise_ers_patch", {"resource": "endpoint", "id": "1", "data": {}}),
    ("ise_ers_delete", {"resource": "endpoint", "id": "1", "confirm": True}),
    ("ise_openapi_repo_create", {"data": {}}),
    ("ise_openapi_backup_create", {"data": {}}),
    ("ise_ers_request", {"method": "POST", "path": "ers/config/endpoint"}),
    ("ise_openapi_request", {"method": "PUT", "path": "/api/v1/x"}),
    ("ise_mnt_request", {"method": "GET", "path": "/admin/API/mnt/CoA/Reauth/n/aa/0"}),
    ("ise_add_deployment", {"name": "X", "host": "192.0.2.9"}),
    ("ise_update_deployment", {"deployment": "1", "host": "evil.example"}),
    ("ise_remove_deployment", {"deployment": "1", "confirm": True}),
])
def test_d1_write_calls_refused_even_if_called(ro, name, args):
    r = _res(name, args)
    assert r.is_error and r.data["error"] == "read_only_mode", r.data


def test_d1_registry_unchanged_by_refused_update(ro):
    ro.add_deployment(name="Lab", host="10.0.0.1", ers_username="u")
    _res("ise_update_deployment", {"deployment": "lab", "host": "evil.example"})
    assert ro.load_registry()["deployments"]["lab"]["host"] == "10.0.0.1"


def test_d1_reads_still_work(ro):
    assert "routing_rule" in _res("ise_capabilities", {}).data
    assert _res("ise_dc_describe", {"view": "network_devices"}).is_error is False
    r = _res("ise_ers_request", {"method": "GET", "path": "ers/config/endpoint"})
    assert r.data.get("error") != "read_only_mode"   # passes the gate (fails later: no deployment)


def test_d1_enabled_lists_everything_except_blocked(ro, monkeypatch):
    from cisco_ise_mcp import server
    monkeypatch.setenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", "1")
    monkeypatch.setenv("CISCO_ISE_MCP_BLOCKED_TOOLS", "ise_ers_delete,ise_openapi_backup_restore")
    names = _names(server.visible_tools())
    assert names == _names(server.all_tools()) - {"ise_ers_delete", "ise_openapi_backup_restore"}
    t = {x.name: x for x in server.visible_tools()}["ise_ers_request"]
    assert "POST" in server.compat.tool_input_schema(t)["properties"]["method"]["enum"]


def test_d1_enabled_destructive_still_needs_confirm(ro, monkeypatch):
    monkeypatch.setenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", "1")
    r = _res("ise_ers_delete", {"resource": "endpoint", "id": "1"})
    assert r.data["error"] == "confirmation_required"
    # A create is not destructive: passes the gates (then fails: no deployment).
    r = _res("ise_ers_create", {"resource": "endpoint", "data": {}})
    assert r.data["error"] not in ("read_only_mode", "confirmation_required", "destructive_disabled")


def test_d1_blocked_read_tool_hidden_in_read_only(ro, monkeypatch):
    from cisco_ise_mcp import server
    monkeypatch.setenv("CISCO_ISE_MCP_BLOCKED_TOOLS", "ise_dc_query")
    assert "ise_dc_query" not in _names(server.visible_tools())


def test_d1_wire_tools_list_default_vs_enabled(tmp_path):
    """Real stdio session: tools/list reflects the environment."""
    import json, os, subprocess, sys

    def listed(extra):
        env = {k: v for k, v in os.environ.items()
               if k not in ("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", "CISCO_ISE_MCP_BLOCKED_TOOLS")}
        env.update({"CISCO_ISE_MCP_HOME": str(tmp_path), **extra})
        p = subprocess.Popen([sys.executable, "-m", "cisco_ise_mcp"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env)

        def send(m):
            p.stdin.write(json.dumps(m) + "\n")
            p.stdin.flush()
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"}}})
        p.stdout.readline()
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = json.loads(p.stdout.readline())["result"]["tools"]
        p.stdin.close()
        p.wait(timeout=10)
        return {t["name"] for t in tools}

    ro_names = listed({})
    rw_names = listed({"CISCO_ISE_MCP_ALLOW_DESTRUCTIVE": "1"})
    assert "ise_ers_delete" not in ro_names and "ise_ers_delete" in rw_names
    assert len(ro_names) < len(rw_names)


# ── Daily audit logs ──

import re as _re
from datetime import date, timedelta
from pathlib import Path


def _today_log(home):
    from datetime import datetime
    return Path(home) / "logs" / f"{datetime.now().astimezone():%Y-%m-%d}.log"


def test_d2_logs_folder_daily_name_and_local_timestamp(ro, tmp_path):
    _res("ise_capabilities", {})
    log = _today_log(tmp_path)
    assert log.parent.name == "logs" and _re.fullmatch(r"\d{4}-\d{2}-\d{2}\.log", log.name)
    line = log.read_text().splitlines()[-1]
    stamp, payload = line.split(" ", 1)
    # Local ISO-8601 with milliseconds and UTC offset, e.g. 2026-11-06T14:03:22.123-06:00
    assert _re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}", stamp)
    from datetime import datetime
    assert stamp.startswith(datetime.now().astimezone().strftime("%Y-%m-%d"))
    import json
    assert json.loads(payload)["tool"] == "ise_capabilities"


def test_d2_every_call_logged_with_tool_access_status(ro, tmp_path):
    from conftest import read_audit
    _res("ise_route", {"query": "x"})                                   # read ok
    _res("ise_ers_create", {"resource": "endpoint", "data": {}})        # write denied (read-only)
    _res("ise_dc_query", {})                                            # invalid args
    entries = read_audit(tmp_path)
    by_tool = {e["tool"]: e for e in entries}
    assert by_tool["ise_route"]["access"] == "read" and by_tool["ise_route"]["status"] == "ok"
    assert by_tool["ise_ers_create"]["access"] == "write"
    assert by_tool["ise_ers_create"]["status"] == "denied"
    assert by_tool["ise_ers_create"]["error"] == "read_only_mode"
    assert by_tool["ise_dc_query"]["error"] == "invalid_arguments"
    assert all("duration_ms" in e for e in entries)


def test_d2_writes_logged_attempt_then_outcome_with_body(ro, tmp_path, monkeypatch):
    from conftest import read_audit
    monkeypatch.setenv("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", "1")
    _res("ise_ers_create", {"resource": "networkdevice",
                            "data": {"NetworkDevice": {"name": "sw1", "authenticationSettings": {
                                "radiusSharedSecret": "TopSecret1"}}}})
    _res("ise_ers_delete", {"resource": "endpoint", "id": "abc", "confirm": True})
    e = [x for x in read_audit(tmp_path) if x["tool"] in ("ise_ers_create", "ise_ers_delete")]
    assert [(x["tool"], x["status"]) for x in e] == [
        ("ise_ers_create", "attempt"), ("ise_ers_create", "error"),
        ("ise_ers_delete", "attempt"), ("ise_ers_delete", "error")]
    assert e[0]["access"] == "write" and e[2]["access"] == "destructive"
    body = e[0]["arguments"]["data"]["NetworkDevice"]
    assert body["name"] == "sw1"                                        # what was created
    assert body["authenticationSettings"]["radiusSharedSecret"] == "*****"
    assert e[2]["arguments"]["id"] == "abc"


@pytest.mark.parametrize("args", [
    {"password": "p@ss"}, {"ise_password": "x"}, {"DataConnect-Password": "x"},
    {"enablePassword": "x"}, {"api_key": "x"}, {"apiKey": "x"}, {"token": "x"},
    {"preSharedKey": "x"}, {"radiusSharedSecret": "x"}, {"privateKey": "x"},
    {"nested": [{"deep": {"secret": "x"}}]}, {"Authorization": "Basic abc"},
])
def test_d2_secret_keys_masked_with_five_asterisks(ro, tmp_path, args):
    from cisco_ise_mcp import audit
    from conftest import read_audit
    audit.record("t", args)
    text = _today_log(tmp_path).read_text()
    assert "*****" in text
    for leaked in ("p@ss", '"x"', "abc"):
        assert leaked not in text.split(" ", 1)[1]


def test_d2_inline_secrets_in_text_masked(ro, tmp_path):
    from cisco_ise_mcp import audit
    audit.record("t", {"note": "login password=Hunter2 and token: abc123, Bearer eyJhbGciOiJIUzI1NiJ9xyz"})
    text = _today_log(tmp_path).read_text()
    assert "Hunter2" not in text and "abc123" not in text and "eyJhbGci" not in text
    assert text.count("*****") == 3


def test_d2_non_secret_keys_not_masked(ro, tmp_path):
    from cisco_ise_mcp import audit
    from conftest import read_audit
    audit.record("t", {"resource": "endpoint", "keyword": "x", "monkey": "y", "description": "z"})
    a = read_audit(tmp_path)[-1]["arguments"]
    assert a == {"resource": "endpoint", "keyword": "x", "monkey": "y", "description": "z"}


def test_d2_log_injection_is_one_line(ro, tmp_path):
    from cisco_ise_mcp import audit
    audit.record("t", {"name": "x\n2099-01-01T00:00:00.000+00:00 {\"tool\":\"forged\"}"})
    lines = _today_log(tmp_path).read_text().splitlines()
    assert len(lines) == 1 and "forged" in lines[0]


def test_d2_permissions_owner_only(ro, tmp_path):
    import os, stat, sys
    if sys.platform.startswith("win"):
        pytest.skip("POSIX permissions")
    from cisco_ise_mcp import audit
    audit.record("t", {})
    log = _today_log(tmp_path)
    assert stat.S_IMODE(os.stat(log).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(log.parent).st_mode) == 0o700
    os.chmod(log, 0o644)                      # widened by someone else ...
    audit.record("t", {})
    assert stat.S_IMODE(os.stat(log).st_mode) == 0o600   # ... is re-tightened


def test_d2_symlink_log_not_followed(ro, tmp_path):
    import os, sys
    if sys.platform.startswith("win"):
        pytest.skip("POSIX symlinks")
    from cisco_ise_mcp import audit
    target = tmp_path / "victim.txt"
    target.write_text("keep")
    log = _today_log(tmp_path)
    log.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, log)
    audit.record("t", {})                     # must not write through the symlink
    assert target.read_text() == "keep"


@pytest.mark.parametrize("raw,expected", [
    (None, 365), ("90", 90), ("3650", 3650), ("30", 90), ("0", 90), ("-5", 90),
    ("99999", 3650), ("abc", 365), ("400", 400),
])
def test_d2_retention_clamped(monkeypatch, raw, expected):
    from cisco_ise_mcp import audit
    if raw is None:
        monkeypatch.delenv("CISCO_ISE_MCP_LOG_RETENTION_DAYS", raising=False)
    else:
        monkeypatch.setenv("CISCO_ISE_MCP_LOG_RETENTION_DAYS", raw)
    assert audit.retention_days() == expected


def test_d2_purge_deletes_only_old_dated_logs(ro, tmp_path, monkeypatch):
    from cisco_ise_mcp import audit
    monkeypatch.setenv("CISCO_ISE_MCP_LOG_RETENTION_DAYS", "90")
    d = tmp_path / "logs"
    d.mkdir()
    today = date(2026, 11, 6)
    keep_edge = today - timedelta(days=89)     # oldest day still retained
    drop = today - timedelta(days=90)
    for name in (f"{keep_edge:%Y-%m-%d}.log", f"{drop:%Y-%m-%d}.log", "2001-01-01.log",
                 "notes.txt", "2001-01-01.log.bak", "2001-13-45.log"):
        (d / name).write_text("x")
    deleted = audit.purge_old_logs(today)
    assert sorted(deleted) == sorted([f"{drop:%Y-%m-%d}.log", "2001-01-01.log"])
    remaining = {p.name for p in d.iterdir()}
    assert f"{keep_edge:%Y-%m-%d}.log" in remaining
    assert {"notes.txt", "2001-01-01.log.bak", "2001-13-45.log"} <= remaining


def test_d2_retention_not_settable_by_agent(ro):
    """Retention comes only from the environment, never from the registry."""
    from cisco_ise_mcp import server
    for t in server.all_tools():
        assert "retention" not in str(server.compat.tool_input_schema(t)).lower(), t.name


def test_d2_audit_failure_never_breaks_call(ro, monkeypatch):
    from cisco_ise_mcp import audit
    monkeypatch.setattr(audit, "_write_line", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    assert _res("ise_capabilities", {}).is_error is False
