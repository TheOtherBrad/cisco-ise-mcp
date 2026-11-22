"""
MCP server entry point for Cisco ISE.

Tool families (dispatched by name prefix), in surface-precedence order — use the
highest-ranked surface that can serve a request, fall back only on failure:
  - ise_openapi_*  Open API (ISE 3.1+) — system/policy/cert/backup/patch/license + state
  - ise_ers_*      ERS (External RESTful Services) — configuration CRUD & current state
  - ise_dc_*       Data Connect — read-only SQL reporting/history no higher surface exposes
  - ise_mnt_*      Monitor API (MnT) — legacy /admin/API/mnt session/CoA queries (XML)

Meta tools:
  - ise_capabilities  surfaces + routing rule + catalog version
  - ise_route         recommend a surface/tools for a natural-language request
  - ise_catalog_info  cached catalog provenance + counts
  - ise_catalog_diff  check the cache against Cisco DevNet / the ERS spec (read-only)

Deployment meta tools (manage WHICH ISE each call targets):
  - ise_list_deployments        list configured deployments (number + name)
  - ise_add_deployment          add a deployment (non-secret fields only)
  - ise_remove_deployment       remove a deployment (requires confirm)
  - ise_set_default_deployment  choose the default deployment
  - ise_test_deployment         check config/credentials (optional live probe)

Every ERS / Open API / Data Connect tool accepts an optional ``deployment``
argument (name, slug, or number). Omit it to use the only/default deployment.
"""

import asyncio
import logging
import os
import re
import time
import uuid
from typing import Optional
from urllib.parse import unquote

from mcp.types import Tool, ToolAnnotations

from cisco_ise_mcp import _mcpcompat as compat
from cisco_ise_mcp import audit, catalog, config, routing
from cisco_ise_mcp.limits import LimitExceeded
from cisco_ise_mcp.openapi import (
    list_ers_tools, handle_ers_tool,
    list_openapi_tools, handle_openapi_tool,
)
from cisco_ise_mcp.monitoring import list_monitoring_tools, handle_monitoring_tool
from cisco_ise_mcp.dataconnect.tools import list_dataconnect_tools, handle_dataconnect_tool

# Shared non-secret deployment field schema for ise_add_deployment /
# ise_update_deployment. Defined once (token cost: these two tools were the
# largest in the listing). Update omits defaults — absent fields are unchanged.
_DEPLOYMENT_FIELD_PROPS: dict = {
    "ers_username": {"type": "string", "description": "ERS/Open API admin username."},
    "ers_port": {"type": "integer", "default": 443, "description": "443 (gateway) or 9060."},
    "openapi_port": {"type": "integer", "default": 443, "description": "443 (gateway) or 9070."},
    "verify_ssl": {"type": "boolean", "default": True, "description": "Verify ISE admin TLS. false ONLY for self-signed labs (no MITM protection)."},
    "ca_cert_path": {"type": "string", "description": "PEM CA bundle for admin TLS; needed for a private ISE CA (httpx trusts only certifi, not the OS/Keychain). '' clears."},
    "monitoring_enabled": {"type": "boolean", "default": False, "description": "Enable Monitor API (ise_mnt_*); needs 'MnT Admin' group."},
    "dataconnect_enabled": {"type": "boolean", "default": True},
    "dataconnect_host": {"type": "string", "description": "MnT node IP/FQDN if not the admin host. '' clears."},
    "dataconnect_port": {"type": "integer", "default": 2484},
    "dataconnect_sid": {"type": "string", "default": "cpm10"},
    "dataconnect_user": {"type": "string", "default": "dataconnect"},
    "dataconnect_mode": {"type": "string", "enum": ["thin", "thick"], "default": "thin",
                         "description": "thin = PEM cert, no Oracle client; thick = Instant Client + wallet."},
    "dataconnect_cert_path": {"type": "string", "description": "Exported Data Connect cert / root CA (PEM). Required if self-signed. '' clears."},
    "dataconnect_wallet_path": {"type": "string", "description": "Wallet dir (thick, or thin via ewallet.pem)."},
    "dataconnect_verify_ssl": {"type": "boolean", "default": True},
    "dataconnect_os_trust": {"type": "boolean", "default": False, "description": "CA-signed cert: trust the OS/default CA store instead of a PEM."},
    "dataconnect_oracle_client_lib": {"type": "string", "description": "Instant Client dir (thick)."},
    # Limits: may only tighten the CISCO_ISE_MCP_* environment ceilings.
    "dc_max_concurrent": {"type": "integer", "description": "Default 5; only tightens CISCO_ISE_MCP_DC_MAX_CONCURRENT."},
    "dc_query_timeout_s": {"type": "integer", "description": "Default 60; cancelled on the MnT node."},
    "dc_max_per_minute": {"type": "integer", "description": "Default 30."},
    "dc_default_days_back": {"type": "integer", "description": "Default 7."},
    "dc_max_days_back": {"type": "integer", "description": "Default 90."},
    "dc_default_row_limit": {"type": "integer", "description": "Bound added to ise_dc_query; default 500 (5000 aggregates)."},
    "dc_max_fact_views": {"type": "integer", "description": "Default 3."},
    "ers_max_concurrent": {"type": "integer", "description": "Default 10 (of Cisco's 100)."},
    "openapi_max_concurrent": {"type": "integer", "description": "Default 15 (of Cisco's 150)."},
    "monitoring_max_concurrent": {"type": "integer", "description": "Default 5."},
}
_UPDATE_FIELD_PROPS: dict = {
    k: {kk: vv for kk, vv in v.items() if kk != "default"} for k, v in _DEPLOYMENT_FIELD_PROPS.items()
}

_META_TOOLS = [
    Tool(
        name="ise_capabilities",
        description=(
            "Summarize the four Cisco ISE API surfaces (Open API, ERS, Data Connect, Monitor API), "
            "their precedence order (Open API > ERS > Data Connect > Monitor API — use the highest that "
            "can serve the task, fall back to a lower one only on failure), and the cached catalog "
            "version. Call this first when unsure which tool family to use."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="ise_route",
        description=(
            "Given a natural-language request, recommend which ISE surface and concrete tools to use, "
            "honoring surface precedence (Open API > ERS > Data Connect > Monitor API). Current config "
            "& state → Open API/ERS; reporting/historical/aggregate/audit only the monitoring DB holds "
            "→ Data Connect (ise_dc_*); legacy live session/CoA lookups with no higher equivalent → "
            "Monitor API (ise_mnt_*). Returns primary_surface plus a fallback_order."
        ),
        inputSchema={"type": "object", "required": ["query"], "properties": {
            "query": {"type": "string", "description": "The user's request in natural language."}}},
    ),
    Tool(
        name="ise_catalog_info",
        description="Show cached catalog provenance: target ISE version, source URLs, generation time, and per-surface entry counts.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="ise_catalog_diff",
        description=(
            "Check the local catalog cache against the current upstream sources (re-scrape Cisco DevNet "
            "for Data Connect views; re-parse the ERS spec) and report added/removed/changed entries. "
            "Read-only — does NOT modify the cache. 'dc' requires network access to developer.cisco.com."
        ),
        inputSchema={"type": "object", "properties": {
            "only": {"type": "string", "default": "dc",
                     "description": "Comma list of catalogs to check: ers,dc,openapi (default 'dc')."}}},
    ),
    Tool(
        name="ise_list_deployments",
        description=(
            "List configured ISE deployments (number, name, slug, host, credential status). Every "
            "tool's 'deployment' argument accepts a name ('RADIUS Only'), slug ('radius-only') or "
            "number ('1' / 'Deployment 1'); omit it to use the only/default deployment."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="ise_add_deployment",
        description=(
            "Add an ISE deployment (non-secret fields only; passwords are NEVER passed here — the "
            "result gives the terminal command to set them). Required: name, host (+ ers_username "
            "for ERS/Open API). Reports every missing/invalid field at once.\n"
            "GUIDED FLOW — ask the user, don't assume: (1) Data Connect reporting needed? If not, "
            "dataconnect_enabled=false. (2) Data Connect on a separate MnT node? Set "
            "dataconnect_host. (3) Data Connect cert SELF-SIGNED: export it, set "
            "dataconnect_cert_path; CA-SIGNED: dataconnect_os_trust=true or dataconnect_cert_path "
            "to the root CA. (4) Enable Monitor API via monitoring_enabled? Needs the ERS account "
            "in ISE's 'MnT Admin' group; Data Connect is preferred for reporting."
        ),
        inputSchema={"type": "object", "required": ["name", "host"], "properties": {
            "name": {"type": "string", "description": "Descriptive label, e.g. 'RADIUS Only'."},
            "host": {"type": "string", "description": "ISE admin-node IP or FQDN."},
            **_DEPLOYMENT_FIELD_PROPS,
            "make_default": {"type": "boolean", "description": "Make this the default deployment."},
        }},
    ),
    Tool(
        name="ise_update_deployment",
        description=(
            "Change an EXISTING deployment's non-secret settings (e.g. fix the host, enable Data "
            "Connect). Only passed fields change; stored passwords are kept. A rename that changes "
            "the slug moves stored credentials and needs reslug=true. Passwords are NEVER set here "
            "(terminal: uv run cisco-ise-mcp set-credential <name>). Pass '' to clear a path/host. "
            "Field meanings: see ise_add_deployment."
        ),
        inputSchema={"type": "object", "required": ["deployment"], "properties": {
            "deployment": {"type": "string", "description": "Deployment to modify (name, slug or number)."},
            "name": {"type": "string", "description": "New label; if its slug changes also pass reslug=true."},
            "reslug": {"type": "boolean", "default": False, "description": "Allow a slug change on rename (migrates credentials)."},
            "host": {"type": "string"},
            **_UPDATE_FIELD_PROPS,
        }},
    ),
    Tool(
        name="ise_remove_deployment",
        description="Remove a deployment from the registry (and its stored credentials). Requires confirm=true.",
        inputSchema={"type": "object", "required": ["deployment", "confirm"], "properties": {
            "deployment": {"type": "string", "description": "Name, slug, or number of the deployment to remove."},
            "confirm": {"type": "boolean", "default": False, "description": "Must be true to actually remove it."}}},
    ),
    Tool(
        name="ise_set_default_deployment",
        description="Set which deployment is used when a tool call does not name one.",
        inputSchema={"type": "object", "required": ["deployment"], "properties": {
            "deployment": {"type": "string", "description": "Name, slug, or number to make the default."}}},
    ),
    Tool(
        name="ise_limits_status",
        description=(
            "Show the resource limits protecting each ISE deployment and their live usage. "
            "Reports the configured cap per surface (Data Connect / ERS / Open API / MnT), the "
            "effective value after environment ceilings are applied, which values a per-deployment "
            "override tightened, in-flight calls, and how many calls have been refused. Use this "
            "when a call is refused with 'concurrency_limited', 'rate_limited' or 'query_timeout' "
            "to see what is actually in force."
        ),
        inputSchema={"type": "object", "properties": {
            "deployment": {"type": "string", "description": (
                "Name, slug, or number. Omit to report every deployment's configured limits.")}}},
    ),
    Tool(
        name="ise_test_deployment",
        description=(
            "Check a deployment's configuration and credentials, reporting EVERY missing field/credential "
            "at once with the exact fix command. If nothing is missing and probe is true (default), also "
            "attempts a read-only live connection (ERS GET + Data Connect 'SELECT 1')."
        ),
        inputSchema={"type": "object", "properties": {
            "deployment": {"type": "string", "description": "Name, slug, or number. Omit for the only/default deployment."},
            "probe": {"type": "boolean", "default": True, "description": "Attempt a live read-only connection when config is complete."}}},
    ),
]

_META_NAMES = {t.name for t in _META_TOOLS}


_CONFIRM_PROP = {
    "type": "boolean",
    "default": False,
    "description": "Must be true. Also requires operator env CISCO_ISE_MCP_ALLOW_DESTRUCTIVE=1.",
}


def _mark_destructive(tool: Tool) -> Tool:
    """Add a required-ish ``confirm`` flag + [DESTRUCTIVE] label to destructive tools."""
    if not _maybe_destructive(tool.name):
        return tool
    schema = compat.tool_input_schema(tool)
    props = dict(schema.get("properties", {}))
    if "confirm" not in props:
        props["confirm"] = _CONFIRM_PROP
    desc = tool.description or ""
    if not desc.startswith("[DESTRUCTIVE]"):
        desc = f"[DESTRUCTIVE] {desc}"
    return Tool(name=tool.name, description=desc, inputSchema={**schema, "properties": props})


# ---------------------------------------------------------------------------
# Tool annotations — MCP behavioural hints for clients (auto-approve
# reads, prompt on destructive calls). They are HINTS only: the server-side
# gates (_destructive_gate, blocklist, validation) remain the real control.
# ---------------------------------------------------------------------------
_READ_ONLY_META = {
    "ise_capabilities", "ise_route", "ise_catalog_info", "ise_catalog_diff",
    "ise_list_deployments", "ise_limits_status", "ise_test_deployment",
}
_PASSTHROUGHS = {"ise_ers_request", "ise_openapi_request", "ise_mnt_request"}


def _tool_http_method(name: str) -> Optional[str]:
    """HTTP method of a fixed (catalog/typed) tool, or None if not fixed."""
    if name in _PASSTHROUGHS:
        return None
    if name.startswith("ise_ers_"):
        action = name[len("ise_ers_"):].split("_", 1)[0]
        return {"resources": "GET", "list": "GET", "get": "GET", "search": "GET",
                "create": "POST", "update": "PUT", "patch": "PATCH",
                "delete": "DELETE"}.get(action)
    if name.startswith("ise_openapi_"):
        entry = catalog.get_openapi_index().get(name[len("ise_openapi_"):])
        return (entry or {}).get("method", "").upper() or None
    if name.startswith("ise_mnt_"):
        entry = catalog.get_monitoring_index().get(name[len("ise_mnt_"):])
        return (entry or {}).get("method", "").upper() or None
    return None


def _annotations_for(name: str) -> dict:
    """camelCase annotation dict (accepted by ``Tool`` on mcp v1 and v2)."""
    # ise_remove_deployment is not ISE-destructive (no server gate), but it
    # deletes stored credentials locally — clients should still prompt for it.
    destructive = _maybe_destructive(name) or name == "ise_remove_deployment"
    if name.startswith("ise_dc_") or name in _READ_ONLY_META:
        read_only = True
    elif name in _PASSTHROUGHS or destructive:
        read_only = False
    else:
        read_only = _tool_http_method(name) == "GET"
    ann: dict = {"readOnlyHint": read_only,
                 # Only catalog_diff reaches beyond the configured ISE (Cisco DevNet).
                 "openWorldHint": name == "ise_catalog_diff"}
    if not read_only:
        ann["destructiveHint"] = destructive
        ann["idempotentHint"] = _tool_http_method(name) in ("PUT", "DELETE")
    return ann


def _annotate(tool: Tool) -> Tool:
    # model_copy(update=) skips validation, so build the typed model explicitly;
    # model_validate accepts the camelCase wire names on both SDK majors.
    ann = ToolAnnotations.model_validate(_annotations_for(tool.name))
    return tool.model_copy(update={"annotations": ann})


def all_tools() -> list[Tool]:
    """Every tool this server exposes — SDK-agnostic; reused by scripts/validate.py."""
    tools: list[Tool] = []
    tools.extend(_META_TOOLS)
    tools.extend(list_ers_tools())
    tools.extend(list_openapi_tools())
    tools.extend(list_monitoring_tools())
    tools.extend(list_dataconnect_tools())
    return [_annotate(_mark_destructive(t)) for t in tools]


async def _list_tools() -> list[Tool]:
    return visible_tools()


# ---------------------------------------------------------------------------
# Read-only default
#
# Unless an operator sets CISCO_ISE_MCP_ALLOW_DESTRUCTIVE=1, the server is
# READ-ONLY: no ISE create/update/delete and no registry add/update/remove.
# Write-capable tools are not advertised in tools/list (the environment is fixed
# for the process lifetime, so the list is stable) and are refused at runtime if
# called anyway. CISCO_ISE_MCP_BLOCKED_TOOLS entries are never advertised.
# ---------------------------------------------------------------------------
# Registry tools that change deployments.json. ise_set_default_deployment only
# selects a default and stays available in read-only mode.
_REGISTRY_WRITE_TOOLS = {"ise_add_deployment", "ise_update_deployment", "ise_remove_deployment"}


def _is_write_tool(name: str) -> bool:
    """Static: can this tool (by name) change ISE or the registry?

    Passthroughs are NOT write tools by name — they stay available read-only
    with their method restricted to GET; their calls are classified at runtime.
    """
    if name in _REGISTRY_WRITE_TOOLS:
        return True
    if name in _PASSTHROUGHS or name in _META_NAMES:
        return False
    if name.startswith("ise_dc_"):
        return False
    if _maybe_destructive(name):
        return True
    method = _tool_http_method(name)
    return method is not None and method != "GET"


def _is_write_call(name: str, arguments: dict) -> bool:
    """Runtime: does THIS call change state (any surface)?"""
    if _is_write_tool(name):
        return True
    if name in _PASSTHROUGHS:
        if str(arguments.get("method", "GET")).upper() != "GET":
            return True
        return _is_destructive(name, arguments)  # e.g. MnT GET .../CoA/...
    return False


def _read_only_refusal(name: str) -> dict:
    return {
        "error": "read_only_mode",
        "tool": name,
        "reason": ("This MCP server is in read-only mode (the default). Create, update and "
                   "delete operations are disabled. An operator can enable them by setting "
                   "CISCO_ISE_MCP_ALLOW_DESTRUCTIVE=1 in the server environment and "
                   "restarting the MCP client. No changes were made."),
    }


def _read_only_variant(tool: Tool) -> Tool:
    """Passthrough as advertised in read-only mode: method limited to GET."""
    schema = compat.tool_input_schema(tool)
    props = dict(schema.get("properties", {}))
    props["method"] = {**props.get("method", {"type": "string"}), "enum": ["GET"]}
    props.pop("confirm", None)  # no destructive call is possible in read-only mode
    desc = (tool.description or "").replace("[DESTRUCTIVE] ", "")
    desc += " (Read-only mode: GET only.)"
    ann = ToolAnnotations.model_validate({"readOnlyHint": True, "openWorldHint": False})
    # Build a new Tool (inputSchema kwarg works on both SDK majors; model_copy
    # would need the major-specific field name).
    return Tool(name=tool.name, description=desc,
                inputSchema={**schema, "properties": props}, annotations=ann)


def visible_tools() -> list[Tool]:
    """Tools advertised to the client under the current environment."""
    blocked = _blocked_tools()
    writes = _destructive_allowed()
    out: list[Tool] = []
    for t in all_tools():
        if t.name in blocked:
            continue
        if not writes:
            if _is_write_tool(t.name):
                continue
            if t.name in _PASSTHROUGHS:
                t = _read_only_variant(t)
        out.append(t)
    return out


_text = compat.text_result
_err = compat.error_result


# ---------------------------------------------------------------------------
# Transport-aware error verbosity (Finding #7)
#
# On the local stdio transport the connected agent is the trusted party (it holds
# the deployment config), so full exception text aids troubleshooting. When the
# server is network-hosted for multiple users the same detail could leak internal
# paths/hostnames/backend errors, so agent-facing errors are generalized to a short
# message + correlation id while the full detail goes only to the local log.
# The HTTP/auth phase flips RUNTIME_TRANSPORT to "remote"; stdio stays "local".
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
RUNTIME_TRANSPORT = "local"


def set_transport(mode: str) -> None:
    """Set the runtime transport trust level ('local' stdio | 'remote' network)."""
    global RUNTIME_TRANSPORT
    RUNTIME_TRANSPORT = "remote" if mode == "remote" else "local"


def _error_payload(exc: Exception) -> dict:
    """Full detail on local/stdio; generalized message + error_id when network-hosted."""
    if RUNTIME_TRANSPORT == "remote":
        error_id = uuid.uuid4().hex[:12]
        logger.error("tool error [%s]: %s: %s", error_id, type(exc).__name__, exc)
        return {
            "error": "An internal error occurred while processing the request.",
            "error_id": error_id,
            "type": type(exc).__name__,
        }
    return {"error": str(exc), "type": type(exc).__name__}


def _flag(value, default: bool = False) -> bool:
    """Strictly interpret a boolean tool argument.

    ``bool("false")`` is True in Python, and the mcp 2.x low-level server does not
    validate arguments against the input schema — so a string ``"false"`` must
    never be read as consent. Only JSON ``true`` or an explicit truthy string
    counts; any other value (``"false"``, ``"0"``, ``""``, ``1.5``, ...) is False.
    ``None`` (argument omitted) yields ``default``.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in _TRUTHY
    return False


_ADD_FIELDS = {
    "name", "host", "ers_username", "ers_port", "openapi_port", "verify_ssl",
    "ca_cert_path", "monitoring_enabled",
    "dataconnect_enabled", "dataconnect_host", "dataconnect_port", "dataconnect_sid",
    "dataconnect_user", "dataconnect_mode", "dataconnect_cert_path", "dataconnect_wallet_path",
    "dataconnect_verify_ssl", "dataconnect_os_trust", "dataconnect_oracle_client_lib", "make_default",
} | set(config._LIMIT_FIELDS)

# Update accepts the same non-secret fields as add, minus make_default (use
# ise_set_default_deployment) and without requiring name/host.
_UPDATE_FIELDS = (_ADD_FIELDS - {"make_default"})


async def _probe_deployment(selector: str) -> dict:
    """Read-only live connectivity check (ERS GET + Data Connect SELECT 1)."""
    out: dict = {}
    # ERS / Open API reachability + auth
    try:
        from cisco_ise_mcp.openapi.client import ISEErSClient
        cfg = config.get_config(selector, surface="ers")
        client = ISEErSClient(host=cfg["ise_host"], port=cfg["ise_ers_port"],
                              username=cfg["ise_username"], password=cfg["ise_password"],
                              verify_ssl=cfg["verify_ssl"], ca_cert_path=cfg.get("ca_cert_path", ""))
        try:
            await client.ers_get("node", page=1, size=1)
            out["ers"] = {"ok": True, "detail": "ERS reachable and credentials accepted."}
        finally:
            await client.close()
    except Exception as exc:  # noqa: BLE001
        out["ers"] = {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}

    # Data Connect reachability + auth
    cfg_dc = config.get_config(selector)
    if not cfg_dc.get("dataconnect_enabled"):
        out["dataconnect"] = {"skipped": "Data Connect is disabled for this deployment."}
        return out
    try:
        from cisco_ise_mcp.dataconnect.client import ISEDataConnectClient
        cfg = config.get_config(selector, surface="dataconnect")
        dc_host = cfg["dataconnect_host"]
        client = ISEDataConnectClient(
            host=dc_host, port=cfg["dataconnect_port"], password=cfg["dataconnect_password"],
            user=cfg["dataconnect_user"], sid=cfg["dataconnect_sid"],
            wallet_path=cfg["dataconnect_wallet_path"], cert_path=cfg["dataconnect_cert_path"],
            mode=cfg["dataconnect_mode"], verify_ssl=cfg["dataconnect_verify_ssl"],
            os_trust=cfg["dataconnect_os_trust"],
            oracle_client_lib=cfg["dataconnect_oracle_client_lib"])

        def _q():
            try:
                client.execute_query("SELECT 1 AS OK FROM DUAL")
                return {"ok": True,
                        "detail": f"Data Connect reachable at {dc_host}:{cfg['dataconnect_port']} and credentials accepted."}
            finally:
                client.close()

        out["dataconnect"] = await asyncio.wait_for(asyncio.to_thread(_q), timeout=30)
    except Exception as exc:  # noqa: BLE001
        out["dataconnect"] = {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
    return out


async def _test_deployment(arguments: dict) -> dict:
    """Offline validation always; live probe only when config is complete and probe!=false."""
    selector = arguments.get("deployment")
    result = config.validate_deployment(selector)
    if result.get("ok") and _flag(arguments.get("probe"), default=True):
        result["probe"] = await _probe_deployment(result["slug"])
    elif not result.get("ok"):
        result["probe"] = {"skipped": "Fix the missing fields/credentials above before probing."}
    return result


async def _handle_meta(name: str, arguments: dict) -> compat.ToolResult:
    if name == "ise_capabilities":
        return _text(routing.capabilities())
    if name == "ise_route":
        return _text(routing.recommend(arguments.get("query", "")))
    if name == "ise_catalog_info":
        meta = catalog.get_meta()
        return _text({
            "ise_version": meta.get("ise_version"),
            "generated_utc": meta.get("generated_utc"),
            "sources": meta.get("sources"),
            "counts": meta.get("counts"),
            "tool_counts": {
                "ers": len(list_ers_tools()),
                "openapi": len(list_openapi_tools()),
                "monitoring": len(list_monitoring_tools()),
                "dataconnect": len(list_dataconnect_tools()),
                "meta": len(_META_TOOLS),
            },
        })
    if name == "ise_catalog_diff":
        return _text(routing.catalog_diff(arguments.get("only", "dc")))
    if name == "ise_list_deployments":
        return _text({
            "deployments": config.list_deployments(),
            "default": config.get_default(),
            "note": config.get_note(),
            "registry_path": str(config.get_registry_path()),
            "hint": "Use a deployment's name, slug, or number in any tool's 'deployment' argument.",
        })
    if name == "ise_add_deployment":
        kwargs = {k: v for k, v in arguments.items() if k in _ADD_FIELDS}
        return _text(config.add_deployment(**kwargs))
    if name == "ise_update_deployment":
        kwargs = {k: v for k, v in arguments.items() if k in _UPDATE_FIELDS}
        return _text(config.update_deployment(
            arguments.get("deployment", ""),
            reslug=_flag(arguments.get("reslug")), **kwargs))
    if name == "ise_remove_deployment":
        return _text(config.remove_deployment(
            arguments.get("deployment", ""), confirm=_flag(arguments.get("confirm"))))
    if name == "ise_set_default_deployment":
        return _text(config.set_default(arguments.get("deployment", "")))
    if name == "ise_test_deployment":
        return _text(await _test_deployment(arguments))
    if name == "ise_limits_status":
        return _text(_limits_status(arguments.get("deployment")))
    raise ValueError(f"Unknown meta tool: {name}")


def _limits_status(selector: Optional[str] = None) -> dict:
    """Configured limits per deployment plus live usage from active limiters."""
    from cisco_ise_mcp.limits import SURFACES, resolve_policy, snapshot_all

    reg = config.load_registry()
    slugs = [config.resolve_deployment(selector)] if selector else list(reg["deployments"])
    configured: dict = {}
    for slug in slugs:
        block = (reg["deployments"].get(slug, {}) or {}).get("limits") or {}
        configured[slug] = {
            s: resolve_policy(s, slug, block.get(s)).as_dict() for s in SURFACES
        }
    return {
        "configured": configured,
        "live": snapshot_all(),
        "precedence": (
            "Environment variables (CISCO_ISE_MCP_*) are hard ceilings; a per-deployment "
            "'limits' block in the registry may only tighten them, never raise them."
        ),
        "note": (
            "'live' lists only limiters created since the server started — a surface that "
            "has not been called yet will be absent."
        ),
    }


# Meta tools that change persisted state (registry). Read-only meta tools
# (list/route/capabilities/test/catalog_*) are intentionally excluded.
_MUTATING_META = {
    "ise_add_deployment", "ise_update_deployment",
    "ise_remove_deployment", "ise_set_default_deployment",
}
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _is_mutating(name: str, arguments: dict) -> bool:
    """True if a tool call changes state (worth an audit entry)."""
    if name in _MUTATING_META:
        return True
    if name.startswith("ise_ers_"):
        action = name[len("ise_ers_"):]
        if action == "request":
            return str(arguments.get("method", "")).upper() in _MUTATING_METHODS
        return action.split("_", 1)[0] in {"create", "update", "patch", "delete"}
    if name.startswith("ise_openapi_"):
        if name == "ise_openapi_request":
            return str(arguments.get("method", "")).upper() in _MUTATING_METHODS
        key = name[len("ise_openapi_"):]
        entry = catalog.get_openapi_index().get(key)
        return bool(entry) and entry.get("method", "GET").upper() in _MUTATING_METHODS
    if name.startswith("ise_mnt_"):
        # State-changing MnT calls: session-record deletes and CoA (reauth /
        # disconnect) — CoA is a GET in the MnT API, so classify by name/path.
        return _is_destructive(name, arguments)
    # ise_dc_* is read-only (SELECT only); nothing else mutates.
    return False


# ---------------------------------------------------------------------------
# Destructive-tool policy (Finding #3)
#
# Destructive ISE-side operations (deletes, patch/backup rollback+restore, CoA
# disconnect, session deletes) are gated so a prompt-injected agent cannot casually
# take disruptive action against production ISE. Evaluation order per call:
#   1. blocked_set (CISCO_ISE_MCP_BLOCKED_TOOLS) — ALWAYS denied ("use the GUI"),
#      even when destructive ops are otherwise enabled. This is the seam for a
#      future "force-GUI" list.
#   2. CISCO_ISE_MCP_ALLOW_DESTRUCTIVE — must be truthy (default OFF/"0"), else deny.
#   3. confirm=true — ALWAYS required on the call, independent of the allow flag.
# Registry-side ise_remove_deployment is NOT gated here (it has its own confirm and
# only edits the local registry, not ISE).
# ---------------------------------------------------------------------------

# Open API POST tools that are destructive / service-impacting despite not using
# the DELETE method: rollbacks and restores replace state; patch/hot-patch
# installs restart application services (node outage); certificate imports can
# restart services when the cert is bound to Admin/EAP/portal roles.
_DESTRUCTIVE_OPENAPI_POST = {
    "patch_rollback", "hotpatch_rollback", "backup_restore",
    "patch_install", "hotpatch_install", "cert_system_import", "cert_trusted_import",
}
# The same operations reached through the raw ise_openapi_request passthrough
# (matched against the lower-cased, percent-decoded path for any non-GET method).
_DESTRUCTIVE_OPENAPI_PATH = re.compile(
    r"/(?:hot)?patch/(?:install|rollback)\b"
    r"|/backup-restore/.*restore\b"
    r"|/certs/[^?#]*/import\b"
    r"|/reset\b"
)
# MnT operations that disconnect/re-authenticate live sessions or delete session
# records. CoA is a GET in the MnT API, so these are matched by PATH, any method.
_DESTRUCTIVE_MNT_TOOLS = {"coa_reauth", "coa_disconnect"}
_DESTRUCTIVE_MNT_PATH = re.compile(r"/coa/|/session/delete/")
_TRUTHY = {"1", "true", "yes", "on"}


def _norm_path(path) -> str:
    """Lower-cased, percent-decoded, slash-prefixed path for classification only."""
    p = unquote(str(path or "")).strip().lower()
    return p if p.startswith("/") else "/" + p


def _is_destructive(name: str, arguments: dict) -> bool:
    """True if this specific call performs a destructive ISE-side operation."""
    if name.startswith("ise_ers_"):
        action = name[len("ise_ers_"):]
        if action == "request":
            return str(arguments.get("method", "")).upper() == "DELETE"
        return action.split("_", 1)[0] == "delete"
    if name.startswith("ise_openapi_"):
        if name == "ise_openapi_request":
            method = str(arguments.get("method", "")).upper()
            if method == "DELETE":
                return True
            return method != "GET" and bool(
                _DESTRUCTIVE_OPENAPI_PATH.search(_norm_path(arguments.get("path"))))
        key = name[len("ise_openapi_"):]
        if key in _DESTRUCTIVE_OPENAPI_POST:
            return True
        entry = catalog.get_openapi_index().get(key)
        return bool(entry) and entry.get("method", "GET").upper() == "DELETE"
    if name.startswith("ise_mnt_"):
        if name == "ise_mnt_request":
            if str(arguments.get("method", "")).upper() == "DELETE":
                return True
            return bool(_DESTRUCTIVE_MNT_PATH.search(_norm_path(arguments.get("path"))))
        key = name[len("ise_mnt_"):]
        return "delete" in key or key in _DESTRUCTIVE_MNT_TOOLS
    return False


def _maybe_destructive(name: str) -> bool:
    """Name-only superset used for STATIC schema marking (method-agnostic).

    The raw passthroughs (ise_ers_request / ise_openapi_request) can be destructive
    depending on their method, so they are marked too; the runtime gate
    (`_is_destructive`) only enforces when the method is actually destructive.
    """
    if name in ("ise_ers_request", "ise_openapi_request", "ise_mnt_request"):
        return True
    if name.startswith("ise_ers_"):
        return name[len("ise_ers_"):].split("_", 1)[0] == "delete"
    if name.startswith("ise_openapi_"):
        key = name[len("ise_openapi_"):]
        if key in _DESTRUCTIVE_OPENAPI_POST:
            return True
        entry = catalog.get_openapi_index().get(key)
        return bool(entry) and entry.get("method", "GET").upper() == "DELETE"
    if name.startswith("ise_mnt_"):
        key = name[len("ise_mnt_"):]
        return "delete" in key or key in _DESTRUCTIVE_MNT_TOOLS
    return False


def _destructive_allowed() -> bool:
    return os.environ.get("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", "").strip().lower() in _TRUTHY


def _blocked_tools() -> set:
    raw = os.environ.get("CISCO_ISE_MCP_BLOCKED_TOOLS", "")
    return {t.strip() for t in raw.split(",") if t.strip()}


def _blocked_refusal(name: str) -> dict:
    return {
        "error": "disabled_by_policy",
        "tool": name,
        "reason": (f"'{name}' is blocked by the CISCO_ISE_MCP_BLOCKED_TOOLS policy. "
                   f"Perform this action directly in the ISE administration GUI."),
    }


def _destructive_gate(name: str, arguments: dict) -> dict:
    """Return a refusal payload if the call must NOT proceed, else {} to allow."""
    if name in _blocked_tools():
        return _blocked_refusal(name)
    if not _destructive_allowed():
        return {
            "error": "destructive_disabled",
            "tool": name,
            "reason": ("Destructive ISE operations are disabled by default. An operator must set "
                       "CISCO_ISE_MCP_ALLOW_DESTRUCTIVE=1 in the server environment to enable them "
                       "(confirm=true is still required on every such call). No changes were made."),
            "would_run": {"tool": name, "deployment": arguments.get("deployment")},
        }
    if not _flag(arguments.get("confirm")):
        return {
            "error": "confirmation_required",
            "tool": name,
            "reason": ("This is a destructive operation. Re-invoke with confirm=true to execute it. "
                       "No changes were made."),
            "would_run": {"tool": name, "deployment": arguments.get("deployment")},
        }
    return {}


# ---------------------------------------------------------------------------
# Argument validation
#
# The mcp 1.x low-level server validates arguments against each tool's
# inputSchema; the 2.x low-level server advertises the schema but never applies
# it. Validate here, in SDK-neutral code, so both majors enforce the same
# contract before any gate or dispatch (MCP spec: servers MUST validate inputs).
# Kill-switch: CISCO_ISE_MCP_VALIDATE_ARGS=0.
# ---------------------------------------------------------------------------
_VALIDATORS: Optional[dict] = None
_MAX_VALIDATION_ERRORS = 5


def _validators() -> dict:
    global _VALIDATORS
    if _VALIDATORS is None:
        from jsonschema import Draft202012Validator
        _VALIDATORS = {t.name: Draft202012Validator(compat.tool_input_schema(t))
                       for t in all_tools()}
    return _VALIDATORS


def _normalize_arguments(arguments: dict) -> dict:
    """Lossless coercions that keep documented usage working.

    ``deployment`` accepts a number ("1" or 1); the schema types it as string,
    so an integer selector is converted rather than rejected.
    """
    dep = arguments.get("deployment")
    if isinstance(dep, int) and not isinstance(dep, bool):
        return {**arguments, "deployment": str(dep)}
    return arguments


def _validate_arguments(name: str, arguments: dict) -> Optional[dict]:
    """Return an ``invalid_arguments`` refusal, or None when the call is valid."""
    if os.environ.get("CISCO_ISE_MCP_VALIDATE_ARGS", "1").strip().lower() in {"0", "false", "no", "off"}:
        return None
    validator = _validators().get(name)
    if validator is None:
        return None  # unknown tool: reported by dispatch
    errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.absolute_path))
    if not errors:
        return None
    details = []
    for err in errors[:_MAX_VALIDATION_ERRORS]:
        where = "/".join(str(p) for p in err.absolute_path) or "(arguments)"
        # Never echo argument VALUES back (could be large or sensitive); report
        # the location and the failing rule only.
        details.append(f"{where}: failed '{err.validator}' ({str(err.validator_value)[:80]})")
    return {
        "error": "invalid_arguments",
        "tool": name,
        "details": details,
        "hint": "Fix the listed arguments to match the tool's input schema and retry.",
    }


def _access_class(name: str, arguments: dict, destructive: bool, mutating: bool) -> str:
    """Audit category: destructive / registry / write / read."""
    if destructive:
        return "destructive"
    if name in _MUTATING_META:
        return "registry"
    if mutating or _is_write_call(name, arguments):
        return "write"
    return "read"


async def call_tool(name: str, arguments: dict) -> compat.ToolResult:
    """Validate, gate, dispatch and AUDIT one tool call.

    Every call produces exactly one final audit line (status ok / error /
    denied) naming the tool, its access class and duration; state-changing calls
    additionally get an ``attempt`` line before they execute (D2).
    """
    started = time.monotonic()
    arguments = _normalize_arguments(arguments or {})
    dep = arguments.get("deployment")

    def _audit(status: str, access: str, error: Optional[str] = None) -> None:
        audit.record(name, arguments, deployment=dep, status=status, access=access,
                     error=error, duration_ms=int((time.monotonic() - started) * 1000))

    invalid = _validate_arguments(name, arguments)
    if invalid:
        _audit("denied", "unknown", "invalid_arguments")
        return _err(invalid)

    destructive = _is_destructive(name, arguments)
    mutating = _is_mutating(name, arguments) or destructive
    access = _access_class(name, arguments, destructive, mutating)

    # Operator blocklist applies to EVERY tool (read or write) and is checked
    # first, before classification or dispatch.
    if name in _blocked_tools():
        refusal = _blocked_refusal(name)
        _audit("denied", access, refusal["error"])
        return _err(refusal)

    # Read-only default: no state change of any kind unless enabled.
    if not _destructive_allowed() and _is_write_call(name, arguments):
        refusal = _read_only_refusal(name)
        _audit("denied", access, refusal["error"])
        return _err(refusal)

    # Gate destructive ISE operations BEFORE any dispatch (Finding #3).
    if destructive:
        refusal = _destructive_gate(name, arguments)
        if refusal:
            _audit("denied", access, refusal.get("error"))
            return _err(refusal)
    if access != "read":
        # Record the ATTEMPT before a state change executes (pre + post audit).
        _audit("attempt", access)

    try:
        if name in _META_NAMES:
            result = await _handle_meta(name, arguments)
        elif name.startswith("ise_ers_"):
            result = await handle_ers_tool(name, arguments)
        elif name.startswith("ise_openapi_"):
            result = await handle_openapi_tool(name, arguments)
        elif name.startswith("ise_mnt_"):
            result = await handle_monitoring_tool(name, arguments)
        elif name.startswith("ise_dc_"):
            result = await handle_dataconnect_tool(name, arguments)
        else:
            _audit("denied", access, "unknown_tool")
            return _err({"error": f"Unknown tool: {name}"})
        _audit("ok", access)
        return result
    except LimitExceeded as e:
        # A resource limit refused the call. Return its structured payload — the
        # agent gets actionable guidance ("narrow the query") instead of a stack
        # trace, in the same shape as the destructive-tool refusal above.
        _audit("denied", access, e.payload.get("error"))
        return _err({**e.payload, "tool": name})
    except Exception as e:  # noqa: BLE001 — surface errors to the agent as a result
        _audit("error", access, f"{type(e).__name__}: {e}")
        return _err(_error_payload(e))


server = compat.make_server("cisco-ise-mcp", "1.1.0", _list_tools, call_tool)


def _configure_logging() -> None:
    """Send server logs to STDERR so security/limit warnings are not lost.

    stdout carries the stdio JSON-RPC stream and must never receive log output.
    Level from CISCO_ISE_MCP_LOG_LEVEL (default WARNING). Respects a logging
    configuration the host already installed (``basicConfig`` is a no-op then).
    """
    import sys
    raw = os.environ.get("CISCO_ISE_MCP_LOG_LEVEL", "WARNING").strip().upper()
    level = getattr(logging, raw, None)
    if not isinstance(level, int):
        level = logging.WARNING
    logging.basicConfig(
        stream=sys.stderr, level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main():
    """Console-script entry point (synchronous wrapper)."""
    _configure_logging()
    config.ensure_registry()
    audit.startup()
    asyncio.run(compat.serve(server))


if __name__ == "__main__":
    main()
