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
import uuid

from mcp.types import Tool

from cisco_ise_mcp import _mcpcompat as compat
from cisco_ise_mcp import audit, catalog, config, routing
from cisco_ise_mcp.openapi import (
    list_ers_tools, handle_ers_tool,
    list_openapi_tools, handle_openapi_tool,
)
from cisco_ise_mcp.monitoring import list_monitoring_tools, handle_monitoring_tool
from cisco_ise_mcp.dataconnect.tools import list_dataconnect_tools, handle_dataconnect_tool

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
            "List every configured ISE deployment with its number, name, slug, host, and whether "
            "credentials are set. Use the number or name in any tool's 'deployment' argument "
            "(e.g. 'List RADIUS policy sets on Deployment 1'). Call this to see what is available."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="ise_add_deployment",
        description=(
            "Add a new ISE deployment to the registry (non-secret fields only — passwords are NEVER "
            "passed here). Returns the exact terminal command(s) to set the password(s) afterwards. "
            "Required: name and host (and ers_username for any ERS/Open API use). Reports every "
            "missing/invalid field at once.\n"
            "GUIDED FLOW — before calling, gather the optional surfaces by asking the user (do not "
            "assume): (1) Is Data Connect reporting needed, or ERS API only? If not needed, set "
            "dataconnect_enabled=false. (2) If needed: does Data Connect run on the same node as the "
            "admin host, or a separate Monitoring (MnT) node? If separate, set dataconnect_host. "
            "(3) Certificate: if the Data Connect cert is SELF-SIGNED, the user must export it and you "
            "set dataconnect_cert_path to the saved .pem; if it is CA-SIGNED, either set "
            "dataconnect_os_trust=true (validate against the OS CA store, no file needed) or point "
            "dataconnect_cert_path at the exported root-CA file. (4) Ask whether to enable the Monitor "
            "API (MAPI/MnT) via monitoring_enabled — it needs the ERS account in ISE's 'MnT Admin' "
            "group. Data Connect is always preferred over MAPI for reporting."
        ),
        inputSchema={"type": "object", "required": ["name", "host"], "properties": {
            "name": {"type": "string", "description": "Descriptive label, e.g. 'RADIUS Only' (not a bare number)."},
            "host": {"type": "string", "description": "ISE admin-node IP or FQDN, e.g. 10.1.1.1."},
            "ers_username": {"type": "string", "description": "ERS/Open API admin username for this node."},
            "ers_port": {"type": "integer", "default": 443, "description": "ERS port (443 gateway, or 9060)."},
            "openapi_port": {"type": "integer", "default": 443, "description": "Open API port (443 gateway, or 9070)."},
            "verify_ssl": {"type": "boolean", "default": True, "description": "Verify the ISE admin TLS cert. Keep true; set false ONLY for self-signed labs (disables MITM protection for admin credentials)."},
            "ca_cert_path": {"type": "string", "description": "Path to a PEM CA bundle to trust for the ERS/Open API/Monitoring (admin) TLS connections. REQUIRED when verify_ssl=true and ISE uses a private/internal CA: httpx trusts only the built-in certifi roots and never reads the OS trust store (macOS Keychain imports do NOT help). Point this at the exported ISE root CA (Base64/PEM). Omit to use the public certifi roots (only works if the admin cert chains to a public CA)."},
            "monitoring_enabled": {"type": "boolean", "default": False, "description": "Enable the Monitoring API (MAPI / MnT, ise_mnt_*) for this deployment. Opt-in: needs the ERS account in ISE's 'MnT Admin' admin group. Prefer Data Connect for reporting."},
            "dataconnect_enabled": {"type": "boolean", "default": True, "description": "Enable Data Connect (reporting DB) for this deployment."},
            "dataconnect_host": {"type": "string", "description": "Data Connect (MnT/Monitoring node) IP or FQDN. Defaults to the admin host if omitted — set it when the MnT persona runs on a different node than the primary Admin node."},
            "dataconnect_port": {"type": "integer", "default": 2484},
            "dataconnect_sid": {"type": "string", "default": "cpm10"},
            "dataconnect_user": {"type": "string", "default": "dataconnect"},
            "dataconnect_mode": {"type": "string", "enum": ["thin", "thick"], "default": "thin",
                                 "description": "thin = no Oracle client (PEM cert); thick = Instant Client + wallet."},
            "dataconnect_cert_path": {"type": "string", "description": "Path to THIS deployment's exported Data Connect certificate (PEM). Required for a SELF-SIGNED cert; for a CA-signed cert use this for a root-CA file OR set dataconnect_os_trust instead."},
            "dataconnect_wallet_path": {"type": "string", "description": "Wallet directory (thick mode, or thin via ewallet.pem)."},
            "dataconnect_verify_ssl": {"type": "boolean", "default": True},
            "dataconnect_os_trust": {"type": "boolean", "default": False, "description": "CA-signed Data Connect cert: validate the chain against the OS/default CA trust store instead of a downloaded PEM (no cert_path needed). Leave false for a self-signed cert. macOS reads the OpenSSL/certifi bundle, not the Keychain."},
            "dataconnect_oracle_client_lib": {"type": "string", "description": "Optional Oracle Instant Client dir (thick mode)."},
            "make_default": {"type": "boolean", "description": "Make this the default deployment."}}},
    ),
    Tool(
        name="ise_update_deployment",
        description=(
            "Modify an EXISTING deployment's non-secret settings — use this to fix a typo (e.g. wrong "
            "host) or add information later (e.g. enable Data Connect and set its certificate). Only the "
            "fields you pass change; everything else (including stored passwords) is preserved. Renaming "
            "to a name with a DIFFERENT slug changes the deployment's identity and moves its stored "
            "credentials, so it requires reslug=true; otherwise the rename is rejected with guidance. "
            "Passwords are NEVER set here (use the terminal: uv run cisco-ise-mcp set-credential <name>). "
            "Reports any remaining gaps."
        ),
        inputSchema={"type": "object", "required": ["deployment"], "properties": {
            "deployment": {"type": "string", "description": "Name, slug, or number of the deployment to modify."},
            "name": {"type": "string", "description": "New descriptive label. If its slug differs from the current one, also pass reslug=true."},
            "reslug": {"type": "boolean", "default": False, "description": "Authorize a slug (identity) change when renaming; migrates stored credentials. Required for renames that change the slug."},
            "host": {"type": "string", "description": "New ISE admin-node IP or FQDN."},
            "ers_username": {"type": "string", "description": "ERS/Open API admin username."},
            "ers_port": {"type": "integer", "description": "ERS port (443 gateway, or 9060)."},
            "openapi_port": {"type": "integer", "description": "Open API port (443 gateway, or 9070)."},
            "verify_ssl": {"type": "boolean", "description": "Verify the ISE admin TLS cert."},
            "ca_cert_path": {"type": "string", "description": "PEM CA bundle to trust for ERS/Open API/Monitoring TLS (private ISE CA). Needed when verify_ssl=true and ISE uses an internal CA — httpx trusts only certifi, not the OS/Keychain store. Pass '' to clear and fall back to certifi."},
            "monitoring_enabled": {"type": "boolean", "description": "Enable/disable the Monitoring API (MAPI / MnT) for this deployment. Needs the ERS account in ISE's 'MnT Admin' group."},
            "dataconnect_enabled": {"type": "boolean", "description": "Enable/disable Data Connect for this deployment."},
            "dataconnect_host": {"type": "string", "description": "Data Connect (MnT/Monitoring node) IP or FQDN. Pass '' to clear and fall back to the admin host."},
            "dataconnect_port": {"type": "integer"},
            "dataconnect_sid": {"type": "string"},
            "dataconnect_user": {"type": "string"},
            "dataconnect_mode": {"type": "string", "enum": ["thin", "thick"]},
            "dataconnect_cert_path": {"type": "string", "description": "Path to THIS deployment's Data Connect certificate (PEM). Pass '' to clear (e.g. when switching to os_trust)."},
            "dataconnect_wallet_path": {"type": "string"},
            "dataconnect_verify_ssl": {"type": "boolean"},
            "dataconnect_os_trust": {"type": "boolean", "description": "CA-signed Data Connect cert: validate against the OS/default CA store instead of a PEM (no cert_path needed). False for self-signed."},
            "dataconnect_oracle_client_lib": {"type": "string"}}},
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
    "description": (
        "Required for this DESTRUCTIVE operation: must be true to execute. The server "
        "additionally requires an operator to enable destructive tools "
        "(CISCO_ISE_MCP_ALLOW_DESTRUCTIVE=1); without it the call is refused regardless."
    ),
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


def all_tools() -> list[Tool]:
    """Every tool this server exposes — SDK-agnostic; reused by scripts/validate.py."""
    tools: list[Tool] = []
    tools.extend(_META_TOOLS)
    tools.extend(list_ers_tools())
    tools.extend(list_openapi_tools())
    tools.extend(list_monitoring_tools())
    tools.extend(list_dataconnect_tools())
    return [_mark_destructive(t) for t in tools]


async def _list_tools() -> list[Tool]:
    return all_tools()


_text = compat.text_result


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


_ADD_FIELDS = {
    "name", "host", "ers_username", "ers_port", "openapi_port", "verify_ssl",
    "ca_cert_path", "monitoring_enabled",
    "dataconnect_enabled", "dataconnect_host", "dataconnect_port", "dataconnect_sid",
    "dataconnect_user", "dataconnect_mode", "dataconnect_cert_path", "dataconnect_wallet_path",
    "dataconnect_verify_ssl", "dataconnect_os_trust", "dataconnect_oracle_client_lib", "make_default",
}

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
    if result.get("ok") and arguments.get("probe", True):
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
            reslug=bool(arguments.get("reslug", False)), **kwargs))
    if name == "ise_remove_deployment":
        return _text(config.remove_deployment(
            arguments.get("deployment", ""), confirm=bool(arguments.get("confirm", False))))
    if name == "ise_set_default_deployment":
        return _text(config.set_default(arguments.get("deployment", "")))
    if name == "ise_test_deployment":
        return _text(await _test_deployment(arguments))
    raise ValueError(f"Unknown meta tool: {name}")


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
        # The only state-changing MnT tools delete session records.
        return "delete" in name
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

# Open API POST tools that are destructive despite not using the DELETE method.
_DESTRUCTIVE_OPENAPI_POST = {"patch_rollback", "hotpatch_rollback", "backup_restore"}
_TRUTHY = {"1", "true", "yes", "on"}


def _is_destructive(name: str, arguments: dict) -> bool:
    """True if this specific call performs a destructive ISE-side operation."""
    if name.startswith("ise_ers_"):
        action = name[len("ise_ers_"):]
        if action == "request":
            return str(arguments.get("method", "")).upper() == "DELETE"
        return action.split("_", 1)[0] == "delete"
    if name.startswith("ise_openapi_"):
        if name == "ise_openapi_request":
            return str(arguments.get("method", "")).upper() == "DELETE"
        key = name[len("ise_openapi_"):]
        if key in _DESTRUCTIVE_OPENAPI_POST:
            return True
        entry = catalog.get_openapi_index().get(key)
        return bool(entry) and entry.get("method", "GET").upper() == "DELETE"
    if name.startswith("ise_mnt_"):
        if name == "ise_mnt_request":
            return str(arguments.get("method", "")).upper() == "DELETE"
        return "delete" in name or name == "ise_mnt_coa_disconnect"
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
        return "delete" in name or name == "ise_mnt_coa_disconnect"
    return False


def _destructive_allowed() -> bool:
    return os.environ.get("CISCO_ISE_MCP_ALLOW_DESTRUCTIVE", "").strip().lower() in _TRUTHY


def _blocked_tools() -> set:
    raw = os.environ.get("CISCO_ISE_MCP_BLOCKED_TOOLS", "")
    return {t.strip() for t in raw.split(",") if t.strip()}


def _destructive_gate(name: str, arguments: dict) -> dict:
    """Return a refusal payload if the call must NOT proceed, else {} to allow."""
    if name in _blocked_tools():
        return {
            "error": "disabled_by_policy",
            "tool": name,
            "reason": (f"'{name}' is blocked by the CISCO_ISE_MCP_BLOCKED_TOOLS policy. "
                       f"Perform this action directly in the ISE administration GUI."),
        }
    if not _destructive_allowed():
        return {
            "error": "destructive_disabled",
            "tool": name,
            "reason": ("Destructive ISE operations are disabled by default. An operator must set "
                       "CISCO_ISE_MCP_ALLOW_DESTRUCTIVE=1 in the server environment to enable them "
                       "(confirm=true is still required on every such call). No changes were made."),
            "would_run": {"tool": name, "deployment": arguments.get("deployment")},
        }
    if not bool(arguments.get("confirm", False)):
        return {
            "error": "confirmation_required",
            "tool": name,
            "reason": ("This is a destructive operation. Re-invoke with confirm=true to execute it. "
                       "No changes were made."),
            "would_run": {"tool": name, "deployment": arguments.get("deployment")},
        }
    return {}


async def call_tool(name: str, arguments: dict) -> compat.ToolResult:
    destructive = _is_destructive(name, arguments)
    mutating = _is_mutating(name, arguments) or destructive
    dep = arguments.get("deployment")

    # Gate destructive ISE operations BEFORE any dispatch (Finding #3).
    if destructive:
        refusal = _destructive_gate(name, arguments)
        if refusal:
            audit.record(name, arguments, deployment=dep,
                         status="denied", error=refusal.get("error"))
            return _text(refusal)
        # Passed the gate — record the ATTEMPT before executing (pre + post audit).
        audit.record(name, arguments, deployment=dep, status="attempt")

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
            return _text({"error": f"Unknown tool: {name}"})
        if mutating:
            audit.record(name, arguments, deployment=dep, status="ok")
        return result
    except Exception as e:  # noqa: BLE001 — surface errors to the agent as a result
        if mutating:
            audit.record(name, arguments, deployment=dep,
                         status="error", error=f"{type(e).__name__}: {e}")
        return _text(_error_payload(e))


server = compat.make_server("cisco-ise-mcp", "1.0.0", _list_tools, call_tool)


def main():
    """Console-script entry point (synchronous wrapper)."""
    config.ensure_registry()
    asyncio.run(compat.serve(server))


if __name__ == "__main__":
    main()
