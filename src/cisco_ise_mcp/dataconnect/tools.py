"""
Data Connect tools for Cisco ISE — read-only SQL access to the monitoring DB.

Data Connect ranks below Open API and ERS but above Monitor API in the surface
precedence. It is the surface for reporting / historical / aggregate / audit
data that no higher surface exposes (authentications, accounting, posture,
sessions, profiling). For *current configuration state* (network devices,
endpoints, SGTs, nodes, policy sets) prefer Open API / ERS; fall back to Data
Connect when they can't serve the request or you need history/aggregates.

Views come from the JSON catalog (``cisco_ise_mcp.catalog.get_dc_views``),
scraped from the Cisco DevNet "Database Views" reference, including each view's
real columns and time column.

Tools:
    ise_dc_list_views         — list all views (offline, from the catalog)
    ise_dc_describe           — column details for a view (name/type/description)
    ise_dc_view               — query any view (filter/sort/limit/days_back)
    ise_dc_view_<view>        — typed shortcut for common reporting views
    ise_dc_query              — custom read-only SELECT (advanced)
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from mcp.types import Tool

from cisco_ise_mcp import _mcpcompat as compat
from cisco_ise_mcp import audit, catalog
from cisco_ise_mcp.config import get_config, surface_limits, with_deployment
from cisco_ise_mcp.dataconnect.client import (
    ISEDataConnectClient, build_query, resolve_days_back, validate_raw_select,
)
from cisco_ise_mcp.limits import get_limiter

logger = logging.getLogger(__name__)

# Hard row cap for the raw ise_dc_query path (mirrors the structured build_query
# cap) so an unbounded SELECT can't exhaust memory. This is the OUTER ceiling: a
# smaller default bound is injected into the SQL itself when the caller supplies
# none, so Oracle stops producing rows rather than the client stopping reading.
_RAW_QUERY_CAP = 10000

# Typed shortcuts for the most-used reporting views (others via generic ise_dc_view).
_COMMON_VIEWS = [
    "radius_authentications", "radius_authentications_week", "radius_authentication_summary",
    "radius_accounting", "radius_accounting_week", "radius_errors_view",
    "tacacs_authentication", "tacacs_authorization", "tacacs_accounting", "tacacs_command_accounting",
    "endpoints_data", "endpoint_identity_groups", "registered_endpoints",
    "profiled_endpoints_summary", "posture_assessment_by_endpoint",
    "administrator_logins", "change_configuration_audit", "aup_acceptance_status",
    "network_devices", "security_groups", "coa_events", "threat_events", "system_summary",
]

_FILTER_PROPS = {
    "filter_column": {"type": "string", "description": "Column to filter on (case-insensitive)."},
    "filter_value": {"type": "string", "description": "Value to match for the filter column."},
    "filter_op": {"type": "string", "enum": ["EQ", "NEQ", "CONTAINS", "LIKE", "GT", "LT", "GTE", "LTE"],
                  "default": "EQ", "description": "EQ=exact, CONTAINS/LIKE=substring, GT/LT/GTE/LTE=compare."},
    "order_by": {"type": "string", "description": "Column to sort by (prefix '-' for descending)."},
    "limit": {"type": "integer", "default": 100, "description": "Max rows (default 100, max 10000)."},
    "days_back": {"type": "integer", "description": (
        "Only rows from the last N days (uses the view's time column). If omitted, a 7-day "
        "window is applied by default to limit load on the ISE Monitoring node. Maximum 90 — "
        "larger values are reduced to 90 rather than rejected.")},
}


def _view_enum() -> dict:
    return {"view": {"type": "string", "enum": sorted(catalog.get_dc_views().keys()),
                     "description": "Data Connect view name. Use ise_dc_list_views to see all."}}


def _build_tools() -> list[Tool]:
    views = catalog.get_dc_views()
    tools: list[Tool] = []

    tools.append(Tool(
        name="ise_dc_list_views",
        description="List all Data Connect database views with descriptions, column counts, and time columns. Starting point for reporting/historical/aggregate questions (data no higher surface exposes).",
        inputSchema={"type": "object", "properties": {}},
    ))
    tools.append(Tool(
        name="ise_dc_describe",
        description="Get the column details (name, type, description) and time column for a Data Connect view.",
        inputSchema={"type": "object", "required": ["view"], "properties": _view_enum()},
    ))
    tools.append(Tool(
        name="ise_dc_view",
        description="Query any Data Connect view with optional filter/sort/limit/days_back. Use for reporting/historical/aggregate data; for current configuration state prefer Open API/ERS.",
        inputSchema={"type": "object", "required": ["view"], "properties": {**_view_enum(), **_FILTER_PROPS}},
    ))
    tools.append(Tool(
        name="ise_dc_query",
        description="Run a custom read-only SELECT against Data Connect (advanced). Only a single SELECT is permitted; SQL comments are rejected and every FROM/JOIN target must be a Data Connect catalog view (see ise_dc_list_views). Always limit rows (FETCH FIRST n ROWS ONLY).",
        inputSchema={"type": "object", "required": ["sql"], "properties": {
            "sql": {"type": "string", "description": "e.g. SELECT username, COUNT(*) FROM radius_authentications GROUP BY username FETCH FIRST 50 ROWS ONLY"}}},
    ))

    for key in _COMMON_VIEWS:
        info = views.get(key)
        if not info:
            continue
        cols = ", ".join(c["name"] for c in info["columns"][:8])
        tools.append(Tool(
            name=f"ise_dc_view_{key}",
            description=f"[Report] {info['label']}: {info['description']} Filterable columns include: {cols}.",
            inputSchema={"type": "object", "properties": _FILTER_PROPS},
        ))
    return [with_deployment(t) for t in tools]


DC_TOOLS: list[Tool] = _build_tools()


def list_dataconnect_tools() -> list[Tool]:
    return DC_TOOLS


async def handle_dataconnect_tool(name: str, arguments: dict) -> compat.ToolResult:
    """Dispatch a Data Connect tool call."""
    if name == "ise_dc_list_views":
        return _text(_list_views())
    if name == "ise_dc_describe":
        return _text(_describe(arguments["view"]))

    cfg = get_config(arguments.get("deployment"), surface="dataconnect")
    limiter = get_limiter(cfg["_slug"], "dataconnect", surface_limits(cfg, "dataconnect"))
    policy = limiter.policy
    client = ISEDataConnectClient(
        host=cfg["dataconnect_host"],
        port=cfg.get("dataconnect_port", 2484),
        password=cfg["dataconnect_password"],
        user=cfg.get("dataconnect_user", "dataconnect"),
        sid=cfg.get("dataconnect_sid", "cpm10"),
        wallet_path=cfg.get("dataconnect_wallet_path", ""),
        cert_path=cfg.get("dataconnect_cert_path", ""),
        mode=cfg.get("dataconnect_mode", "thin"),
        verify_ssl=cfg.get("dataconnect_verify_ssl", True),
        os_trust=cfg.get("dataconnect_os_trust", False),
        oracle_client_lib=cfg.get("dataconnect_oracle_client_lib", ""),
        max_sessions=policy.max_concurrent,
        acquire_wait_s=policy.acquire_wait_s,
        query_timeout_s=policy.query_timeout_s,
    )
    try:
        # The limiter bounds how many queries run at once; asyncio.to_thread keeps
        # the blocking Oracle driver off the event loop so one slow query cannot
        # stall concurrent ERS / Open API / MnT tool calls.
        async with limiter.slot():
            if name == "ise_dc_query":
                return _text(await asyncio.to_thread(
                    _run_raw, client, arguments["sql"], policy, cfg["_slug"]))
            if name == "ise_dc_view" or name.startswith("ise_dc_view_"):
                key = arguments["view"] if name == "ise_dc_view" else name[len("ise_dc_view_"):]
                return _text(await asyncio.to_thread(
                    _run_view, client, key, arguments, policy, cfg["_slug"]))
            raise ValueError(f"Unknown Data Connect tool: {name}")
    finally:
        client.close()


def _run_raw(client: ISEDataConnectClient, sql: str, policy: Any, slug: str) -> Any:
    """Guard, bound and execute a raw SELECT (runs in a worker thread)."""
    views = catalog.get_dc_views(include_internal=True)
    allowed = {v["view"].upper() for v in views.values()}
    time_cols = {v["view"].upper(): v.get("time_col") for v in views.values()}
    guarded = validate_raw_select(
        sql, allowed,
        fact_views=catalog.get_fact_view_names(),
        view_time_cols=time_cols,
        policy=policy,
    )
    started = time.monotonic()
    outcome = "ok"
    rows: list = []
    try:
        rows = client.execute_query(guarded, max_rows=_RAW_QUERY_CAP)
    except Exception:
        outcome = "error"
        raise
    finally:
        audit.record_dc_query(
            "ise_dc_query", deployment=slug, rows=len(rows), outcome=outcome,
            duration_ms=int((time.monotonic() - started) * 1000))
    if len(rows) >= _RAW_QUERY_CAP:
        return {
            "truncated": True,
            "row_cap": _RAW_QUERY_CAP,
            "note": (f"Result capped at {_RAW_QUERY_CAP} rows. Add your own "
                     f"FETCH FIRST n ROWS ONLY / aggregation to narrow it."),
            "rows": rows,
        }
    return rows


def _run_view(client: ISEDataConnectClient, key: str, arguments: dict,
              policy: Any = None, slug: str = "") -> Any:
    """Run a structured view query (runs in a worker thread).

    Returns a bare row list — the response shape is unchanged, so the injected
    default window and the 90-day clamp stay non-breaking for existing callers.
    Both are announced in the tool schema (which the agent reads before calling)
    and recorded in the Data Connect query log.
    """
    views = catalog.get_dc_views(include_internal=True)
    info = views.get(key)
    if info is None:
        raise ValueError(f"Unknown Data Connect view: {key}. Use ise_dc_list_views.")

    args = dict(arguments)
    days, source = resolve_days_back(args, info.get("time_col"), policy) if policy else (
        args.get("days_back"), "explicit")
    if days is not None:
        args["days_back"] = days
    if source == "clamped":
        logger.warning(
            "Data Connect: days_back=%s requested for view '%s' exceeds the %s-day maximum; "
            "the query ran with %s days instead.",
            arguments.get("days_back"), key, getattr(policy, "max_days_back", "?"), days)

    sql, binds = build_query(info["view"], args, time_col=info.get("time_col"))
    started = time.monotonic()
    outcome = "ok"
    rows: list = []
    try:
        rows = client.execute_query(sql, binds)
        return rows
    except Exception:
        outcome = "error"
        raise
    finally:
        audit.record_dc_query(
            key, deployment=slug, days_back=days, days_back_source=source,
            row_limit=binds.get("maxrows"), rows=len(rows), outcome=outcome,
            duration_ms=int((time.monotonic() - started) * 1000))


def _list_views() -> list[dict]:
    views = catalog.get_dc_views()
    return [
        {"key": k, "view": v["view"], "description": v["description"],
         "columns": len(v["columns"]), "time_col": v["time_col"]}
        for k, v in sorted(views.items())
    ]


def _describe(key: str) -> dict:
    views = catalog.get_dc_views(include_internal=True)
    info = views.get(key)
    if info is None:
        raise ValueError(f"Unknown Data Connect view: {key}. Use ise_dc_list_views.")
    return {"view": info["view"], "description": info["description"],
            "time_col": info.get("time_col"), "columns": info["columns"]}


_text = compat.text_result
