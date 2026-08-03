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

from typing import Any

from mcp.types import Tool

from cisco_ise_mcp import _mcpcompat as compat
from cisco_ise_mcp import catalog
from cisco_ise_mcp.config import get_config, with_deployment
from cisco_ise_mcp.dataconnect.client import ISEDataConnectClient, build_query, validate_raw_select

# Hard row cap for the raw ise_dc_query path (mirrors the structured build_query
# cap) so an unbounded SELECT can't exhaust memory.
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
    "days_back": {"type": "integer", "description": "Only rows from the last N days (uses the view's time column)."},
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
    )
    try:
        if name == "ise_dc_query":
            sql = arguments["sql"]
            allowed = {v["view"].upper() for v in catalog.get_dc_views(include_internal=True).values()}
            validate_raw_select(sql, allowed)
            rows = client.execute_query(sql, max_rows=_RAW_QUERY_CAP)
            if len(rows) >= _RAW_QUERY_CAP:
                return _text({
                    "truncated": True,
                    "row_cap": _RAW_QUERY_CAP,
                    "note": (f"Result capped at {_RAW_QUERY_CAP} rows. Add your own "
                             f"FETCH FIRST n ROWS ONLY / aggregation to narrow it."),
                    "rows": rows,
                })
            return _text(rows)
        if name == "ise_dc_view" or name.startswith("ise_dc_view_"):
            key = arguments["view"] if name == "ise_dc_view" else name[len("ise_dc_view_"):]
            return _text(_run_view(client, key, arguments))
        raise ValueError(f"Unknown Data Connect tool: {name}")
    finally:
        client.close()


def _run_view(client: ISEDataConnectClient, key: str, arguments: dict) -> Any:
    views = catalog.get_dc_views(include_internal=True)
    info = views.get(key)
    if info is None:
        raise ValueError(f"Unknown Data Connect view: {key}. Use ise_dc_list_views.")
    sql, binds = build_query(info["view"], arguments, time_col=info.get("time_col"))
    return client.execute_query(sql, binds)


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
