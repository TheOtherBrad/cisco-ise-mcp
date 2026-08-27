"""
Monitoring (MnT) tools for Cisco ISE — the legacy ``/admin/API/mnt`` REST API.

Tools are generated from the curated Monitoring catalog
(``cisco_ise_mcp.catalog.get_monitoring_endpoints``), parsed from the Monitoring
OpenAPI spec.  Each catalog entry maps a tool to a concrete ``(method, path)``;
dispatch fills ``{placeholders}`` in the path from the call arguments and issues a
single request that returns the **raw XML** response body.

Tool naming:
    ise_mnt_<name>     — typed shortcut for a curated MnT operation
    ise_mnt_request    — raw passthrough for any MnT path not curated

NOTE on routing: MnT is the lowest-precedence surface — legacy and returns XML.
Use it only when no higher surface serves the request; for reporting / historical
/ aggregate data prefer the Data Connect tools (``ise_dc_*``).
"""

from __future__ import annotations

import re
from typing import Any, Optional

from mcp.types import Tool

from cisco_ise_mcp import _mcpcompat as compat
from cisco_ise_mcp import catalog
from cisco_ise_mcp.config import get_config, surface_limits, with_deployment
from cisco_ise_mcp.limits import get_limiter
from cisco_ise_mcp.monitoring.client import ISEMonitoringClient

_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _build_tools() -> list[Tool]:
    tools: list[Tool] = []
    for e in catalog.get_monitoring_endpoints():
        props: dict = {}
        required: list[str] = []
        for p in e["params"]:
            props[p] = {"type": "string", "description": f"Path parameter '{p}'."}
            required.append(p)
        desc = e.get("desc", "")
        if e.get("category"):
            desc = f"[{e['category']}] {desc}"
        tools.append(Tool(
            name=f"ise_mnt_{e['tool']}",
            description=f"{desc}  ({e['method']} {e['path']}). Returns raw XML.",
            inputSchema={"type": "object", "required": required, "properties": props},
        ))

    tools.append(Tool(
        name="ise_mnt_request",
        description=(
            "Raw Monitoring (MnT) passthrough — call ANY /admin/API/mnt/ endpoint not "
            "covered by a typed tool (e.g. '/admin/API/mnt/Session/ActiveList'). Returns "
            "raw XML. MnT is legacy; prefer Data Connect (ise_dc_*) for reporting."
        ),
        inputSchema={"type": "object", "required": ["method", "path"], "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
            "path": {"type": "string", "description": "Path starting with /admin/API/mnt/ ..."},
            "params": {"type": "object", "description": "Optional query parameters."}}},
    ))
    return [with_deployment(t) for t in tools]


MONITORING_TOOLS: list[Tool] = _build_tools()


def list_monitoring_tools() -> list[Tool]:
    return MONITORING_TOOLS


async def handle_monitoring_tool(name: str, arguments: dict) -> compat.ToolResult:
    """Dispatch a Monitoring tool call via catalog lookup. MnT reuses the admin
    (ERS/Open API) credentials and the admin gateway port; the ``monitoring``
    surface also enforces the per-deployment MAPI enable flag."""
    cfg = get_config(arguments.get("deployment"), surface="monitoring")
    limiter = get_limiter(cfg["_slug"], "monitoring", surface_limits(cfg, "monitoring"))
    client = ISEMonitoringClient(
        host=cfg["ise_host"],
        port=cfg.get("ise_openapi_port", 443),
        username=cfg["ise_username"],
        password=cfg["ise_password"],
        verify_ssl=cfg.get("verify_ssl", True),
        ca_cert_path=cfg.get("ca_cert_path", ""),
        max_connections=limiter.policy.max_concurrent,
    )
    try:
        # MnT queries are the expensive legacy path, so this surface gets the
        # smallest concurrency budget of the four.
        async with limiter.slot():
            result = await _dispatch(client, name, arguments)
        return compat.text_result(result)
    finally:
        await client.close()


def _resolve(name: str, arguments: dict) -> tuple[str, str, Optional[dict]]:
    """Return (method, path, params) for a catalog tool call."""
    key = name[len("ise_mnt_"):]
    entry = catalog.get_monitoring_index().get(key)
    if entry is None:
        raise ValueError(
            f"Unknown Monitoring tool: {name}. Use ise_mnt_request for uncurated MnT paths.")

    def _sub(m):
        pname = m.group(1)
        if pname not in arguments:
            raise ValueError(f"Missing required path parameter '{pname}' for {name}.")
        return str(arguments[pname])

    path = _PLACEHOLDER.sub(_sub, entry["path"])
    return entry["method"], path, None


async def _dispatch(client: ISEMonitoringClient, name: str, arguments: dict) -> Any:
    if name == "ise_mnt_request":
        return await client.request(
            arguments["method"], arguments["path"], params=arguments.get("params"))
    method, path, params = _resolve(name, arguments)
    return await client.request(method, path, params=params)
