"""
ERS (External Restful Services) tools for Cisco ISE.

Tools are generated from the ERS resource catalog
(``cisco_ise_mcp.catalog.get_ers_resources``), which is itself produced from the
authoritative ERS OpenAPI spec.  Each resource advertises exactly the CRUD
operations the spec supports (GET list / GET by id / GET by name / POST / PUT /
PATCH / DELETE).

Tool naming:
    ise_ers_resources            — list every ERS resource + supported ops
    ise_ers_list / get / search  — generic read (any resource via `resource` arg)
    ise_ers_get_by_name          — fetch by name instead of id
    ise_ers_create/update/patch/delete — generic write
    ise_ers_request              — raw passthrough for action sub-paths
    ise_ers_<action>_<resource>  — typed convenience tools for common resources

NOTE on routing: ERS handles *configuration* CRUD & current-state reads. Open API
outranks ERS — use it when it has an endpoint for the object. For historical/
reporting data (authentications, accounting, audits, sessions) prefer the Data
Connect tools (`ise_dc_*`) — see `ise_route` / `ise_capabilities`.
"""

from __future__ import annotations

from typing import Any

from mcp.types import Tool

from cisco_ise_mcp import _mcpcompat as compat
from cisco_ise_mcp import catalog
from cisco_ise_mcp.config import get_config, surface_limits, with_deployment
from cisco_ise_mcp.limits import get_limiter
from cisco_ise_mcp.openapi.client import ISEErSClient

# Common resources that get typed convenience tools (filtered to those present).
_COMMON = [
    "endpoint", "endpointgroup", "networkdevice", "networkdevicegroup",
    "internaluser", "identitygroup", "authorizationprofile", "activedirectory",
    "downloadableacl", "allowedprotocols", "node", "adminuser", "sgt", "sgacl",
    "tacacscommandsets", "tacacsprofile", "guestuser", "guesttype", "ancpolicy",
    "ancendpoint", "profilerprofile", "portal", "repository", "ldap", "restidstore",
]


def _resource_enum() -> dict:
    keys = sorted(catalog.get_ers_resources().keys())
    return {
        "resource": {
            "type": "string",
            "enum": keys,
            "description": "ERS resource name. Use ise_ers_resources to see all with their supported operations.",
        }
    }


def _build_tools() -> list[Tool]:
    res = catalog.get_ers_resources()
    enum = _resource_enum()
    tools: list[Tool] = []

    tools.append(Tool(
        name="ise_ers_resources",
        description="List every available ERS resource with its API path and supported operations (list/get/create/update/patch/delete/get_by_name).",
        inputSchema={"type": "object", "properties": {}},
    ))
    tools.append(Tool(
        name="ise_ers_list",
        description="List all objects of an ERS resource type (paginated). ERS = live configuration; for reports use ise_dc_* (Data Connect).",
        inputSchema={"type": "object", "required": ["resource"], "properties": {
            **enum, "page": {"type": "integer", "default": 1},
            "size": {"type": "integer", "default": 100, "description": "Page size (max 100)"}}},
    ))
    tools.append(Tool(
        name="ise_ers_get",
        description="Retrieve a single ERS object by its ID.",
        inputSchema={"type": "object", "required": ["resource", "id"], "properties": {
            **enum, "id": {"type": "string", "description": "Resource ID (UUID)"}}},
    ))
    tools.append(Tool(
        name="ise_ers_get_by_name",
        description="Retrieve a single ERS object by its name (for resources that support /name/<name>).",
        inputSchema={"type": "object", "required": ["resource", "name"], "properties": {
            **enum, "name": {"type": "string", "description": "Resource name"}}},
    ))
    tools.append(Tool(
        name="ise_ers_search",
        description="Search/filter ERS objects with ERS filter ('field.OP.value') and sort ('+field'/'-field') expressions.",
        inputSchema={"type": "object", "required": ["resource"], "properties": {
            **enum,
            "filter": {"type": "string", "description": "e.g. 'name.CONTAINS.sw', 'mac.EQ.AA:BB:CC:DD:EE:FF'"},
            "sort": {"type": "string", "description": "e.g. '+name' or '-name'"},
            "page": {"type": "integer", "default": 1}, "size": {"type": "integer", "default": 100}}},
    ))
    tools.append(Tool(
        name="ise_ers_create",
        description="Create a new ERS object. Provide the JSON payload matching the resource schema (use ise_ers_get to see an example first).",
        inputSchema={"type": "object", "required": ["resource", "data"], "properties": {
            **enum, "data": {"type": "object", "description": "Full JSON object for the new resource."}}},
    ))
    tools.append(Tool(
        name="ise_ers_update",
        description="Full update (PUT) of an existing ERS object by ID. Provide the complete JSON payload.",
        inputSchema={"type": "object", "required": ["resource", "id", "data"], "properties": {
            **enum, "id": {"type": "string"}, "data": {"type": "object"}}},
    ))
    tools.append(Tool(
        name="ise_ers_patch",
        description="Partial update (PATCH) of an existing ERS object by ID (ISE 3.x). Provide only the fields to change.",
        inputSchema={"type": "object", "required": ["resource", "id", "data"], "properties": {
            **enum, "id": {"type": "string"}, "data": {"type": "object", "description": "Fields to change."}}},
    ))
    tools.append(Tool(
        name="ise_ers_delete",
        description="Delete an ERS object by ID.",
        inputSchema={"type": "object", "required": ["resource", "id"], "properties": {
            **enum, "id": {"type": "string"}}},
    ))
    tools.append(Tool(
        name="ise_ers_request",
        description="Raw ERS passthrough for action sub-paths not covered by a typed tool (e.g. POST ers/config/endpoint/{id}/deregister). Path is relative to the host root.",
        inputSchema={"type": "object", "required": ["method", "path"], "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
            "path": {"type": "string", "description": "e.g. 'ers/config/endpoint/<id>/deregister'"},
            "data": {"type": "object", "description": "Optional JSON body."},
            "params": {"type": "object", "description": "Optional query params."}}},
    ))

    # ── Typed convenience tools for common resources ──
    for key in _COMMON:
        meta = res.get(key)
        if not meta:
            continue
        label = meta["label"]
        ops = meta["ops"]
        if ops.get("list"):
            tools.append(Tool(
                name=f"ise_ers_list_{key}",
                description=f"List all {label}. Paginated.",
                inputSchema={"type": "object", "properties": {
                    "page": {"type": "integer", "default": 1}, "size": {"type": "integer", "default": 100}}},
            ))
        if ops.get("get"):
            tools.append(Tool(
                name=f"ise_ers_get_{key}",
                description=f"Get a single {label} object by ID.",
                inputSchema={"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}},
            ))
        if ops.get("list"):
            tools.append(Tool(
                name=f"ise_ers_search_{key}",
                description=f"Search/filter {label} with ERS filter expressions.",
                inputSchema={"type": "object", "properties": {
                    "filter": {"type": "string"}, "sort": {"type": "string"},
                    "page": {"type": "integer", "default": 1}, "size": {"type": "integer", "default": 100}}},
            ))
    return [with_deployment(t) for t in tools]


ERS_TOOLS: list[Tool] = _build_tools()


def list_ers_tools() -> list[Tool]:
    return ERS_TOOLS


def _resolve_path(resource_key: str) -> str:
    res = catalog.get_ers_resources()
    if resource_key not in res:
        raise ValueError(f"Unknown ERS resource: {resource_key}")
    return res[resource_key]["path"]


async def handle_ers_tool(name: str, arguments: dict) -> compat.ToolResult:
    """Dispatch an ERS tool call."""
    cfg = get_config(arguments.get("deployment"), surface="ers")
    limiter = get_limiter(cfg["_slug"], "ers", surface_limits(cfg, "ers"))
    client = ISEErSClient(
        host=cfg["ise_host"],
        port=cfg.get("ise_ers_port", 443),
        username=cfg["ise_username"],
        password=cfg["ise_password"],
        verify_ssl=cfg.get("verify_ssl", True),
        ca_cert_path=cfg.get("ca_cert_path", ""),
        max_connections=limiter.policy.max_concurrent,
    )
    try:
        # Cisco documents ~100 concurrent ERS connections per deployment, shared
        # with pxGrid, the admin GUI and every other integration — so this server
        # claims only a small slice rather than the whole budget.
        async with limiter.slot():
            result = await _dispatch_ers(client, name, arguments)
        return compat.text_result(result)
    finally:
        await client.close()


async def _dispatch_ers(client: ISEErSClient, name: str, args: dict) -> Any:
    """Route an ERS tool name to the correct client call."""

    if name == "ise_ers_resources":
        res = catalog.get_ers_resources()
        return [
            {"key": k, "path": v["path"], "label": v["label"],
             "operations": [o for o, on in v["ops"].items() if on]}
            for k, v in sorted(res.items())
        ]

    if name == "ise_ers_request":
        return await client.request(
            args["method"], args["path"], json=args.get("data"), params=args.get("params"))

    # ── Generic CRUD (resource supplied as an argument) ──
    if name in ("ise_ers_list", "ise_ers_get", "ise_ers_get_by_name", "ise_ers_search",
                "ise_ers_create", "ise_ers_update", "ise_ers_patch", "ise_ers_delete"):
        path = _resolve_path(args["resource"])
        action = name[len("ise_ers_"):]
        return await _crud(client, action, path, args)

    # ── Typed convenience tools: ise_ers_<action>_<resource> ──
    parts = name.split("_", 3)  # ["ise","ers","<action>","<resource>"]
    if len(parts) == 4:
        action, res_key = parts[2], parts[3]
        path = _resolve_path(res_key)
        return await _crud(client, action, path, args)

    raise ValueError(f"Unknown ERS tool: {name}")


async def _crud(client: ISEErSClient, action: str, path: str, args: dict) -> Any:
    if action == "list":
        return await client.ers_get(path, page=args.get("page", 1), size=args.get("size", 100))
    if action == "get":
        return await client.ers_get(path, resource_id=args["id"])
    if action == "get_by_name":
        return await client.ers_get_by_name(path, args["name"])
    if action == "search":
        return await client.ers_get(
            path, page=args.get("page", 1), size=args.get("size", 100),
            filter=args.get("filter"), sort=args.get("sort"))
    if action == "create":
        return await client.ers_create(path, args["data"])
    if action == "update":
        return await client.ers_update(path, args["id"], args["data"])
    if action == "patch":
        return await client.ers_patch(path, args["id"], args["data"])
    if action == "delete":
        return await client.ers_delete(path, args["id"])
    raise ValueError(f"Unknown ERS action: {action}")
