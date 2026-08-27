"""
Open API (ISE 3.1+) tools for Cisco ISE — the newer REST APIs under ``/api/``.

Tools are generated from the curated Open API catalog
(``cisco_ise_mcp.catalog.get_openapi_endpoints``).  Each catalog entry maps a
tool to a concrete ``(method, path)`` with corroborated ISE 3.4 paths
(e.g. RADIUS policy = ``/api/v1/policy/network-access/...``, TACACS+ =
``/api/v1/policy/device-admin/...``).  Dispatch fills ``{placeholders}`` in the
path from the call arguments and issues a single generic request — no
method-name guessing.

Because the full ``/api/`` surface is large and not exported as a spec from the
node, anything not curated is reachable via ``ise_openapi_request`` (raw
method + path + body).

Base URL: ``https://<host>:<openapi_port>`` (default 443 admin gateway; 9070 is
the dedicated Open API listener — set ISE_OPENAPI_PORT).
"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import quote

import httpx
from mcp.types import Tool

from cisco_ise_mcp import _mcpcompat as compat
from cisco_ise_mcp import catalog
from cisco_ise_mcp.config import get_config, surface_limits, with_deployment
from cisco_ise_mcp.limits import get_limiter

_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class ISEOpenAPIClient:
    """Async HTTP client for the ISE 3.1+ Open API endpoints."""

    def __init__(self, host: str, username: str, password: str,
                 port: int = 443, verify_ssl: bool = True, ca_cert_path: str = "",
                 max_connections: int = 0):
        self.base_url = f"https://{host}:{port}"
        # httpx verify=True trusts only certifi, not the OS/Keychain store;
        # admin_tls_verify() adds a private ISE CA when ca_cert_path is set.
        from cisco_ise_mcp.config import admin_tls_verify
        kwargs: dict = {}
        if max_connections and max_connections > 0:
            # Bound the socket pool to the concurrency this surface was granted.
            kwargs["limits"] = httpx.Limits(
                max_connections=int(max_connections),
                max_keepalive_connections=int(max_connections),
            )
        self._client = httpx.AsyncClient(
            auth=(username, password),
            verify=admin_tls_verify(verify_ssl, ca_cert_path),
            timeout=60.0,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            **kwargs,
        )

    async def close(self):
        await self._client.aclose()

    async def request(self, method: str, path: str,
                      json: Optional[dict] = None, params: Optional[dict] = None) -> Any:
        clean = path.strip().lstrip("/")
        if ".." in clean.split("/"):
            raise ValueError(f"Path traversal ('..') is not allowed in path: {path!r}")
        # Confine the passthrough to the Open API surface so a raw call cannot
        # reach other authenticated surfaces (/admin/..., /ers/...) on the host.
        if not clean.startswith("api/"):
            raise ValueError(
                f"Open API passthrough paths must start with '/api/' (got {path!r}). "
                f"Use ise_ers_request for /ers/ or ise_mnt_request for /admin/API/mnt/ paths."
            )
        url = f"{self.base_url}/{clean}"
        resp = await self._client.request(method.upper(), url, json=json, params=params or {})
        resp.raise_for_status()
        if resp.status_code == 204 or not resp.content:
            return {"status": "ok", "code": resp.status_code}
        try:
            return resp.json()
        except ValueError:
            return {"status": "ok", "code": resp.status_code, "body": resp.text}


def _build_tools() -> list[Tool]:
    tools: list[Tool] = []
    for e in catalog.get_openapi_endpoints():
        props: dict = {}
        required: list[str] = []
        for p in e["params"]:
            props[p] = {"type": "string", "description": f"Path parameter '{p}'."}
            required.append(p)
        if e["body"]:
            props["data"] = {"type": "object", "description": "JSON request body."}
            if e["method"] in ("POST", "PUT", "PATCH"):
                required.append("data")
        if e["method"] == "GET" and not e["params"]:
            props["page"] = {"type": "integer", "default": 1}
            props["size"] = {"type": "integer", "default": 100}
        desc = e["desc"]
        if e.get("category"):
            desc = f"[{e['category']}] {desc}"
        tools.append(Tool(
            name=f"ise_openapi_{e['tool']}",
            description=f"{desc}  ({e['method']} {e['path']})",
            inputSchema={"type": "object", "required": required, "properties": props},
        ))

    tools.append(Tool(
        name="ise_openapi_request",
        description=(
            "Raw Open API passthrough — call ANY /api/ endpoint not covered by a typed tool. "
            "Provide the HTTP method and the full path (e.g. '/api/v1/certs/system-certificate/<host>'). "
            "Browse the live spec at https://<ise>/api/swagger-ui/index.html."
        ),
        inputSchema={"type": "object", "required": ["method", "path"], "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
            "path": {"type": "string", "description": "Path starting with /api/ ..."},
            "data": {"type": "object", "description": "Optional JSON body."},
            "params": {"type": "object", "description": "Optional query parameters."}}},
    ))
    return [with_deployment(t) for t in tools]


OPENAPI_TOOLS: list[Tool] = _build_tools()


def list_openapi_tools() -> list[Tool]:
    return OPENAPI_TOOLS


async def handle_openapi_tool(name: str, arguments: dict) -> compat.ToolResult:
    """Dispatch an Open API tool call via catalog lookup."""
    cfg = get_config(arguments.get("deployment"), surface="openapi")
    limiter = get_limiter(cfg["_slug"], "openapi", surface_limits(cfg, "openapi"))
    client = ISEOpenAPIClient(
        host=cfg["ise_host"],
        port=cfg.get("ise_openapi_port", 443),
        username=cfg["ise_username"],
        password=cfg["ise_password"],
        verify_ssl=cfg.get("verify_ssl", True),
        ca_cert_path=cfg.get("ca_cert_path", ""),
        max_connections=limiter.policy.max_concurrent,
    )
    try:
        # Cisco documents ~150 concurrent Open API connections per deployment,
        # shared with every other client — this server takes a small slice.
        async with limiter.slot():
            result = await _dispatch_openapi(client, name, arguments)
        return compat.text_result(result)
    finally:
        await client.close()


def _resolve(name: str, arguments: dict) -> tuple[str, str, Optional[dict], Optional[dict]]:
    """Return (method, path, body, params) for a catalog tool call."""
    key = name[len("ise_openapi_"):]
    entry = catalog.get_openapi_index().get(key)
    if entry is None:
        raise ValueError(
            f"Unknown Open API tool: {name}. Use ise_openapi_request for uncurated /api/ paths.")

    def _sub(m):
        pname = m.group(1)
        if pname not in arguments:
            raise ValueError(f"Missing required path parameter '{pname}' for {name}.")
        return quote(str(arguments[pname]), safe="")

    path = _PLACEHOLDER.sub(_sub, entry["path"])
    body = arguments.get("data") if entry["body"] else None
    params = {}
    for q in ("page", "size", "filter"):
        if q in arguments:
            params[q] = arguments[q]
    return entry["method"], path, body, (params or None)


async def _dispatch_openapi(client: ISEOpenAPIClient, name: str, arguments: dict) -> Any:
    if name == "ise_openapi_request":
        return await client.request(
            arguments["method"], arguments["path"],
            json=arguments.get("data"), params=arguments.get("params"))
    method, path, body, params = _resolve(name, arguments)
    return await client.request(method, path, json=body, params=params)
