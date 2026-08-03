"""
ERS (External Restful Services) HTTP client for Cisco ISE.

All ERS endpoints follow the pattern:
    https://<host>:<port>/ers/config/<resource>[/<id>]
    https://<host>:<port>/ers/config/<resource>/<id>/<child>[/<child_id>]

Supported HTTP methods: GET, POST, PUT, PATCH, DELETE
Authentication: HTTP Basic Auth

Resource definitions live in the JSON catalog (``cisco_ise_mcp.catalog``),
generated from the authoritative ERS spec — not hard-coded here.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import quote

import httpx


class ISEErSClient:
    """Async HTTP client for Cisco ISE ERS APIs."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        verify_ssl: bool = True,
        ca_cert_path: str = "",
    ):
        self.base_url = f"https://{host}:{port}"
        self.auth = (username, password)
        # httpx trusts only the certifi bundle for verify=True and never the OS
        # trust store; admin_tls_verify() lets an operator add a private ISE CA.
        from cisco_ise_mcp.config import admin_tls_verify
        self._verify = admin_tls_verify(verify_ssl, ca_cert_path)
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                auth=self.auth,
                verify=self._verify,
                timeout=30.0,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ── Generic CRUD helpers ──

    async def ers_get(
        self,
        resource: str,
        resource_id: Optional[str] = None,
        page: int = 1,
        size: int = 100,
        filter: Optional[str] = None,
        sort: Optional[str] = None,
    ) -> dict:
        """GET /ers/config/<resource>[/<id>] — list or retrieve a single resource."""
        path_parts = ["ers", "config", resource]
        if resource_id:
            path_parts.append(quote(resource_id, safe=""))
        url = f"{self.base_url}/{'/'.join(path_parts)}"
        params: dict = {} if resource_id else {"page": page, "size": size}
        if filter:
            params["filter"] = filter
        if sort:
            params["sort"] = sort
        client = await self._get_client()
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    async def ers_get_by_name(self, resource: str, name: str) -> dict:
        """GET /ers/config/<resource>/name/<name>."""
        url = f"{self.base_url}/ers/config/{resource}/name/{quote(name, safe='')}"
        client = await self._get_client()
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()

    async def ers_create(self, resource: str, data: dict) -> dict:
        """POST /ers/config/<resource> — create a new resource."""
        url = f"{self.base_url}/ers/config/{resource}"
        client = await self._get_client()
        resp = await client.post(url, json=data)
        resp.raise_for_status()
        return _json_or_status(resp, "created")

    async def ers_update(self, resource: str, resource_id: str, data: dict) -> dict:
        """PUT /ers/config/<resource>/<id> — full update of an existing resource."""
        url = f"{self.base_url}/ers/config/{resource}/{quote(resource_id, safe='')}"
        client = await self._get_client()
        resp = await client.put(url, json=data)
        resp.raise_for_status()
        return _json_or_status(resp, "updated")

    async def ers_patch(self, resource: str, resource_id: str, data: dict) -> dict:
        """PATCH /ers/config/<resource>/<id> — partial update (ISE 3.x)."""
        url = f"{self.base_url}/ers/config/{resource}/{quote(resource_id, safe='')}"
        client = await self._get_client()
        resp = await client.patch(url, json=data)
        resp.raise_for_status()
        return _json_or_status(resp, "patched")

    async def ers_delete(self, resource: str, resource_id: str) -> dict:
        """DELETE /ers/config/<resource>/<id> — delete a resource."""
        url = f"{self.base_url}/ers/config/{resource}/{quote(resource_id, safe='')}"
        client = await self._get_client()
        resp = await client.delete(url)
        resp.raise_for_status()
        return {"status": "deleted", "code": resp.status_code}

    # ── Child resources ──

    async def ers_child_get(
        self,
        resource: str,
        resource_id: str,
        child_resource: str,
        child_id: Optional[str] = None,
        page: int = 1,
        size: int = 100,
    ) -> dict:
        """GET /ers/config/<resource>/<id>/<child>[/<child_id>]"""
        parts = ["ers", "config", resource, quote(resource_id, safe=""), child_resource]
        if child_id:
            parts.append(quote(child_id, safe=""))
        url = f"{self.base_url}/{'/'.join(parts)}"
        client = await self._get_client()
        params = {} if child_id else {"page": page, "size": size}
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    # ── Generic passthrough ──

    async def request(
        self,
        method: str,
        path: str,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Any:
        """
        Raw ERS request escape hatch for any path not covered by a typed helper
        (e.g. action sub-paths like '/ers/config/endpoint/{id}/deregister').

        ``path`` is relative to the host root, e.g. 'ers/config/endpoint'.
        """
        clean = path.strip().lstrip("/")
        if ".." in clean.split("/"):
            raise ValueError(f"Path traversal ('..') is not allowed in ERS path: {path!r}")
        if not clean.startswith("ers/"):
            raise ValueError(
                f"ERS passthrough paths must start with 'ers/' (got {path!r}). "
                f"Use ise_openapi_request for /api/ endpoints."
            )
        url = f"{self.base_url}/{clean}"
        client = await self._get_client()
        resp = await client.request(method.upper(), url, json=json, params=params or {})
        resp.raise_for_status()
        return _json_or_status(resp, "ok")


def _json_or_status(resp: httpx.Response, verb: str) -> Any:
    """Return parsed JSON when present, else a status summary (ERS often 201/204 with no body)."""
    if resp.status_code in (201, 204) or not resp.content:
        loc = resp.headers.get("Location")
        out = {"status": verb, "code": resp.status_code}
        if loc:
            out["location"] = loc
            out["id"] = loc.rstrip("/").rsplit("/", 1)[-1]
        return out
    try:
        return resp.json()
    except ValueError:
        return {"status": verb, "code": resp.status_code, "body": resp.text}
