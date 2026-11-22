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

import os
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
        max_connections: int = 0,
    ):
        self.base_url = f"https://{host}:{port}"
        self.auth = (username, password)
        self.max_connections = int(max_connections or 0)
        # httpx trusts only the certifi bundle for verify=True and never the OS
        # trust store; admin_tls_verify() lets an operator add a private ISE CA.
        from cisco_ise_mcp.config import admin_tls_verify
        self._verify = admin_tls_verify(verify_ssl, ca_cert_path)
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            kwargs: dict = {}
            if self.max_connections > 0:
                # Bound the socket pool as well as the caller-side semaphore, so
                # the client can never exceed the concurrency this surface was
                # granted out of Cisco's deployment-wide connection budget.
                kwargs["limits"] = httpx.Limits(
                    max_connections=self.max_connections,
                    max_keepalive_connections=self.max_connections,
                )
            self._client = httpx.AsyncClient(
                auth=self.auth,
                verify=self._verify,
                # Ignore HTTP(S)_PROXY / SSL_CERT_FILE etc. from the environment so
                # admin credentials go only to the configured host with the configured trust.
                trust_env=False,
                timeout=30.0,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                **kwargs,
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
        return trim_ers(resp.json())

    async def ers_get_by_name(self, resource: str, name: str) -> dict:
        """GET /ers/config/<resource>/name/<name>."""
        url = f"{self.base_url}/ers/config/{resource}/name/{quote(name, safe='')}"
        client = await self._get_client()
        resp = await client.get(url)
        resp.raise_for_status()
        return trim_ers(resp.json())

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
        return trim_ers(resp.json())

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
        from cisco_ise_mcp.url_safety import check_passthrough_path
        try:
            clean = check_passthrough_path(path, "ers/", "ERS")
        except ValueError as exc:
            if not path.strip().lstrip("/").startswith("ers/"):
                raise ValueError(
                    f"ERS passthrough paths must start with 'ers/' (got {path!r}). "
                    f"Use ise_openapi_request for /api/ endpoints.") from exc
            raise
        url = f"{self.base_url}/{clean}"
        client = await self._get_client()
        resp = await client.request(method.upper(), url, json=json, params=params or {})
        resp.raise_for_status()
        result = _json_or_status(resp, "ok")
        return trim_ers(result) if method.upper() == "GET" else result


def _raw_ers() -> bool:
    return os.environ.get("CISCO_ISE_MCP_RAW_ERS", "").strip().lower() in {"1", "true", "yes", "on"}


def trim_ers(payload: Any) -> Any:
    """Drop hypermedia the model never needs from an ERS GET response.

    ERS repeats a ``link: {rel, href, type}`` object on every list row and on
    single objects, plus ``previousPage``/``nextPage`` link objects on lists
    (shape per the ERS OpenAPI spec). Rows are addressed by ``id`` — the href
    adds ~100 chars per row and nothing else. Paging links are replaced by
    ``has_previous``/``has_next`` booleans next to ``total``; the page number is
    still the caller's ``page`` argument. Everything else is returned verbatim.
    Kill-switch: ``CISCO_ISE_MCP_RAW_ERS=1`` returns responses unmodified.
    """
    if _raw_ers() or not isinstance(payload, dict):
        return payload
    out = dict(payload)
    sr = out.get("SearchResult")
    if isinstance(sr, dict):
        sr = dict(sr)
        prev, nxt = sr.pop("previousPage", None), sr.pop("nextPage", None)
        sr["has_previous"] = prev is not None
        sr["has_next"] = nxt is not None
        res = sr.get("resources")
        if isinstance(res, list):
            sr["resources"] = [_drop_link(r) for r in res]
        out["SearchResult"] = sr
        return out
    # Single object: {"<ResourceType>": {..., "link": {...}}}
    return {k: _drop_link(v) for k, v in out.items()}


def _drop_link(obj: Any) -> Any:
    if isinstance(obj, dict) and isinstance(obj.get("link"), dict) and "href" in obj["link"]:
        return {k: v for k, v in obj.items() if k != "link"}
    return obj


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
