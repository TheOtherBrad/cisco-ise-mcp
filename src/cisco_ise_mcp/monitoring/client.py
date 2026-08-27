"""
Monitoring (MnT) HTTP client for Cisco ISE.

The Monitoring REST API ("MnT") is served under
    https://<host>:<port>/admin/API/mnt/...
with HTTP Basic auth (the same admin credentials as ERS / Open API) and returns
**XML**, not JSON. This client therefore returns the raw response body as text —
no JSON/XML parsing assumptions are made — wrapped with a little metadata.

Endpoint definitions live in the JSON catalog (``cisco_ise_mcp.catalog`` ->
``monitoring_endpoints.json``), generated from the Monitoring OpenAPI spec by
``scripts/refresh_catalog.py``.

NOTE on routing: the MnT API is the lowest-precedence surface (legacy). For
reporting / historical / aggregate queries, prefer the Data Connect tools
(``ise_dc_*``) — see ``ise_route`` / ``ise_capabilities``.
"""

from __future__ import annotations

from typing import Any, Optional

import httpx


class ISEMonitoringClient:
    """Async HTTP client for the Cisco ISE Monitoring (MnT) API. Returns raw XML."""

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
            headers={"Accept": "application/xml"},
            **kwargs,
        )

    async def close(self):
        await self._client.aclose()

    # Every MnT path lives under this prefix; the passthrough is confined to it so
    # a raw call (or a prompt-injected agent) cannot reach other authenticated
    # surfaces (/admin/..., /api/..., /ers/...) on the same host with these creds.
    _PATH_PREFIX = "admin/API/mnt/"

    async def request(self, method: str, path: str,
                      params: Optional[dict] = None) -> Any:
        """Issue a request and return the raw response body as text.

        The MnT API returns XML; we surface it verbatim so the agent can read it
        directly rather than risk a lossy XML->dict conversion.
        """
        clean = path.strip().lstrip("/")
        if ".." in clean.split("/"):
            raise ValueError(f"Path traversal ('..') is not allowed in MnT path: {path!r}")
        if not clean.startswith(self._PATH_PREFIX):
            raise ValueError(
                f"MnT passthrough paths must start with '/{self._PATH_PREFIX}' (got {path!r})."
            )
        url = f"{self.base_url}/{clean}"
        resp = await self._client.request(method.upper(), url, params=params or {})
        resp.raise_for_status()
        return {
            "status": "ok",
            "code": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "body": resp.text,
        }
