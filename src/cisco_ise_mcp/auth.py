"""
Pluggable agent<->server authentication (design-now, phase-implementation).

The server is **stdio-only today**: the OS process boundary IS the trust
boundary, so the default :class:`NullAuthenticator` authorizes every request and
there is no behavior change for existing local users.

This module exists so the network / multi-user story (Streamable HTTP + OAuth —
see ``docs/AUTH_DESIGN.md``) can plug into a stable seam without reworking the
core dispatch. Two authenticators ship now:

  * :class:`NullAuthenticator` — the stdio/local default (process boundary = gate).
  * :class:`AllowListAuthenticator` — a config-driven permit/deny list of client
    ids / bearer tokens, ready to enforce the moment a network transport exists.

Selection is via ``build_authenticator()``:
  * env ``CISCO_ISE_MCP_AUTH`` = ``null`` (default) | ``allowlist``
  * or an ``auth.json`` policy file in the config home (see ``AUTH_FILE``).

The policy file and any token material live in the per-user config home with the
same ``0o600`` hygiene as the deployment registry — tokens are treated as secrets
(never logged, compared with a constant-time check).
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Protocol, runtime_checkable

from cisco_ise_mcp.config import get_home

logger = logging.getLogger(__name__)

AUTH_FILE = "auth.json"
_ENV_MODE = "CISCO_ISE_MCP_AUTH"


@dataclass(frozen=True)
class Principal:
    """An authenticated caller. ``id`` is an opaque identity; ``source`` records
    which authenticator vouched for it (useful for audit/per-principal scoping)."""

    id: str
    source: str


@runtime_checkable
class Authenticator(Protocol):
    """Authenticate a request. Return a :class:`Principal` on success, else None.

    ``credentials`` is a transport-supplied mapping (e.g. a bearer token, client
    id, or validated OAuth claims). For stdio there are no credentials to check.
    """

    def authenticate(self, credentials: Mapping[str, object]) -> Optional[Principal]:
        ...


class NullAuthenticator:
    """Authorize every request — correct for stdio, where the OS process boundary
    is the trust boundary. This is the default so local users see no change."""

    def authenticate(self, credentials: Mapping[str, object]) -> Optional[Principal]:
        return Principal(id="local", source="stdio")


class AllowListAuthenticator:
    """Local permit/deny gate keyed on a client id or bearer token.

    Evaluation: an id/token on the ``deny`` list is always rejected; otherwise it
    must appear on the ``allow`` list. An empty ``allow`` list denies everyone
    (fail-closed) — configure at least one entry to permit access.
    """

    def __init__(self, allow: Optional[set] = None, deny: Optional[set] = None):
        self._allow = set(allow or ())
        self._deny = set(deny or ())

    def authenticate(self, credentials: Mapping[str, object]) -> Optional[Principal]:
        token = str(credentials.get("token") or credentials.get("client_id") or "")
        if not token:
            return None
        if self._matches(token, self._deny):
            return None
        if self._matches(token, self._allow):
            return Principal(id=token, source="allowlist")
        return None

    @staticmethod
    def _matches(token: str, entries: set) -> bool:
        # Constant-time compare so timing can't reveal how much of a token matched.
        return any(hmac.compare_digest(token, e) for e in entries)


def _policy_path() -> Path:
    return get_home() / AUTH_FILE


def _load_policy() -> dict:
    """Load the optional ``auth.json`` policy (never raises; missing -> {})."""
    path = _policy_path()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Ignoring unreadable auth policy %s: %s", path, exc)
        return {}


def build_authenticator() -> Authenticator:
    """Select the authenticator: env override > policy file > Null (default).

    Kept intentionally simple; the HTTP/OAuth phase adds an ``oauth`` mode here
    (validating IdP-issued claims) without touching call sites.
    """
    policy = _load_policy()
    mode = (os.environ.get(_ENV_MODE) or policy.get("mode") or "null").strip().lower()
    if mode == "allowlist":
        return AllowListAuthenticator(
            allow=set(policy.get("allow") or ()),
            deny=set(policy.get("deny") or ()),
        )
    return NullAuthenticator()


__all__ = [
    "Principal",
    "Authenticator",
    "NullAuthenticator",
    "AllowListAuthenticator",
    "build_authenticator",
    "AUTH_FILE",
]
