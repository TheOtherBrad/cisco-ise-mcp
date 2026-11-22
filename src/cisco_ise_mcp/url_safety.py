"""Shared URL-path safety checks for the raw REST passthrough tools.

``ise_ers_request``, ``ise_openapi_request`` and ``ise_mnt_request`` take an
agent-supplied path. Each surface confines it to its own prefix, but a prefix
check on the raw string is not enough: percent-encoded dot-segments or slashes
(``%2e%2e``, ``%2f``), backslashes, or an embedded ``?``/``#`` can change which
resource the request finally addresses. Query parameters belong in ``params``.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

# Encoded '.', '/', '\', '%' (double-encoding) — rejected case-insensitively.
_ENCODED = re.compile(r"%(?:2e|2f|5c|25)", re.IGNORECASE)
_FORBIDDEN_CHARS = set("\\?#;")


def check_passthrough_path(path: str, prefix: str, surface: str) -> str:
    """Return the cleaned relative path (no leading '/') or raise ValueError.

    ``prefix`` is the required leading segment(s), e.g. ``"ers/"``.
    """
    raw = str(path or "")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw):
        raise ValueError(f"Control characters are not allowed in {surface} path.")
    clean = raw.strip().lstrip("/")
    bad = sorted(_FORBIDDEN_CHARS.intersection(clean))
    if bad:
        raise ValueError(
            f"Characters {''.join(bad)!r} are not allowed in {surface} path {path!r}; "
            "pass query parameters via 'params'.")
    if _ENCODED.search(clean):
        raise ValueError(
            f"Percent-encoded '.', '/', '\\' or '%' are not allowed in {surface} path {path!r}.")
    segments = unquote(clean).split("/")
    if ".." in segments or "." in segments:
        raise ValueError(f"Path traversal ('..' / '.') is not allowed in {surface} path: {path!r}")
    # Empty segments ('//', trailing '/' excepted) are normalised away by the ISE
    # web tier, so they could hide a path from the destructive classifier.
    if "" in segments[:-1]:
        raise ValueError(f"Empty path segments ('//') are not allowed in {surface} path: {path!r}")
    if not clean.startswith(prefix):
        raise ValueError(f"{surface} passthrough paths must start with '/{prefix}' (got {path!r}).")
    return clean
