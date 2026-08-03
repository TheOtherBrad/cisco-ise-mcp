"""
Append-only audit log for state-changing actions.

Every mutating tool call (deployment-registry edits, ERS/Open API writes, MnT
session deletes) is recorded as one JSON line in ``<config-home>/audit.log``.
This is a local security trail of *what the agent changed* — it never records
secrets (passwords, cert contents) and never records read-only calls.

The file is append-only and ``0o600`` on POSIX. Audit failures are swallowed
(logged at WARNING) so they can never block or break an operation.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cisco_ise_mcp.config import get_home

logger = logging.getLogger(__name__)

# Argument keys that must never be written to the log, even though secrets are
# not supposed to reach these tools in the first place (defense in depth).
_REDACT_KEYS = {
    "password", "ise_password", "dataconnect_password", "secret", "data",
}


def _audit_path() -> Path:
    return get_home() / "audit.log"


def _sanitize(arguments: dict) -> dict:
    """Copy arguments for logging, redacting secret-ish keys and large bodies."""
    out: dict[str, Any] = {}
    for k, v in (arguments or {}).items():
        if k in _REDACT_KEYS:
            out[k] = "<redacted>"
        elif isinstance(v, (dict, list)) and len(str(v)) > 500:
            out[k] = f"<{type(v).__name__}, {len(v)} items>"
        else:
            out[k] = v
    return out


def record(action: str, arguments: dict, *, deployment: Optional[str] = None,
           status: str = "ok", error: Optional[str] = None) -> None:
    """Append one audit entry. Never raises."""
    try:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "deployment": deployment,
            "status": status,
            "arguments": _sanitize(arguments),
        }
        if error:
            entry["error"] = error
        path = _audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        if not sys.platform.startswith("win"):
            try:
                os.chmod(path.parent, 0o700)
            except OSError:
                pass
        # O_APPEND makes concurrent writes atomic per line on POSIX.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (json.dumps(entry, default=str) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except Exception as exc:  # noqa: BLE001 — auditing must never break the call
        logger.warning("Failed to write audit entry for %s: %s", action, exc)
