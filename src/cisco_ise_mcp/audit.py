"""
Daily audit log for every tool call made through this MCP server (D2, v1.1.0).

Location   ``<config home>/logs/YYYY-MM-DD.log`` — one file per LOCAL calendar day.
           The config home is OS-specific (see ``config.get_home``) or
           ``CISCO_ISE_MCP_HOME``.
Format     One line per event:
               ``<local ISO-8601 time with UTC offset> <JSON object>``
           e.g. ``2026-11-06T14:03:22.123-06:00 {"tool":"ise_ers_create",...}``.
           The JSON always contains ``tool`` (the function called), ``access``
           (read / write / destructive / registry / cli), ``status`` and
           ``deployment``; plus sanitized ``arguments`` and, when relevant,
           ``error`` and ``duration_ms``.
Secrets    Values of secret-like keys (password, secret, token, key, psk, ...)
           at ANY depth, and secret-looking ``key=value`` text, are replaced by
           ``*****``. Long strings are truncated.
Access     Directory ``0700``, files ``0600`` (re-asserted on every write; POSIX).
Retention  ``CISCO_ISE_MCP_LOG_RETENTION_DAYS`` (default 365, clamped 90..3650).
           Set it in the server ENVIRONMENT (MCP client ``env`` block or the
           config-home ``.env``) — deliberately NOT in deployments.json, which the
           agent can edit: the agent must not be able to shorten its own trail.
           Old files are deleted at startup and on the first write of each day;
           only files named exactly ``YYYY-MM-DD.log`` inside ``logs/`` are touched.

Audit failures are logged at WARNING and never break a tool call.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from cisco_ise_mcp.config import get_home

logger = logging.getLogger(__name__)

MASK = "*****"
RETENTION_ENV = "CISCO_ISE_MCP_LOG_RETENTION_DAYS"
RETENTION_DEFAULT = 365
RETENTION_MIN = 90
RETENTION_MAX = 3650
_MAX_STR = 2000          # longer strings are truncated
_MAX_ITEMS = 200         # list items / dict keys kept per container
_MAX_DEPTH = 8
_LOG_NAME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\.log$")

# Key names whose VALUES are secrets (case-insensitive, matched on the key with
# '-'/' ' normalised to '_'). Substring match, so 'ise_password', 'radiusSharedSecret',
# 'enablePassword', 'api_key', 'preSharedKey' are all covered.
_SECRET_KEY = re.compile(
    r"pass(word|wd|phrase)?|secret|token|api_?key|private_?key|psk|pre_?shared|"
    r"shared_?key|credential|auth_?key|key_?encryption|keywrap|enable_?pass|"
    r"cookie|authorization|session_?key|otp|pin$",
    re.IGNORECASE)
# Inline secrets inside free text, e.g. "password=abc", "secret: x", "Bearer abc".
_INLINE_SECRET = re.compile(
    r"(?i)\b(pass(?:word|wd|phrase)?|secret|token|api[_-]?key|psk|shared[_-]?secret)"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")

_lock = threading.Lock()
_purged_for: Optional[date] = None


# ---------------------------------------------------------------------------
# Sanitizer — secrets never reach the file.
# ---------------------------------------------------------------------------

def _is_secret_key(key: Any) -> bool:
    return bool(_SECRET_KEY.search(re.sub(r"[-\s]", "_", str(key))))


def _mask_text(text: str) -> str:
    text = _INLINE_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {MASK}", text)
    if len(text) > _MAX_STR:
        text = text[:_MAX_STR] + f"...<truncated {len(text) - _MAX_STR} chars>"
    return text


def sanitize(value: Any, _depth: int = 0) -> Any:
    """Deep copy of ``value`` with secrets masked and sizes bounded."""
    if _depth > _MAX_DEPTH:
        return "<nested too deep>"
    if isinstance(value, dict):
        out: dict = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= _MAX_ITEMS:
                out["<truncated>"] = f"{len(value) - _MAX_ITEMS} more keys"
                break
            out[str(k)] = MASK if _is_secret_key(k) and v not in (None, "") \
                else sanitize(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        items = [sanitize(v, _depth + 1) for v in list(value)[:_MAX_ITEMS]]
        if len(value) > _MAX_ITEMS:
            items.append(f"<{len(value) - _MAX_ITEMS} more items>")
        return items
    if isinstance(value, str):
        return _mask_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _mask_text(str(value))


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def logs_dir() -> Path:
    return get_home() / "logs"


def _now() -> datetime:
    """Local wall-clock time with the local UTC offset."""
    return datetime.now().astimezone()


def _secure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if not sys.platform.startswith("win"):
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def _write_line(now: datetime, entry: dict) -> None:
    directory = logs_dir()
    _secure_dir(directory)
    path = directory / f"{now:%Y-%m-%d}.log"
    line = f"{now.isoformat(timespec='milliseconds')} " \
           f"{json.dumps(entry, default=str, ensure_ascii=False, separators=(',', ':'))}\n"
    # O_APPEND keeps concurrent lines whole on POSIX; 0o600 applies on create and
    # is re-asserted below in case the file pre-existed with wider permissions.
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, 0o600)
    try:
        if not sys.platform.startswith("win"):
            os.fchmod(fd, 0o600)
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

def retention_days() -> int:
    """Configured retention, clamped to RETENTION_MIN..RETENTION_MAX."""
    raw = os.environ.get(RETENTION_ENV, "").strip()
    try:
        days = int(raw) if raw else RETENTION_DEFAULT
    except ValueError:
        logger.warning("%s=%r is not a whole number; using %s days.",
                       RETENTION_ENV, raw, RETENTION_DEFAULT)
        days = RETENTION_DEFAULT
    clamped = max(RETENTION_MIN, min(RETENTION_MAX, days))
    if clamped != days:
        logger.warning("%s=%s is outside %s..%s; using %s days.",
                       RETENTION_ENV, days, RETENTION_MIN, RETENTION_MAX, clamped)
    return clamped


def purge_old_logs(today: Optional[date] = None) -> list[str]:
    """Delete daily logs older than the retention window. Returns deleted names.

    Keeps today plus the previous ``retention_days() - 1`` days. Only regular
    files named exactly YYYY-MM-DD.log directly inside logs/ are considered;
    symlinks and anything else are left alone.
    """
    today = today or _now().date()
    cutoff = today - timedelta(days=retention_days() - 1)
    deleted: list[str] = []
    directory = logs_dir()
    if not directory.is_dir():
        return deleted
    for entry in directory.iterdir():
        m = _LOG_NAME.match(entry.name)
        if not m or entry.is_symlink() or not entry.is_file():
            continue
        try:
            day = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            continue
        if day < cutoff:
            try:
                entry.unlink()
                deleted.append(entry.name)
            except OSError as exc:
                logger.warning("Could not delete old audit log %s: %s", entry.name, exc)
    return deleted


def _maybe_purge(today: date) -> None:
    global _purged_for
    if _purged_for == today:
        return
    _purged_for = today
    removed = purge_old_logs(today)
    if removed:
        _emit(_now(), {"tool": "audit_retention", "access": "system", "status": "ok",
                       "deleted": removed, "retention_days": retention_days()})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _emit(now: datetime, entry: dict) -> None:
    _write_line(now, entry)


def write(entry: dict) -> None:
    """Append one sanitized event to today's log. Never raises."""
    try:
        now = _now()
        with _lock:
            _maybe_purge(now.date())
            _emit(now, sanitize(entry))
    except Exception as exc:  # noqa: BLE001 — auditing must never break the call
        logger.warning("Failed to write audit entry for %s: %s", entry.get("tool"), exc)


def record(action: str, arguments: dict, *, deployment: Optional[str] = None,
           status: str = "ok", error: Optional[str] = None,
           access: Optional[str] = None, duration_ms: Optional[int] = None) -> None:
    """Record one tool call (or CLI action). Never raises."""
    entry: dict[str, Any] = {"tool": action, "access": access, "status": status,
                             "deployment": deployment, "arguments": arguments or {}}
    if duration_ms is not None:
        entry["duration_ms"] = duration_ms
    if error:
        entry["error"] = error
    write({k: v for k, v in entry.items() if v is not None})


def record_dc_query(view: str, *, deployment: Optional[str] = None,
                    days_back: Optional[int] = None, days_back_source: str = "",
                    rows: Optional[int] = None, duration_ms: Optional[int] = None,
                    row_limit: Optional[int] = None, outcome: str = "ok") -> None:
    """Record Data Connect query shape (load visibility). Never raises."""
    write({"tool": "dc_query", "access": "read", "status": outcome, "view": view,
           "deployment": deployment, "days_back": days_back,
           "days_back_source": days_back_source or None, "row_limit": row_limit,
           "rows": rows, "duration_ms": duration_ms})


def startup() -> None:
    """Called once when the server starts: create logs/, apply retention."""
    try:
        now = _now()
        with _lock:
            _secure_dir(logs_dir())
            _maybe_purge(now.date())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Audit log startup failed: %s", exc)
