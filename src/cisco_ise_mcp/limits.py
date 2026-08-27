"""
Shared resource governance for every Cisco ISE API surface.

Cisco documents two hard ceilings — **ERS: 100 concurrent connections** and
**Open API: 150** — and publishes *no* limits for Data Connect. Those documented
budgets are deployment-wide (shared with pxGrid, the admin GUI and any other
integration), so this server deliberately claims only a small slice of them.

Data Connect is the real risk: the ISE ``dataconnect`` Oracle account is
read-only with no DBA rights, so server-side Oracle governance (``ALTER PROFILE
SESSIONS_PER_USER``, Resource Manager plans) is unavailable. Every control must
therefore live here, client-side.

Four layers, because each stops something the others do not:

  1. **Connection pool cap** — bounds concurrent Oracle *sessions* (see
     ``dataconnect.client``); also removes the connect/disconnect storm.
  2. **Concurrency semaphore + short queue wait** — bounds simultaneous
     in-flight queries.
  3. **Query timeout** (``call_timeout``) — the only control that genuinely
     *cancels server-side work* on the MnT node.
  4. **Token bucket** — bounds the *sustained* rate. A pool alone never catches
     a runaway agent issuing N fast queries at a time forever.

Configuration precedence: environment variables are **hard ceilings**;
per-deployment registry values may only *tighten* them (``min(ceiling, value)``).
An agent can write non-secret registry fields via ``ise_update_deployment``, so
this ordering stops it raising its own budget.

Queue wait and query timeout are separate clocks and they compound
(``agent latency = wait + execution``). The wait is deliberately short: a slot is
held by a *long* query, so waiting longer rarely helps, and a slow refusal would
land outside a typical MCP client timeout — the agent would see its own opaque
timeout instead of the actionable "narrow your query" message.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Hard ceiling on how long a caller may queue for a slot, regardless of config.
_MAX_ACQUIRE_WAIT_S = 15.0

SURFACES = ("dataconnect", "ers", "openapi", "monitoring")

# Built-in defaults per surface. ERS/Open API sit at roughly 10% of Cisco's
# documented 100/150, leaving the rest of the deployment-wide budget for the GUI,
# pxGrid and other integrations.
_DEFAULTS: dict[str, dict[str, Any]] = {
    "dataconnect": {
        "max_concurrent": 5,
        "acquire_wait_s": 5.0,
        "query_timeout_s": 60,
        "max_per_minute": 30,
        "default_days_back": 7,
        "max_days_back": 90,
        "default_row_limit": 500,
        "default_agg_row_limit": 5000,
        "max_fact_views": 3,
    },
    "ers": {"max_concurrent": 10, "acquire_wait_s": 5.0, "max_per_minute": 0},
    "openapi": {"max_concurrent": 15, "acquire_wait_s": 5.0, "max_per_minute": 0},
    "monitoring": {"max_concurrent": 5, "acquire_wait_s": 5.0, "max_per_minute": 0},
}

# Environment variable per (surface, field). Absent -> the built-in default.
_ENV_VARS: dict[str, dict[str, str]] = {
    "dataconnect": {
        "max_concurrent": "CISCO_ISE_MCP_DC_MAX_CONCURRENT",
        "acquire_wait_s": "CISCO_ISE_MCP_DC_ACQUIRE_WAIT_S",
        "query_timeout_s": "CISCO_ISE_MCP_DC_QUERY_TIMEOUT_S",
        "max_per_minute": "CISCO_ISE_MCP_DC_QPM",
        "default_days_back": "CISCO_ISE_MCP_DC_DEFAULT_DAYS_BACK",
        "max_days_back": "CISCO_ISE_MCP_DC_MAX_DAYS_BACK",
        "default_row_limit": "CISCO_ISE_MCP_DC_DEFAULT_ROW_LIMIT",
        "default_agg_row_limit": "CISCO_ISE_MCP_DC_DEFAULT_AGG_ROW_LIMIT",
        "max_fact_views": "CISCO_ISE_MCP_DC_MAX_FACT_VIEWS",
    },
    "ers": {"max_concurrent": "CISCO_ISE_MCP_ERS_MAX_CONCURRENT"},
    "openapi": {"max_concurrent": "CISCO_ISE_MCP_OPENAPI_MAX_CONCURRENT"},
    "monitoring": {"max_concurrent": "CISCO_ISE_MCP_MNT_MAX_CONCURRENT"},
}


class LimitExceeded(Exception):
    """A resource limit refused the call.

    Carries a structured payload so the agent receives actionable guidance
    ("narrow the query") rather than a stack trace. ``server.call_tool``
    renders ``payload`` directly.
    """

    def __init__(self, payload: dict):
        self.payload = payload
        super().__init__(payload.get("reason", "limit exceeded"))


def _env_num(name: str, default: float, *, minimum: float = 0.0) -> float:
    """Read a numeric env override. Unparseable/negative values fall back."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("Ignoring %s=%r: not a number; using %s.", name, raw, default)
        return default
    if value < minimum:
        logger.warning("Ignoring %s=%r: below minimum %s; using %s.", name, raw, minimum, default)
        return default
    return value


@dataclass(frozen=True)
class LimitPolicy:
    """Effective limits for one (deployment, surface) pair."""

    surface: str
    slug: str
    max_concurrent: int
    acquire_wait_s: float
    query_timeout_s: int = 0
    max_per_minute: int = 0
    default_days_back: int = 0
    max_days_back: int = 0
    default_row_limit: int = 0
    default_agg_row_limit: int = 0
    max_fact_views: int = 0
    clamped: tuple = ()          # fields where the registry value hit the env ceiling
    from_registry: tuple = ()    # fields the registry actually set

    def as_dict(self) -> dict:
        return {
            "surface": self.surface,
            "max_concurrent": self.max_concurrent,
            "acquire_wait_s": self.acquire_wait_s,
            "query_timeout_s": self.query_timeout_s,
            "max_per_minute": self.max_per_minute,
            "default_days_back": self.default_days_back,
            "max_days_back": self.max_days_back,
            "default_row_limit": self.default_row_limit,
            "default_agg_row_limit": self.default_agg_row_limit,
            "max_fact_views": self.max_fact_views,
            "clamped_by_env_ceiling": list(self.clamped),
            "set_in_registry": list(self.from_registry),
        }


def resolve_policy(surface: str, slug: str = "", registry: Optional[dict] = None) -> LimitPolicy:
    """Resolve effective limits: env ceiling, tightened (never raised) by the registry."""
    if surface not in _DEFAULTS:
        raise ValueError(f"Unknown surface: {surface!r}")
    base = _DEFAULTS[surface]
    env_map = _ENV_VARS.get(surface, {})
    reg = registry or {}

    values: dict[str, Any] = {}
    clamped: list[str] = []
    from_registry: list[str] = []

    for field_name, default in base.items():
        is_float = isinstance(default, float)
        # 1. Env ceiling (or built-in default).
        env_name = env_map.get(field_name)
        ceiling = _env_num(env_name, float(default)) if env_name else float(default)

        # 2. Registry may only tighten.
        effective = ceiling
        if field_name in reg and reg[field_name] is not None:
            try:
                requested = float(reg[field_name])
            except (TypeError, ValueError):
                logger.warning(
                    "Deployment %r: limits.%s=%r is not a number; ignoring.",
                    slug, field_name, reg[field_name])
                requested = ceiling
            else:
                from_registry.append(field_name)
                if requested > ceiling:
                    clamped.append(field_name)
                effective = min(requested, ceiling)

        values[field_name] = effective if is_float else int(effective)

    # Queueing longer than this converts a fast, actionable refusal into a slow one.
    values["acquire_wait_s"] = min(float(values.get("acquire_wait_s", 5.0)), _MAX_ACQUIRE_WAIT_S)
    # A zero/negative concurrency cap would deadlock every call; keep at least one slot.
    values["max_concurrent"] = max(1, int(values.get("max_concurrent", 1)))

    return LimitPolicy(surface=surface, slug=slug, clamped=tuple(clamped),
                       from_registry=tuple(from_registry), **values)


class _TokenBucket:
    """Sustained-rate limiter. ``per_minute <= 0`` disables it."""

    def __init__(self, per_minute: int):
        self.capacity = float(max(per_minute, 0))
        self.tokens = self.capacity
        self.rate = self.capacity / 60.0
        self.updated = time.monotonic()

    def take(self) -> bool:
        if self.capacity <= 0:
            return True
        now = time.monotonic()
        # Refill for elapsed time, never above capacity. No await here, so this
        # stays atomic on the single-threaded event loop.
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def available(self) -> int:
        if self.capacity <= 0:
            return -1
        now = time.monotonic()
        return int(min(self.capacity, self.tokens + (now - self.updated) * self.rate))


class SurfaceLimiter:
    """Concurrency + sustained-rate gate for one (deployment, surface)."""

    def __init__(self, policy: LimitPolicy):
        self.policy = policy
        self._sem = asyncio.Semaphore(policy.max_concurrent)
        self._bucket = _TokenBucket(policy.max_per_minute)
        self.in_flight = 0
        self.refusals = 0

    def _refuse(self, code: str, reason: str, **extra) -> LimitExceeded:
        self.refusals += 1
        payload = {
            "error": code,
            "surface": self.policy.surface,
            "deployment": self.policy.slug or None,
            "reason": reason,
            "limits": {
                "max_concurrent": self.policy.max_concurrent,
                "max_per_minute": self.policy.max_per_minute,
                "queue_wait_seconds": self.policy.acquire_wait_s,
            },
            "in_flight": self.in_flight,
        }
        payload.update(extra)
        return LimitExceeded(payload)

    @asynccontextmanager
    async def slot(self):
        """Hold a slot for the duration of one call, or refuse with guidance."""
        if not self._bucket.take():
            raise self._refuse(
                "rate_limited",
                (f"This deployment is limited to {self.policy.max_per_minute} "
                 f"{self.policy.surface} calls per minute to protect the ISE node, and that "
                 f"rate is currently exhausted. Wait a few seconds, then retry — or reduce the "
                 f"number of calls by aggregating in SQL (GROUP BY) instead of querying in a loop."),
                remediation="Aggregate in SQL, widen filters, or retry shortly.",
            )
        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=self.policy.acquire_wait_s)
        except (asyncio.TimeoutError, TimeoutError):
            raise self._refuse(
                "concurrency_limited",
                (f"All {self.policy.max_concurrent} concurrent {self.policy.surface} slots for "
                 f"this deployment are busy and none freed within "
                 f"{self.policy.acquire_wait_s:g}s. Slots are usually held by long-running "
                 f"queries, so retrying immediately will not help."),
                remediation=("Run fewer calls at once; narrow each query with days_back, a "
                             "filter, or an aggregate so it finishes faster."),
            ) from None
        self.in_flight += 1
        try:
            yield self.policy
        finally:
            self.in_flight -= 1
            self._sem.release()

    def snapshot(self) -> dict:
        out = self.policy.as_dict()
        out.update({
            "in_flight": self.in_flight,
            "refusals": self.refusals,
            "rate_tokens_available": self._bucket.available(),
        })
        return out


# Process-wide limiters keyed by (slug, surface). ``asyncio.Semaphore`` binds to
# the running loop, so the creating loop is tracked and the limiter rebuilt if a
# different loop appears (repeated ``asyncio.run`` in tests, or a restarted host).
_LIMITERS: dict[tuple, tuple] = {}


def get_limiter(slug: str, surface: str, registry: Optional[dict] = None) -> SurfaceLimiter:
    """Return the limiter for a (deployment, surface), creating it on first use."""
    key = (slug or "", surface)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    cached = _LIMITERS.get(key)
    if cached is not None and cached[0] is loop:
        return cached[1]
    limiter = SurfaceLimiter(resolve_policy(surface, slug, registry))
    _LIMITERS[key] = (loop, limiter)
    return limiter


def snapshot_all() -> list[dict]:
    """Live view of every limiter created so far (drives ise_limits_status)."""
    out = []
    for (slug, surface), (_loop, limiter) in sorted(_LIMITERS.items()):
        entry = limiter.snapshot()
        entry["deployment"] = slug or None
        out.append(entry)
    return out


def reset_for_tests() -> None:
    """Drop all cached limiters (test helper; not used at runtime)."""
    _LIMITERS.clear()


__all__ = [
    "LimitExceeded", "LimitPolicy", "SurfaceLimiter",
    "resolve_policy", "get_limiter", "snapshot_all", "reset_for_tests", "SURFACES",
]
