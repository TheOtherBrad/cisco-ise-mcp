"""
Request routing for the Cisco ISE MCP server.

Encodes the surface PRECEDENCE the agent should follow. When more than one
surface can serve a request, use the highest-ranked one; fall back to the next
only if the higher surface can't serve the task or errors:

    1. Open API     (ise_openapi_*) — system/policy/cert/backup/patch/license/deployment + state
    2. ERS          (ise_ers_*)     — configuration object CRUD & current state
    3. Data Connect (ise_dc_*)      — reporting/historical/aggregate/audit only it exposes
    4. Monitor API  (ise_mnt_*)     — legacy live session / CoA / failure-reason lookups

Precedence is a TIEBREAKER among *capable* surfaces: reporting data that only
the monitoring DB holds still routes to Data Connect, because no higher surface
can serve it. It never tells the agent to attempt a surface that lacks the
capability.

Surfaced to the agent via the ``ise_route`` and ``ise_capabilities`` tools, and
reinforced in individual tool descriptions. ``recommend()`` is heuristic
guidance (the actual dispatch is still by tool name) — it points the agent at
the right surface and concrete tools.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from cisco_ise_mcp import catalog

# Surface precedence: when more than one surface can serve a task, prefer the
# highest-ranked (index 0). Advisory only — dispatch is still by tool name.
SURFACE_PRECEDENCE = ("openapi", "ers", "data_connect", "monitoring")


def precedence_rank(surface: str) -> int:
    """1-based rank of a surface in ``SURFACE_PRECEDENCE`` (unknown → last)."""
    try:
        return SURFACE_PRECEDENCE.index(surface) + 1
    except ValueError:
        return len(SURFACE_PRECEDENCE) + 1


def _ordered(*surfaces: str) -> list[str]:
    """De-duplicate the given surfaces and sort them by global precedence."""
    uniq = list(dict.fromkeys(s for s in surfaces if s))
    return sorted(uniq, key=precedence_rank)


ROUTING_RULE = (
    "Surfaces are ranked by precedence: (1) Open API (ise_openapi_*), (2) ERS "
    "(ise_ers_*), (3) Data Connect (ise_dc_*), (4) Monitor API / MnT (ise_mnt_*). "
    "When more than one surface can serve a request, use the highest-ranked one; "
    "fall back to the next only if the higher surface is unavailable, unsupported "
    "on this ISE version, disabled for the deployment, or errors. In practice: "
    "current configuration & state (network devices, endpoints, users, identity/"
    "endpoint groups, SGT/SGACL, nodes, policy sets, certificates, deployment "
    "lifecycle) → Open API or ERS; reporting / historical / aggregate / audit data "
    "that only the monitoring database exposes (RADIUS/TACACS authentication & "
    "accounting, posture, profiling, threat, guest, AUP, failures) → Data Connect; "
    "live session / CoA / failure-reason lookups with no higher equivalent → "
    "Monitor API (MnT, legacy XML). Data Connect outranks MnT, so prefer Data "
    "Connect for any reporting it can serve."
)

# Reporting-intent signals.
_REPORTING_HINTS = (
    "report", "history", "historical", "audit", "how many", "count", "number of",
    "statistic", "stats", "summary", "trend", "over time", "last ", "past ",
    "today", "yesterday", "this week", "this month", "failed", "failure",
    "succeed", "success", "who ", "when ", "top ", "most ", "logged in", "log in",
    "login", "logins", "session", "accounting", "authenticat", "posture",
    "profiled", "profiling", "logs",
)

# Strong historical/aggregate signals. Even for an object a higher surface can
# read live (see ``_OVERLAP_CONFIG``), these push the request to Data Connect —
# the config surfaces don't hold history/aggregates.
_AGGREGATE_HINTS = (
    "how many", "count", "number of", "history", "historical", "over time",
    "trend", "last ", "past ", "failed", "failure", "summary", "today",
    "yesterday", "this week", "this month", "logged in", "log in", "login",
    "logins", "when ", "top ", "most ", "statistic", "stats",
)

# Configuration write verbs.
_WRITE_VERBS = (
    "create", "add ", "new ", "update", "modify", "change", "edit", "delete",
    "remove", "configure", "enable", "disable", "register", "deregister",
    "provision", "rename", "assign", "set ",
)

# Reporting keyword → candidate Data Connect view keys.
_INTENT_VIEW_MAP: dict[str, list[str]] = {
    "radius": ["radius_authentications", "radius_accounting", "radius_authentication_summary", "radius_errors_view"],
    "authentication": ["radius_authentications", "radius_authentication_summary", "tacacs_authentication"],
    "accounting": ["radius_accounting", "tacacs_accounting"],
    "tacacs": ["tacacs_authentication", "tacacs_authorization", "tacacs_accounting", "tacacs_command_accounting"],
    "device admin": ["tacacs_authentication", "tacacs_authorization", "tacacs_command_accounting"],
    "session": ["radius_accounting", "radius_authentications"],
    "endpoint": ["endpoints_data", "registered_endpoints", "profiled_endpoints_summary"],
    "profil": ["profiled_endpoints_summary", "profiling_policies", "endpoints_data"],
    "posture": ["posture_assessment_by_endpoint", "posture_assessment_by_condition"],
    "admin login": ["administrator_logins"],
    "administrator": ["administrator_logins", "admin_users"],
    "login": ["administrator_logins", "sponsor_login_and_audit"],
    "config change": ["change_configuration_audit"],
    "audit": ["change_configuration_audit", "administrator_logins", "openapi_operations"],
    "guest": ["guest_accounting", "primary_guest", "sponsor_login_and_audit"],
    "sponsor": ["sponsor_login_and_audit"],
    "network device": ["network_devices", "network_device_groups"],
    "security group": ["security_groups", "security_group_acls"],
    "sgt": ["security_groups"],
    "sgacl": ["security_group_acls"],
    "threat": ["threat_events", "coa_events"],
    "coa": ["coa_events"],
    "change of authorization": ["coa_events"],
    "system health": ["system_summary", "key_performance_metrics"],
    "performance": ["key_performance_metrics", "system_summary"],
    "node": ["node_list", "system_summary"],
    "failure": ["radius_errors_view", "failure_code_cause"],
    "error": ["radius_errors_view"],
    "vulnerab": ["vulnerability_assessment_failures"],
    "aup": ["aup_acceptance_status"],
    "password change": ["user_password_changes"],
}

# Config noun → Open API category (else ERS).
_OPENAPI_NOUNS: dict[str, str] = {
    "policy set": "Policy", "authorization rule": "Policy", "authentication rule": "Policy",
    "policy": "Policy", "certificate": "Certificates", "csr": "Certificates",
    "trusted cert": "Certificates", "backup": "Backup & Restore", "restore": "Backup & Restore",
    "repository": "Repository", "patch": "Patch", "hot patch": "Patch",
    "deployment": "Deployment", "node group": "Deployment", "license": "Licensing",
}

# Config/state nouns a HIGHER surface can read live. Precedence says use Open API /
# ERS over a Data Connect view for a *current-state* read, unless the ask is clearly
# historical/aggregate (see ``_AGGREGATE_HINTS``). Value: (surface, [concrete tools]).
# Insertion order matters — most specific keys first (e.g. "endpoint group" before
# "endpoint") so ``_overlap_surface`` returns the tightest match.
_OVERLAP_CONFIG: dict[str, tuple[str, list[str]]] = {
    "policy set": ("openapi", ["ise_openapi_radius_policy_set_list", "ise_openapi_tacacs_policy_set_list"]),
    "node": ("openapi", ["ise_openapi_deployment_node_list"]),
    "network device": ("ers", ["ise_ers_resources", "ise_ers_list_networkdevice"]),
    "endpoint group": ("ers", ["ise_ers_list_endpointgroup"]),
    "identity group": ("ers", ["ise_ers_list_identitygroup"]),
    "endpoint": ("ers", ["ise_ers_list_endpoint", "ise_ers_search_endpoint"]),
    "internal user": ("ers", ["ise_ers_list_internaluser"]),
    "admin user": ("ers", ["ise_ers_list_adminuser"]),
    "security group": ("ers", ["ise_ers_list_sgt", "ise_ers_list_sgacl"]),
    "sgacl": ("ers", ["ise_ers_list_sgacl"]),
    "sgt": ("ers", ["ise_ers_list_sgt"]),
}


def _dc_views_for(q: str) -> list[str]:
    seen: list[str] = []
    available = catalog.get_dc_views()
    for kw, views in _INTENT_VIEW_MAP.items():
        if kw in q:
            for v in views:
                if v in available and v not in seen:
                    seen.append(v)
    return seen


def _overlap_surface(q: str) -> tuple[str, list[str]] | None:
    """First matching config/state overlap (higher surface + tools), or None."""
    for kw, val in _OVERLAP_CONFIG.items():
        if kw in q:
            return val
    return None


def recommend(query: str) -> dict:
    """Heuristically recommend an API surface + concrete tools for a request.

    Advisory only — dispatch is still by tool name. Applies ``SURFACE_PRECEDENCE``
    (Open API > ERS > Data Connect > Monitor API) as a tiebreaker among surfaces
    that can actually serve the request. Every result carries ``surface_precedence``
    (the global order) and ``fallback_order`` (capable surfaces for THIS query).
    """
    q = (query or "").lower()
    matched_views = _dc_views_for(q)
    is_write = any(v in q for v in _WRITE_VERBS)
    is_aggregate = any(h in q for h in _AGGREGATE_HINTS)
    is_reporting = bool(matched_views) or any(h in q for h in _REPORTING_HINTS)

    base = {"query": query, "rule": ROUTING_RULE, "surface_precedence": list(SURFACE_PRECEDENCE)}

    # 1. Configuration write / lifecycle → Open API (by noun) else ERS. Already
    #    precedence-correct (Open API rank 1 > ERS rank 2); Data Connect is read-only.
    if is_write:
        category = next((cat for noun, cat in _OPENAPI_NOUNS.items() if noun in q), None)
        if category:
            return {**base, "primary_surface": "openapi", "openapi_category": category,
                    "fallback_order": ["openapi"],
                    "suggested_tools": ["ise_capabilities", "ise_openapi_request"],
                    "notes": f"{category} lifecycle is managed via the Open API surface (ise_openapi_*), "
                             "the highest-precedence surface for this task."}
        return {**base, "primary_surface": "ers", "fallback_order": ["ers"],
                "suggested_tools": ["ise_ers_resources", "ise_ers_create", "ise_ers_update", "ise_ers_patch"],
                "notes": "Configuration object CRUD → ERS (ise_ers_*). Use ise_ers_resources to find the resource."}

    # 2. Current config/state READ that a higher surface exposes → precedence beats a
    #    Data Connect view, UNLESS the ask is clearly historical/aggregate (DC-only data).
    overlap = _overlap_surface(q)
    if overlap and not is_aggregate:
        surface, tools = overlap
        fallback = _ordered(surface, "data_connect") if matched_views else _ordered(surface)
        return {**base, "primary_surface": surface, "fallback_order": fallback,
                "matched_views": matched_views, "suggested_tools": tools[:6],
                "notes": f"Current configuration/state read → {surface} (higher precedence than a Data "
                         "Connect view). Fall back to Data Connect only if the higher surface can't serve "
                         "it, or when you need historical/aggregate data."}

    # 3. Reporting / historical / aggregate read → Data Connect (sole capable surface).
    if is_reporting:
        tools = [f"ise_dc_view_{v}" for v in matched_views] or ["ise_dc_list_views", "ise_dc_view"]
        fallback = _ordered("data_connect", "monitoring") if "session" in q else ["data_connect"]
        return {**base, "primary_surface": "data_connect", "matched_views": matched_views,
                "fallback_order": fallback, "suggested_tools": tools[:6],
                "notes": "Reporting/historical/aggregate request → Data Connect (no higher surface exposes "
                         "this data). If a needed view is missing, fall back to ERS/Open API."}

    # 4. Ambiguous → discovery entrypoints, walk the full precedence order.
    return {**base, "primary_surface": "unknown", "matched_views": matched_views,
            "fallback_order": list(SURFACE_PRECEDENCE),
            "suggested_tools": ["ise_capabilities", "ise_openapi_request", "ise_ers_resources", "ise_dc_list_views"],
            "notes": "Could not classify with confidence. Work down the precedence order: Open API, then "
                     "ERS, then Data Connect for reports, then Monitor API (MnT)."}


def capabilities() -> dict:
    """Summarize the surfaces (in precedence order), the routing rule, and provenance."""
    meta = catalog.get_meta()
    return {
        "routing_rule": ROUTING_RULE,
        "surface_precedence": list(SURFACE_PRECEDENCE),
        "surfaces": {
            "openapi": {
                "tool_prefix": "ise_openapi_",
                "precedence_rank": precedence_rank("openapi"),
                "use_for": "Highest precedence. System/lifecycle + current state: policy sets "
                           "(network-access/device-admin), certificates, backup/restore, repositories, "
                           "patches, licensing, deployment/nodes.",
                "transport": "HTTPS /api/ (Basic auth), port 443 gateway or 9070",
                "passthrough": "ise_openapi_request for any uncurated /api/ path",
                "start_with": ["ise_openapi_request"],
            },
            "ers": {
                "tool_prefix": "ise_ers_",
                "precedence_rank": precedence_rank("ers"),
                "use_for": "Configuration object CRUD & current state: endpoints, NADs, users, identity/"
                           "endpoint groups, SGT/SGACL, portals, guests, etc. Use when Open API has no "
                           "endpoint for the object.",
                "transport": "HTTPS /ers/config (Basic auth), port 443/9060",
                "start_with": ["ise_ers_resources", "ise_ers_list", "ise_ers_search"],
            },
            "data_connect": {
                "tool_prefix": "ise_dc_",
                "precedence_rank": precedence_rank("data_connect"),
                "use_for": "Reporting / historical / aggregate / audit data that no higher surface exposes: "
                           "authentication & accounting history, posture, profiling, sessions, config-change "
                           "audit. Outranks Monitor API for any reporting it can serve.",
                "transport": "Oracle TCPS (read-only SQL), port 2484",
                "start_with": ["ise_dc_list_views", "ise_dc_view", "ise_dc_query"],
            },
            "monitoring": {
                "tool_prefix": "ise_mnt_",
                "precedence_rank": precedence_rank("monitoring"),
                "use_for": "Lowest precedence (legacy XML). Live session count/list, session by MAC/IP/"
                           "username, CoA reauth/disconnect, failure reasons. Use only when no higher "
                           "surface (especially Data Connect) exposes the data.",
                "transport": "HTTPS /admin/API/mnt (Basic auth, admin creds), returns XML",
                "passthrough": "ise_mnt_request for any uncurated /admin/API/mnt path",
                "legacy": True,
                "start_with": ["ise_mnt_active_session_count", "ise_mnt_request"],
            },
        },
        "catalog": {
            "ise_version": meta.get("ise_version"),
            "generated_utc": meta.get("generated_utc"),
            "counts": meta.get("counts"),
            "sources": meta.get("sources"),
        },
    }


def catalog_diff(only: str = "dc") -> dict:
    """
    Compare the cached catalogs against freshly-built ones (e.g. re-scrape Cisco
    DevNet for Data Connect) and report added/removed/changed entries WITHOUT
    writing. Read-only "check the cache vs DevNet" capability.
    """
    script = Path(__file__).resolve().parents[2] / "scripts" / "refresh_catalog.py"
    if not script.is_file():
        return {"error": f"refresh_catalog.py not found at {script}"}
    spec = importlib.util.spec_from_file_location("_refresh_catalog", script)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception as exc:  # noqa: BLE001
        return {"error": f"could not load refresh_catalog.py: {exc}"}

    want = {s.strip() for s in only.split(",") if s.strip()}
    fetch_dc = "dc" in want
    try:
        built = mod.build_all(fetch_dc=fetch_dc, want=want)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"build failed (network for DevNet scrape?): {exc}"}

    files = {
        "ers": "ers_resources.json",
        "dc": "dataconnect_views.json",
        "openapi": "openapi_endpoints.json",
        "monitoring": "monitoring_endpoints.json",
    }
    import json as _json
    out: dict = {"checked": sorted(want), "changes": {}}
    cat_dir = Path(__file__).resolve().parent / "catalog"
    for key in ("ers", "dc", "openapi", "monitoring"):
        if key not in want or key not in built:
            continue
        path = cat_dir / files[key]
        empty = [] if key in ("openapi", "monitoring") else {}
        old = _json.loads(path.read_text(encoding="utf-8")) if path.exists() else empty
        lines = mod.diff_catalog(key, old, built[key])
        out["changes"][key] = lines or ["no changes"]
    return out


__all__ = ["ROUTING_RULE", "SURFACE_PRECEDENCE", "precedence_rank", "recommend", "capabilities", "catalog_diff"]
