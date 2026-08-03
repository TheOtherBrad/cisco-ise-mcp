#!/usr/bin/env python3
"""
Refresh the Cisco ISE MCP catalogs.

Generates the JSON catalogs that drive the MCP tool surfaces from authoritative
Cisco sources:

  * ers_resources.json        — parsed from the ERS OpenAPI spec (ERS_APIs.yaml)
  * openapi_endpoints.json    — curated subset parsed from the Open API specs
  * monitoring_endpoints.json — curated subset parsed from the Monitoring (MnT) spec
  * dataconnect_views.json    — scraped from the Cisco DevNet "Database Views" page

The ERS / Open API / Monitoring YAML specs are DOWNLOADED from the URLs listed in
``iseapi_yaml/links.yaml`` into ``iseapi_yaml/{ers,openapi,monitoring}/`` and then
parsed. Data Connect views are scraped from DevNet (Cisco publishes no spec for them).

ERS and Open API are always built. Data Connect and Monitoring are built only when at
least one configured deployment enables them (read from the deployments registry) —
pass ``--all`` to force them, or ``--only`` to choose an explicit subset. Skipped
surfaces leave their existing catalog file untouched.

It also writes ``_meta.json`` (source URLs, fetch date, per-catalog sha256) and can
diff a freshly-built catalog against the cached one to surface upstream changes.

Usage:
    python scripts/refresh_catalog.py                  # auto: ers+openapi, DC/MnT if enabled
    python scripts/refresh_catalog.py --all            # force all four catalogs
    python scripts/refresh_catalog.py --no-download    # rebuild from local specs only
    python scripts/refresh_catalog.py --diff-only      # report changes, write nothing
    python scripts/refresh_catalog.py --only ers,dc    # rebuild an explicit subset

Run it with uv:   uv run python scripts/refresh_catalog.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = ROOT / "src" / "cisco_ise_mcp" / "catalog"
YAML_DIR = ROOT / "iseapi_yaml"
LINKS_FILE = YAML_DIR / "links.yaml"
ERS_DIR = YAML_DIR / "ers"
OPENAPI_DIR = YAML_DIR / "openapi"
MONITORING_DIR = YAML_DIR / "monitoring"
ERS_SPEC = ERS_DIR / "ERS_APIs.yaml"
MONITORING_SPEC = MONITORING_DIR / "monitoring-open-api.yaml"

DEVNET_VIEWS_URL = "https://developer.cisco.com/docs/dataconnect/database-views/"
ISE_VERSION = "3.4"

# Supply-chain guard (Finding #4): Cisco publishes no checksums for these specs and
# no structured spec for Data Connect views, so integrity rests on TLS. We pin what
# we can — refuse any non-HTTPS URL or any host outside this allowlist before opening
# a connection. pubhub hosts the ERS/Open API/Monitoring YAML; developer.cisco.com
# hosts ONLY the Data Connect "Database Views" doc that must be scraped. The committed
# catalog/*.json files are the source of truth — review diffs before regenerating.
_ALLOWED_HOSTS = frozenset({"pubhub.devnetcloud.com", "developer.cisco.com"})


def _check_url(url: str) -> str:
    """Enforce https:// and the host allowlist. Returns the url or raises."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise RuntimeError(f"Refusing non-HTTPS spec URL: {url!r}")
    if parsed.hostname not in _ALLOWED_HOSTS:
        raise RuntimeError(
            f"Refusing spec URL from unlisted host {parsed.hostname!r}: {url!r}. "
            f"Allowed hosts: {', '.join(sorted(_ALLOWED_HOSTS))}."
        )
    return url

# Columns used as the time axis for ``days_back`` filtering, in priority order.
TIME_COL_PRIORITY = (
    "TIMESTAMP", "LOGGED_AT", "GENERATED_TIME", "LOGGED_TIME",
    "EVENT_TIME", "REQUEST_TIME", "RUN_TIME", "CREATE_TIME", "LOGGED_TIME",
)

# Acronyms to upper-case when deriving a human label from an ERS path segment.
_ACRONYMS = {
    "ad", "anc", "aci", "byod", "cts", "csr", "dacl", "id", "ip", "ldap",
    "mdm", "nbar", "ocsp", "odbc", "pxgrid", "radius", "rest", "sgacl",
    "sgt", "sg", "smtp", "sms", "snmp", "sxp", "tacacs", "vlan", "vn", "vpn",
}

# Friendly labels for common ERS resources (segments are single concatenated
# words that can't be auto-split). Anything not listed falls back to title-casing.
_ERS_LABELS = {
    "activedirectory": "Active Directory", "adminuser": "Admin Users",
    "allowedprotocols": "Allowed Protocols", "ancendpoint": "ANC Endpoints",
    "ancpolicy": "ANC Policies", "authorizationprofile": "Authorization Profiles",
    "byodportal": "BYOD Portals", "downloadableacl": "Downloadable ACLs (dACLs)",
    "endpoint": "Endpoints", "endpointgroup": "Endpoint Identity Groups",
    "externalradiusserver": "External RADIUS Servers", "guestuser": "Guest Users",
    "guesttype": "Guest Types", "identitygroup": "Identity Groups",
    "idstoresequence": "Identity Store Sequences", "internaluser": "Internal Users",
    "ldap": "LDAP Identity Sources", "networkdevice": "Network Devices (NADs)",
    "networkdevicegroup": "Network Device Groups", "node": "ISE Nodes",
    "portal": "Portals", "profilerprofile": "Profiler Profiles",
    "radiusserversequence": "RADIUS Server Sequences", "restidstore": "REST ID Stores",
    "sgacl": "Security Group ACLs (SGACLs)", "sgmapping": "SGT Mappings",
    "sgmappinggroup": "SGT Mapping Groups", "sgt": "Security Group Tags (SGTs)",
    "sxpconnections": "SXP Connections", "sxplocalbindings": "SXP Local Bindings",
    "systemcertificate": "System Certificates", "tacacscommandsets": "TACACS+ Command Sets",
    "tacacsexternalservers": "TACACS+ External Servers", "tacacsprofile": "TACACS+ Profiles",
    "tacacsserversequence": "TACACS+ Server Sequences",
}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _http_get(url: str, timeout: int = 30) -> str:
    _check_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": "cisco-ise-mcp-catalog/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (allowlisted https URL)
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def _download(url: str, dest: Path, timeout: int = 30, retries: int = 3) -> int:
    """Download ``url`` to ``dest`` (bytes). Returns the byte count.

    Retries on transient (network / 5xx) errors; a 4xx is raised immediately (no
    point retrying a missing or forbidden file). The URL must be HTTPS on an
    allow-listed host (see ``_check_url``).
    """
    _check_url(url)
    last_exc: Exception | None = None
    for attempt in range(1, max(1, retries) + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cisco-ise-mcp-catalog/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (allowlisted https URL)
                data = resp.read()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            return len(data)
        except urllib.error.HTTPError as exc:
            if 400 <= exc.code < 500:
                raise RuntimeError(f"HTTP {exc.code} for {url}") from exc
            last_exc = exc
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
        if attempt < retries:
            time.sleep(min(2 * attempt, 5))
    raise RuntimeError(f"failed to download {url} after {retries} attempt(s): {last_exc}")


def _label_from_segment(segment: str) -> str:
    """Turn an ERS path segment (e.g. 'tacacscommandsets') into a readable label."""
    words = re.findall(r"[a-z]+|[0-9]+", segment.lower()) or [segment]
    out = []
    for w in words:
        out.append(w.upper() if w in _ACRONYMS else w.capitalize())
    return " ".join(out)


def _pick_time_col(columns: list[str]) -> str | None:
    upper = {c.upper() for c in columns}
    for cand in TIME_COL_PRIORITY:
        if cand in upper:
            return cand
    return None


def _load_yaml(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(
            f"Spec '{path.name}' is missing from {path.parent}. Run a full refresh to "
            f"download it:  uv run python scripts/refresh_catalog.py"
        )
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ─────────────────────────── links.yaml — download specs ───────────────────────

def _items(section) -> list:
    return section if isinstance(section, list) else ([section] if section else [])


def _first(items: list, field: str):
    for it in items:
        if isinstance(it, dict) and it.get(field) is not None:
            return it[field]
    return None


def _all(items: list, field: str) -> list:
    return [it[field] for it in items if isinstance(it, dict) and it.get(field) is not None]


def download_specs(only: set[str] | None = None) -> tuple[dict, list[str]]:
    """Download ERS / Open API / Monitoring specs listed in ``links.yaml``.

    Returns ``(summary, failures)`` where summary is {section: [(name, dest, bytes)]}
    and failures is a list of human-readable per-file errors. A single bad link (404,
    transient outage) is recorded and skipped — it never aborts the whole refresh.
    ``only`` restricts which sections are fetched ('ers', 'openapi', 'monitoring').
    """
    links = _load_yaml(LINKS_FILE)
    settings = _items(links.get("default_settings"))
    timeout = int(_first(settings, "timeout_seconds") or 30)
    retries = int(_first(settings, "retry_count") or 3)
    want = only or {"ers", "openapi", "monitoring"}
    summary: dict[str, list] = {}
    failures: list[str] = []

    def _grab(name: str, url: str, dest: Path, bucket: list) -> None:
        try:
            bucket.append((name, dest, _download(url, dest, timeout, retries)))
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{name}: {exc}")

    # Fail fast on a tampered/unlisted link BEFORE fetching anything, so a bad
    # links.yaml aborts the whole refresh rather than being logged as one skipped
    # file (supply-chain guard, Finding #4).
    urls_to_check: list[str] = []
    if "ers" in want:
        urls_to_check += _all(_items(links.get("ers")), "url")
    if "openapi" in want:
        oa_items = _items(links.get("openapi"))
        oa_base = (_first(oa_items, "baseurl") or "").rstrip("/")
        for f in (_first(oa_items, "files") or []):
            rel = f.get("path") if isinstance(f, dict) else None
            if rel and oa_base:
                urls_to_check.append(f"{oa_base}/{rel}")
    if "monitoring" in want:
        urls_to_check += _all(_items(links.get("monitoring")), "url")
    for u in urls_to_check:
        _check_url(u)  # raises on non-HTTPS or unlisted host

    if "ers" in want:
        out: list = []
        for url in _all(_items(links.get("ers")), "url"):
            _grab(Path(url).name, url, ERS_DIR / Path(url).name, out)
        summary["ers"] = out

    if "openapi" in want:
        items = _items(links.get("openapi"))
        baseurl = (_first(items, "baseurl") or "").rstrip("/")
        files = _first(items, "files") or []
        out = []
        for f in files:
            rel = f.get("path") if isinstance(f, dict) else None
            if not rel or not baseurl:
                continue
            _grab(rel, f"{baseurl}/{rel}", OPENAPI_DIR / rel, out)
        summary["openapi"] = out

    if "monitoring" in want:
        out = []
        for url in _all(_items(links.get("monitoring")), "url"):
            _grab(Path(url).name, url, MONITORING_DIR / Path(url).name, out)
        summary["monitoring"] = out

    return summary, failures


# ───────────────────────────── ERS (from ERS_APIs.yaml) ────────────────────────

def build_ers(spec_path: Path) -> dict:
    """Parse the ERS OpenAPI spec into a resource catalog keyed by path segment."""
    spec = _load_yaml(spec_path)
    paths: dict = spec.get("paths", {}) or {}
    resources: dict[str, dict] = {}

    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        parts = [p for p in str(raw_path).strip("/").split("/") if p != ""]
        if not parts:
            continue
        seg = parts[0]
        rest = parts[1:]
        methods = {m.upper() for m in item if m.lower() in ("get", "post", "put", "delete", "patch")}
        tags = []
        for m in item.values():
            if isinstance(m, dict) and m.get("tags"):
                tags = m["tags"]
                break

        r = resources.setdefault(seg, {
            "key": seg, "path": seg, "label": _ERS_LABELS.get(seg, _label_from_segment(seg)),
            "tag": (tags[0] if tags else seg),
            "ops": {k: False for k in
                    ("list", "create", "get", "update", "delete", "patch", "get_by_name")},
            "actions": [],
        })

        is_collection = len(rest) == 0
        is_item = len(rest) == 1 and rest[0].startswith("{")
        is_by_name = len(rest) == 2 and rest[0] == "name" and rest[1].startswith("{")

        if is_collection:
            if "GET" in methods:
                r["ops"]["list"] = True
            if "POST" in methods:
                r["ops"]["create"] = True
        elif is_item:
            if "GET" in methods:
                r["ops"]["get"] = True
            if "PUT" in methods:
                r["ops"]["update"] = True
            if "DELETE" in methods:
                r["ops"]["delete"] = True
            if "PATCH" in methods:
                r["ops"]["patch"] = True
        elif is_by_name:
            if "GET" in methods:
                r["ops"]["get_by_name"] = True
        else:
            action = "/".join(rest)
            if action and action not in r["actions"]:
                r["actions"].append(action)

    for r in resources.values():
        r["actions"].sort()
    return dict(sorted(resources.items()))


# ─────────────────────── Data Connect (scraped from DevNet) ────────────────────

class _ViewsParser(HTMLParser):
    """Extract {view_name: {description, columns[]}} from the DevNet views page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.views: dict[str, dict] = {}
        self._cur: str | None = None
        self._mode: str | None = None
        self._buf = ""
        self._in_tbody = False
        self._row: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "h1":
            self._mode, self._buf = "h1", ""
        elif tag == "p" and self._cur and not self.views[self._cur]["description"]:
            self._mode, self._buf = "p", ""
        elif tag == "tbody":
            self._in_tbody = True
        elif tag == "tr" and self._in_tbody:
            self._row = []
        elif tag == "td" and self._in_tbody:
            self._mode, self._buf = "td", ""

    def handle_data(self, data):
        if self._mode in ("h1", "p", "td"):
            self._buf += data

    def handle_endtag(self, tag):
        if tag == "h1":
            name = self._buf.strip()
            if re.fullmatch(r"[A-Z][A-Z0-9_]+", name):
                self._cur = name
                self.views.setdefault(name, {"description": "", "columns": [], "internal": False})
            else:
                self._cur = None
            self._mode = None
        elif tag == "p" and self._mode == "p":
            txt = self._buf.strip()
            if self._cur and not self.views[self._cur]["description"] and not txt.lower().startswith("type:"):
                self.views[self._cur]["description"] = txt
                if "not to be used" in txt.lower() or "internal view" in txt.lower():
                    self.views[self._cur]["internal"] = True
            self._mode = None
        elif tag == "td" and self._mode == "td":
            self._row.append(self._buf.strip())
            self._mode = None
        elif tag == "tr" and self._in_tbody and self._row:
            name = self._row[0]
            if self._cur and name and name.lower() != "column name":
                col = {"name": name}
                if len(self._row) >= 2:
                    col["type"] = self._row[1]
                if len(self._row) >= 3:
                    col["description"] = self._row[2]
                self.views[self._cur]["columns"].append(col)
            self._row = []
        elif tag == "tbody":
            self._in_tbody = False


def scrape_dataconnect(html: str) -> dict:
    """Parse the DevNet Database Views HTML into a view catalog."""
    p = _ViewsParser()
    p.feed(html)
    if len(p.views) < 30:
        raise RuntimeError(
            f"Data Connect scrape produced only {len(p.views)} views — the DevNet page "
            "structure may have changed. Refusing to write a truncated catalog."
        )
    out: dict[str, dict] = {}
    for name, info in sorted(p.views.items()):
        cols = [c["name"] for c in info["columns"]]
        out[name.lower()] = {
            "view": name,
            "label": _label_from_segment(name.lower().replace("_view", "")).replace(" View", ""),
            "description": info["description"] or f"{name} view.",
            "internal": info["internal"],
            "time_col": _pick_time_col(cols),
            "columns": info["columns"],
        }
    return out


# ───────────────────────────── diff helpers ───────────────────────────────────

def _keys(catalog) -> set:
    if isinstance(catalog, dict):
        return set(catalog.keys())
    return {e.get("tool") for e in catalog}


def diff_catalog(name: str, old, new) -> list[str]:
    """Return human-readable add/remove/change lines comparing two catalogs."""
    lines: list[str] = []
    ok, nk = _keys(old), _keys(new)
    for added in sorted(nk - ok):
        lines.append(f"  + [{name}] added: {added}")
    for removed in sorted(ok - nk):
        lines.append(f"  - [{name}] removed: {removed}")

    def _get(cat, k):
        if isinstance(cat, dict):
            return cat.get(k)
        return next((e for e in cat if e.get("tool") == k), None)

    for shared in sorted(ok & nk):
        if json.dumps(_get(old, shared), sort_keys=True) != json.dumps(_get(new, shared), sort_keys=True):
            lines.append(f"  ~ [{name}] changed: {shared}")
    return lines


# ─────────────────────── Open API (curated, parsed from specs) ─────────────────
# Curated allowlist of high-value Open API operations. Each entry names a stable
# tool plus the (method, path) to resolve against the downloaded spec for that
# category. ``has_body`` / ``params`` / ``desc`` are taken from the parsed spec
# (path placeholders → params; requestBody → body; summary/description → desc),
# falling back to the curated description below. Everything NOT listed here remains
# reachable through the generic ``ise_openapi_request`` passthrough.

# category -> spec file under iseapi_yaml/openapi/
_OA_SPEC_BY_CATEGORY = {
    "Repository": "Repository.yaml",
    "Backup & Restore": "BackupRestore.yaml",
    "Certificates": "certificates.yaml",
    "Policy: Network Access": "policy.yaml",
    "Policy: Device Admin": "policy.yaml",
    "Deployment": "deployment.yaml",
    "Patch": "patch-hot-patch.yaml",
    "Licensing": "licensing.yaml",
    "Task": "task-service.yaml",
}

_NA = "/api/v1/policy/network-access"
_DA = "/api/v1/policy/device-admin"

# (tool, method, path, category, fallback_desc)
_OPENAPI_CURATED = [
    # Repository
    ("repo_list", "GET", "/api/v1/repository", "Repository", "List all configured repositories."),
    ("repo_get", "GET", "/api/v1/repository/{name}", "Repository", "Get a repository by name."),
    ("repo_create", "POST", "/api/v1/repository", "Repository", "Create a repository."),
    ("repo_update", "PUT", "/api/v1/repository/{name}", "Repository", "Update a repository by name."),
    ("repo_delete", "DELETE", "/api/v1/repository/{name}", "Repository", "Delete a repository by name."),
    ("repo_list_files", "GET", "/api/v1/repository/{name}/files", "Repository", "List files in a repository."),
    # Backup & Restore
    ("backup_create", "POST", "/api/v1/backup-restore/config/backup", "Backup & Restore", "Trigger an on-demand config backup."),
    ("backup_cancel", "POST", "/api/v1/backup-restore/config/cancel-backup", "Backup & Restore", "Cancel the running backup."),
    ("backup_restore", "POST", "/api/v1/backup-restore/config/restore", "Backup & Restore", "Restore a config backup."),
    ("backup_last_status", "GET", "/api/v1/backup-restore/config/last-backup-status", "Backup & Restore", "Get the last backup status."),
    ("backup_schedule_create", "POST", "/api/v1/backup-restore/config/schedule-config-backup", "Backup & Restore", "Create the scheduled backup config."),
    ("backup_schedule_update", "PUT", "/api/v1/backup-restore/config/schedule-config-backup", "Backup & Restore", "Update the scheduled backup config."),
    # Certificates
    ("cert_system_list", "GET", "/api/v1/certs/system-certificate/{hostName}", "Certificates", "List system certificates on a node (hostName = ISE node FQDN/hostname)."),
    ("cert_system_get", "GET", "/api/v1/certs/system-certificate/{hostName}/{id}", "Certificates", "Get a system certificate by ID on a node."),
    ("cert_system_delete", "DELETE", "/api/v1/certs/system-certificate/{hostName}/{id}", "Certificates", "Delete a system certificate by ID on a node."),
    ("cert_system_import", "POST", "/api/v1/certs/system-certificate/import", "Certificates", "Import a system certificate (with key)."),
    ("cert_system_export", "POST", "/api/v1/certs/system-certificate/export", "Certificates", "Export a system certificate."),
    ("cert_trusted_list", "GET", "/api/v1/certs/trusted-certificate", "Certificates", "List all trusted certificates (cluster-wide)."),
    ("cert_trusted_get", "GET", "/api/v1/certs/trusted-certificate/{id}", "Certificates", "Get a trusted certificate by ID."),
    ("cert_trusted_update", "PUT", "/api/v1/certs/trusted-certificate/{id}", "Certificates", "Update a trusted certificate by ID."),
    ("cert_trusted_delete", "DELETE", "/api/v1/certs/trusted-certificate/{id}", "Certificates", "Delete a trusted certificate by ID."),
    ("cert_trusted_import", "POST", "/api/v1/certs/trusted-certificate/import", "Certificates", "Import a trusted certificate."),
    ("cert_csr_list", "GET", "/api/v1/certs/certificate-signing-request", "Certificates", "List certificate signing requests."),
    # Policy — Network Access (RADIUS)
    ("radius_policy_set_list", "GET", f"{_NA}/policy-set", "Policy: Network Access", "List RADIUS (network-access) policy sets."),
    ("radius_policy_set_get", "GET", f"{_NA}/policy-set/{{id}}", "Policy: Network Access", "Get a network-access policy set by ID."),
    ("radius_policy_set_create", "POST", f"{_NA}/policy-set", "Policy: Network Access", "Create a network-access policy set."),
    ("radius_policy_set_update", "PUT", f"{_NA}/policy-set/{{id}}", "Policy: Network Access", "Update a network-access policy set."),
    ("radius_policy_set_delete", "DELETE", f"{_NA}/policy-set/{{id}}", "Policy: Network Access", "Delete a network-access policy set."),
    ("radius_authentication_list", "GET", f"{_NA}/policy-set/{{id}}/authentication", "Policy: Network Access", "List authentication rules in a network-access policy set."),
    ("radius_authentication_create", "POST", f"{_NA}/policy-set/{{id}}/authentication", "Policy: Network Access", "Create an authentication rule in a network-access policy set."),
    ("radius_authorization_list", "GET", f"{_NA}/policy-set/{{id}}/authorization", "Policy: Network Access", "List authorization rules in a network-access policy set."),
    ("radius_authorization_create", "POST", f"{_NA}/policy-set/{{id}}/authorization", "Policy: Network Access", "Create an authorization rule in a network-access policy set."),
    ("radius_exception_list", "GET", f"{_NA}/policy-set/{{id}}/exception", "Policy: Network Access", "List local exception rules in a network-access policy set."),
    ("radius_global_exception_list", "GET", f"{_NA}/policy-set/global-exception", "Policy: Network Access", "List network-access global exception rules."),
    ("radius_condition_list", "GET", f"{_NA}/condition", "Policy: Network Access", "List network-access policy conditions."),
    ("radius_condition_get", "GET", f"{_NA}/condition/{{id}}", "Policy: Network Access", "Get a network-access condition by ID."),
    ("radius_condition_create", "POST", f"{_NA}/condition", "Policy: Network Access", "Create a network-access condition."),
    ("radius_dictionary_list", "GET", f"{_NA}/dictionaries", "Policy: Network Access", "List network-access dictionaries."),
    ("radius_dictionary_get", "GET", f"{_NA}/dictionaries/{{name}}", "Policy: Network Access", "Get a network-access dictionary by name."),
    # Policy — Device Admin (TACACS+)
    ("tacacs_policy_set_list", "GET", f"{_DA}/policy-set", "Policy: Device Admin", "List TACACS+ (device-admin) policy sets."),
    ("tacacs_policy_set_get", "GET", f"{_DA}/policy-set/{{id}}", "Policy: Device Admin", "Get a device-admin policy set by ID."),
    ("tacacs_policy_set_create", "POST", f"{_DA}/policy-set", "Policy: Device Admin", "Create a device-admin policy set."),
    ("tacacs_policy_set_update", "PUT", f"{_DA}/policy-set/{{id}}", "Policy: Device Admin", "Update a device-admin policy set."),
    ("tacacs_policy_set_delete", "DELETE", f"{_DA}/policy-set/{{id}}", "Policy: Device Admin", "Delete a device-admin policy set."),
    ("tacacs_authentication_list", "GET", f"{_DA}/policy-set/{{id}}/authentication", "Policy: Device Admin", "List authentication rules in a device-admin policy set."),
    ("tacacs_authorization_list", "GET", f"{_DA}/policy-set/{{id}}/authorization", "Policy: Device Admin", "List authorization rules in a device-admin policy set."),
    ("tacacs_command_sets_list", "GET", f"{_DA}/command-sets", "Policy: Device Admin", "List TACACS+ command sets."),
    ("tacacs_condition_list", "GET", f"{_DA}/condition", "Policy: Device Admin", "List device-admin policy conditions."),
    ("tacacs_shell_profiles_list", "GET", f"{_DA}/shell-profiles", "Policy: Device Admin", "List TACACS+ shell profiles."),
    # Deployment
    ("deployment_node_list", "GET", "/api/v1/deployment/node", "Deployment", "List all deployment nodes."),
    ("deployment_node_get", "GET", "/api/v1/deployment/node/{hostname}", "Deployment", "Get a deployment node by hostname."),
    ("deployment_node_group_list", "GET", "/api/v1/deployment/node-group", "Deployment", "List node groups."),
    # Patch / Hot Patch
    ("patch_list", "GET", "/api/v1/patch", "Patch", "List installed patches."),
    ("patch_install", "POST", "/api/v1/patch/install", "Patch", "Install a patch (patchName, repositoryName)."),
    ("patch_rollback", "POST", "/api/v1/patch/rollback", "Patch", "Roll back a patch."),
    ("hotpatch_list", "GET", "/api/v1/hotpatch", "Patch", "List installed hot patches."),
    ("hotpatch_install", "POST", "/api/v1/hotpatch/install", "Patch", "Install a hot patch."),
    ("hotpatch_rollback", "POST", "/api/v1/hotpatch/rollback", "Patch", "Roll back a hot patch."),
    # Licensing
    ("license_smart_state_get", "GET", "/api/v1/license/system/smart-state", "Licensing", "Get smart licensing state."),
    ("license_smart_state_set", "POST", "/api/v1/license/system/smart-state", "Licensing", "Set smart licensing state."),
    ("license_tier_state_get", "GET", "/api/v1/license/system/tier-state", "Licensing", "Get license tier state."),
    ("license_register", "POST", "/api/v1/license/system/register", "Licensing", "Register smart licensing."),
    ("license_eval_get", "GET", "/api/v1/license/system/eval-license", "Licensing", "Get evaluation license info."),
    ("license_connection_type_get", "GET", "/api/v1/license/system/connection-type", "Licensing", "Get the smart licensing connection type."),
    # Task service
    ("task_get", "GET", "/api/v1/task/{id}", "Task", "Get the status/result of an async task by ID."),
]

_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _seg_template(path: str) -> tuple:
    """Normalize a path to a comparable template: drop a leading /api/vN, wildcard
    every ``{param}`` to ``{}``, lowercase, and ignore trailing slashes. Lets a
    curated path match the spec regardless of param names or the /api/v1 prefix
    (some ISE specs, e.g. deployment.yaml, omit it)."""
    segs = [s for s in str(path).strip("/").split("/") if s]
    while segs and (segs[0].lower() == "api" or re.fullmatch(r"v\d+", segs[0].lower())):
        segs = segs[1:]
    return tuple("{}" if s.startswith("{") else s.lower() for s in segs)


def _index_spec(paths_dict: dict) -> dict:
    """Index a parsed spec's paths by segment-template -> {path, ops:{method: op}}."""
    idx: dict = {}
    for p, item in (paths_dict or {}).items():
        if not isinstance(item, dict):
            continue
        entry = idx.setdefault(_seg_template(p), {"path": p, "ops": {}})
        for m, op in item.items():
            if m.lower() in ("get", "post", "put", "delete", "patch") and isinstance(op, dict):
                entry["ops"].setdefault(m.lower(), op)
    return idx


def _openapi_index(spec_file: str, cache: dict) -> dict:
    if spec_file not in cache:
        cache[spec_file] = _index_spec(_load_yaml(OPENAPI_DIR / spec_file).get("paths", {}))
    return cache[spec_file]


def _op_desc(op: dict, fallback: str) -> str:
    summary = (op.get("summary") or "").strip()
    if summary and summary.lower() not in ("get-all", "get", "create", "update", "delete"):
        return summary
    first_line = (op.get("description") or "").strip().splitlines()[0:1]
    return (first_line[0].strip() if first_line else "") or fallback


def build_openapi(openapi_dir: Path) -> list:
    """Resolve the curated Open API allowlist against the downloaded specs.

    Each curated op is located in its spec by segment-template (tolerating param-name
    and /api/v1-prefix differences). The authoritative *curated* path is emitted (it
    is the corroborated client path — some specs omit /api/v1), while ``body`` and
    ``desc`` are taken from the matched spec operation. Unresolved ops are warned and
    skipped (still reachable via ise_openapi_request)."""
    cache: dict = {}
    out: list[dict] = []
    warnings: list[str] = []
    for tool, method, path, category, fallback in _OPENAPI_CURATED:
        spec_file = _OA_SPEC_BY_CATEGORY[category]
        try:
            idx = _openapi_index(spec_file, cache)
        except FileNotFoundError as exc:
            warnings.append(f"{tool}: {exc}")
            continue
        entry = idx.get(_seg_template(path))
        op = entry["ops"].get(method.lower()) if entry else None
        if not isinstance(op, dict):
            warnings.append(f"{tool}: {method} {path} not found in {spec_file}")
            continue
        out.append({
            "tool": tool, "method": method, "path": path,
            "params": _PLACEHOLDER_RE.findall(path),
            "body": bool(op.get("requestBody")) or method.upper() in ("POST", "PUT", "PATCH"),
            "desc": _op_desc(op, fallback),
            "category": category,
        })
    if warnings:
        print(f"[openapi] WARNING: {len(warnings)} curated op(s) not resolved from specs:", file=sys.stderr)
        for w in warnings:
            print(f"    {w}", file=sys.stderr)
    return out


# ──────────────────── Monitoring / MnT (curated, parsed from spec) ─────────────
# The MnT API is served under https://<host>/admin/API/mnt and returns XML. We
# curate a subset of well-known read/operational endpoints; the rest are reachable
# via the generic ``ise_mnt_request`` passthrough. ``spec_path`` is the path as it
# appears in monitoring-open-api.yaml; the published tool path is prefixed with the
# MnT base below.

_MNT_BASE = "/admin/API/mnt"

# (tool, method, spec_path, category, fallback_desc)
_MNT_CURATED = [
    ("active_session_count", "GET", "/Session/ActiveCount", "Sessions", "Count of currently active sessions."),
    ("active_session_list", "GET", "/Session/ActiveList", "Sessions", "List of currently active sessions."),
    ("posture_session_count", "GET", "/Session/PostureCount", "Sessions", "Count of active sessions with posture."),
    ("profiler_session_count", "GET", "/Session/ProfilerCount", "Sessions", "Count of profiler sessions."),
    ("auth_session_list", "GET", "/Session/AuthList/{startTime}/{endTime}", "Sessions", "Authentication session list for a time window (use 'null'/'null' for all)."),
    ("session_by_mac", "GET", "/Session/MACAddress/{mac}", "Sessions", "Full session details for a MAC address."),
    ("session_by_username", "GET", "/Session/UserName/{username}", "Sessions", "Full session details for a username."),
    ("session_by_ip", "GET", "/Session/IPAddress/{ipaddress}", "Sessions", "Full session details for an IP address."),
    ("session_by_endpoint_ip", "GET", "/Session/EndPointIPAddress/{ip}", "Sessions", "Full session details for an endpoint IP address."),
    ("session_by_id", "GET", "/Session/Active/SessionID/{sid}/{outputType}", "Sessions", "Active session by session ID (outputType = xml or json)."),
    ("mnt_version", "GET", "/Version", "System", "MnT product/schema version."),
    ("failure_reasons", "GET", "/FailureReasons", "System", "List of authentication failure reasons."),
    ("coa_reauth", "GET", "/CoA/Reauth/{node}/{mac}/{type}", "CoA", "Issue a CoA re-authentication for a session."),
    ("coa_disconnect", "GET", "/CoA/Disconnect/{node}/{mac}/{option}", "CoA", "Issue a CoA disconnect for a session."),
    ("session_delete_by_mac", "DELETE", "/Session/Delete/MACAddress/{mac}", "Sessions", "Delete a session record by MAC address."),
    ("session_delete_by_id", "DELETE", "/Session/Delete/SessionID/{sid}", "Sessions", "Delete a session record by session ID."),
]


def build_monitoring(spec_path: Path) -> list:
    """Resolve the curated MnT allowlist against the Monitoring spec, emitting the
    spec's real path prefixed with the MnT base (/admin/API/mnt)."""
    idx = _index_spec(_load_yaml(spec_path).get("paths", {}))
    out: list[dict] = []
    warnings: list[str] = []
    for tool, method, spath, category, fallback in _MNT_CURATED:
        entry = idx.get(_seg_template(spath))
        op = entry["ops"].get(method.lower()) if entry else None
        if not isinstance(op, dict):
            warnings.append(f"{tool}: {method} {spath} not found in {spec_path.name}")
            continue
        full = f"{_MNT_BASE}/{entry['path'].strip('/')}"
        out.append({
            "tool": tool, "method": method, "path": full,
            "params": _PLACEHOLDER_RE.findall(full),
            "body": bool(op.get("requestBody")),
            "desc": _op_desc(op, fallback),
            "category": category,
        })
    if warnings:
        print(f"[monitoring] WARNING: {len(warnings)} curated op(s) not resolved from spec:", file=sys.stderr)
        for w in warnings:
            print(f"    {w}", file=sys.stderr)
    return out


# ───────────────────────────── write / build / CLI ────────────────────────────

def _dump(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


_FILES = {
    "ers": "ers_resources.json",
    "openapi": "openapi_endpoints.json",
    "monitoring": "monitoring_endpoints.json",
    "dc": "dataconnect_views.json",
}


def build_all(fetch_dc: bool = True, want: set[str] | None = None) -> dict:
    """Build the requested catalogs from LOCAL specs (+ DevNet scrape for DC).

    Never raises for a missing local spec — that surface is simply skipped with a
    note (so the runtime ``ise_catalog_diff`` degrades gracefully without specs).
    """
    want = want or {"ers", "openapi", "monitoring", "dc"}
    catalogs: dict = {}

    def _try(key: str, fn) -> None:
        try:
            catalogs[key] = fn()
        except FileNotFoundError as exc:
            print(f"[{key}] skipped — {exc}", file=sys.stderr)

    if "ers" in want:
        _try("ers", lambda: build_ers(ERS_SPEC))
    if "openapi" in want:
        _try("openapi", lambda: build_openapi(OPENAPI_DIR))
    if "monitoring" in want:
        _try("monitoring", lambda: build_monitoring(MONITORING_SPEC))
    if "dc" in want and fetch_dc:
        catalogs["dc"] = scrape_dataconnect(_http_get(DEVNET_VIEWS_URL))
    return catalogs


def _registry_surfaces() -> tuple[bool, bool]:
    """Return ``(any_dc_enabled, any_mapi_enabled)`` from the deployment registry.

    Best-effort: returns ``(False, False)`` when the package or registry can't be read
    (e.g. a fresh checkout with no deployments), so we never fetch/scrape Data Connect
    or Monitoring catalogs that nothing uses. Use ``--all`` to force them.
    """
    try:
        from cisco_ise_mcp import config
        deps = config.load_registry().get("deployments", {})
    except Exception:  # noqa: BLE001
        return False, False
    any_dc = any((d.get("dataconnect") or {}).get("enabled", True) for d in deps.values())
    any_mapi = any(config._monitoring_enabled(d) for d in deps.values())
    return any_dc, any_mapi


def _resolve_want(args) -> set[str]:
    """Decide which catalogs to build: explicit ``--only`` > ``--all`` > registry auto."""
    if args.only:
        return {s.strip() for s in args.only.split(",") if s.strip()}
    if getattr(args, "all_surfaces", False):
        return {"ers", "openapi", "monitoring", "dc"}
    want = {"ers", "openapi"}  # always built
    any_dc, any_mapi = _registry_surfaces()
    if any_dc:
        want.add("dc")
    if any_mapi:
        want.add("monitoring")
    skipped = [s for s, on in (("dc", any_dc), ("monitoring", any_mapi)) if not on]
    if skipped:
        print(f"auto: no configured deployment enables {', '.join(skipped)} — skipping "
              f"(existing catalog file(s) left untouched; pass --all to force).")
    return want


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Refresh / diff the Cisco ISE MCP catalogs.")
    ap.add_argument("--diff-only", action="store_true", help="Report changes without writing.")
    ap.add_argument("--only", default=None,
                    help="Comma list of catalogs to build: ers,dc,openapi,monitoring "
                         "(overrides the registry-based auto-selection).")
    ap.add_argument("--all", dest="all_surfaces", action="store_true",
                    help="Build ALL catalogs (ers,openapi,dc,monitoring) regardless of which "
                         "deployments enable Data Connect / Monitoring.")
    ap.add_argument("--no-download", action="store_true",
                    help="Do not download specs; build from the local iseapi_yaml files.")
    ap.add_argument("--no-network", action="store_true",
                    help="Skip ALL network (no spec download, no DevNet scrape).")
    args = ap.parse_args(argv)

    want = _resolve_want(args)
    no_net = args.no_network
    fetch_dc = "dc" in want and not no_net

    # Download the ERS / Open API / Monitoring specs listed in links.yaml first.
    if not args.no_download and not no_net and not args.diff_only:
        spec_sections = want & {"ers", "openapi", "monitoring"}
        if spec_sections:
            try:
                summary, failures = download_specs(only=spec_sections)
            except Exception as exc:  # noqa: BLE001 — links.yaml unreadable / total failure
                print(f"ERROR downloading specs: {exc}", file=sys.stderr)
                return 2
            for sect, items in summary.items():
                total = sum(b for _, _, b in items)
                print(f"downloaded {sect}: {len(items)} file(s), {total:,} bytes")
            if failures:
                print(f"WARNING: {len(failures)} spec(s) could not be downloaded "
                      f"(skipped — check links.yaml):", file=sys.stderr)
                for fail in failures:
                    print(f"    {fail}", file=sys.stderr)

    try:
        built = build_all(fetch_dc=fetch_dc, want=want)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR building catalogs: {exc}", file=sys.stderr)
        return 2

    any_change = False
    for key in ("ers", "openapi", "monitoring", "dc"):
        if key not in want or key not in built:
            continue
        new = built[key]
        path = CATALOG_DIR / _FILES[key]
        empty: object = [] if key in ("openapi", "monitoring") else {}
        old = json.loads(path.read_text(encoding="utf-8")) if path.exists() else empty
        lines = diff_catalog(key, old, new)
        n = len(new)
        if lines:
            any_change = True
            print(f"[{key}] {n} entries — {len(lines)} change(s):")
            print("\n".join(lines))
        else:
            print(f"[{key}] {n} entries — no changes.")

    if args.diff_only:
        print("\n--diff-only: no files written.")
        return 1 if any_change else 0

    CATALOG_DIR.mkdir(parents=True, exist_ok=True)
    meta = {
        "ise_version": ISE_VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": {
            "ers": "iseapi_yaml/ers/ERS_APIs.yaml (via links.yaml)",
            "openapi": "iseapi_yaml/openapi/*.yaml (via links.yaml)",
            "monitoring": "iseapi_yaml/monitoring/monitoring-open-api.yaml (via links.yaml)",
            "dataconnect": DEVNET_VIEWS_URL,
        },
        "counts": {}, "sha256": {},
    }
    for key in ("ers", "openapi", "monitoring", "dc"):
        if key not in want or key not in built:
            continue
        text = _dump(built[key])
        (CATALOG_DIR / _FILES[key]).write_text(text, encoding="utf-8")
        meta["counts"][key] = len(built[key])
        meta["sha256"][_FILES[key]] = _sha256(text)
        print(f"wrote {_FILES[key]} ({len(built[key])} entries)")

    # Merge meta (preserve untouched catalog checksums if a subset was built).
    meta_path = CATALOG_DIR / "_meta.json"
    if meta_path.exists():
        prev = json.loads(meta_path.read_text(encoding="utf-8"))
        for k in ("counts", "sha256"):
            merged = dict(prev.get(k, {}))
            merged.update(meta[k])
            meta[k] = merged
    meta_path.write_text(_dump(meta), encoding="utf-8")
    print("wrote _meta.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
