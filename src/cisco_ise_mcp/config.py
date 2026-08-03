"""
Configuration management for the Cisco ISE MCP server (v2.0 — multi-deployment).

A single running server can manage MANY Cisco ISE deployments. Non-secret
per-deployment config (name, host, ports, Data Connect cert path, TLS flags) is
stored in a registry file, ``deployments.json``; passwords are stored separately
and securely in the OS keyring (or injected via env vars for headless hosts).

Registry location (override with the ``CISCO_ISE_MCP_HOME`` env var):
  * Windows : %APPDATA%\\cisco-ise-mcp\\deployments.json
  * macOS   : ~/Library/Application Support/cisco-ise-mcp/deployments.json
  * Linux   : $XDG_CONFIG_HOME/cisco-ise-mcp/deployments.json  (else ~/.config/...)

Per-deployment secret resolution order (first hit wins):
  1. Env var   CISCO_ISE__<SLUG>__ISE_PASSWORD  / ..._DATACONNECT_PASSWORD
  2. Secret file via the ``*_FILE`` variant of the same env var (Docker/K8s)
  3. OS keyring  (service ``cisco-ise-mcp``, username ``<slug>:<key>``)
Passwords are NEVER accepted through MCP/agent tool arguments — they are set on
a terminal with ``uv run cisco-ise-mcp set-credential <name>`` (getpass) or injected as
env vars. The agent only ever writes non-secret fields.

Optional dependencies:
  * ``python-dotenv`` — loads a local ``.env`` (optional; for env-var credential injection)
  * ``keyring``       — OS keyring integration (primary secret store)
"""

from __future__ import annotations

import json
import logging
import os
import re
import ssl
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional, Union

from mcp.types import Tool

from cisco_ise_mcp import _mcpcompat as compat

logger = logging.getLogger(__name__)


def admin_tls_verify(verify_ssl: bool, ca_cert_path: str = "") -> Union[bool, str]:
    """Resolve the ``verify=`` value for the ERS/Open API/Monitoring httpx clients.

    httpx treats ``verify=True`` as "trust only the certifi bundle" — it never
    consults the OS trust store (e.g. the macOS Keychain), so a private ISE CA
    is invisible no matter what the operator imported there. To trust a private
    CA the caller must point httpx at the CA bundle explicitly.

    Returns one of:
      * ``False`` — verification disabled (verify_ssl is off; lab only).
      * a filesystem path (str) — trust anchor is the operator-supplied CA PEM.
        httpx builds an SSLContext from it with certificate AND hostname
        checking left ON (``ssl.create_default_context(cafile=path)``), so the
        server's leaf SAN must match the dialed host. Full chain validation is
        preserved — this only *adds* the private root as a trust anchor.
      * ``True`` — no CA path given; fall back to the public certifi roots.

    A configured-but-missing ``ca_cert_path`` is a hard error rather than a
    silent fallback to certifi: silently downgrading the trust anchor the
    operator asked for would be a security surprise (the connection would either
    fail confusingly or trust the wrong roots).
    """
    if not verify_ssl:
        return False
    path = (ca_cert_path or "").strip()
    if not path:
        return True
    if not os.path.isfile(path):
        raise ConfigError(
            f"ca_cert_path is set to {path!r} but no readable file exists there. "
            "Point it at the exported ISE root-CA (or full-chain) PEM, or clear it "
            "to fall back to the system/certifi trust store."
        )
    # Fail fast with a clear message if the file is not a usable CA bundle,
    # instead of surfacing an opaque httpx SSL error on the first request.
    try:
        ssl.create_default_context(cafile=path)
    except ssl.SSLError as exc:
        raise ConfigError(
            f"ca_cert_path {path!r} is not a valid PEM CA bundle: {exc}. Export the "
            "ISE root CA in Base64/PEM form (a text file beginning with "
            "'-----BEGIN CERTIFICATE-----')."
        ) from exc
    return path

# ---------------------------------------------------------------------------
# dotenv — optional; loads a .env for env-var credential injection.
# Loaded ONLY from the config home (see ``_load_env`` below, called once
# ``get_home`` is defined) — never from the current working directory, so
# starting the server in an attacker-controlled dir cannot inject credentials.
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv as _load_dotenv
except ImportError:
    _load_dotenv = None

# ---------------------------------------------------------------------------
# keyring — primary secret store; degrades gracefully when no backend exists
# ---------------------------------------------------------------------------
_KEYRING_AVAILABLE = False
try:
    import keyring as _keyring

    try:
        from keyring.errors import NoKeyringError as _NoKeyringError
    except Exception:  # noqa: BLE001 - very old keyring
        _NoKeyringError = Exception  # type: ignore[assignment,misc]
    _KEYRING_AVAILABLE = True
except ImportError:
    _NoKeyringError = Exception  # type: ignore[assignment,misc]

_KEYRING_SERVICE = "cisco-ise-mcp"

# Records the reason the most recent keyring read failed (backend missing, locked,
# offline, etc.) so callers can distinguish "the keyring is unavailable" from
# "no password is stored". Set by ``_keyring_get``; consulted by the error paths.
_LAST_KEYRING_ERROR: Optional[str] = None

# Credential keys stored per deployment.
_CRED_ERS = "ise_password"
_CRED_DC = "dataconnect_password"

_REGISTRY_VERSION = 2

# Default Data Connect sub-config (non-secret).
#
# ``host`` is the node that serves Data Connect (the MnT / Monitoring persona).
# It is OPTIONAL: when blank, Data Connect falls back to the deployment's admin
# ``host`` (the PAN used for ERS/Open API) — so single-node deployments and any
# pre-existing registry keep working unchanged. Set it when the MnT node lives on
# a different IP/FQDN than the primary Admin node.
_DC_DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "host": "",
    "port": 2484,
    "sid": "cpm10",
    "user": "dataconnect",
    "mode": "thin",
    "cert_path": "",
    "wallet_path": "",
    "verify_ssl": True,
    "os_trust": False,
    "oracle_client_lib": "",
}

# Monitoring (MnT / "MAPI") is enabled per deployment. The flag is OPTIONAL in the
# registry: when the key is ABSENT a deployment is treated as ENABLED, so registries
# that predate this field keep MnT working unchanged. New deployments written by
# ``add_deployment`` set it explicitly (default off — opt-in).
def _monitoring_enabled(dep: dict) -> bool:
    return bool(dep.get("monitoring_enabled", True))

# Names that would collide with a numeric selector are forbidden.
_NUMERIC_NAME_RE = re.compile(r"^(?:deployment\s*)?#?\d+$", re.IGNORECASE)
# Selector like "1", "#2", "Deployment 3".
_NUM_SELECTOR_RE = re.compile(r"^(?:deployment\s*)?#?(\d+)$", re.IGNORECASE)


class ConfigError(ValueError):
    """Raised for deployment-config problems with an agent-friendly message."""


class ReslugRequired(ConfigError):
    """
    Raised when a rename would change a deployment's slug (its identity / keyring
    key) and the caller has not authorized that with reslug=True.

    Carries the old/new slug so the CLI can prompt and the agent can retry.
    """

    def __init__(self, old_slug: str, new_slug: str, new_name: str):
        self.old_slug = old_slug
        self.new_slug = new_slug
        self.new_name = new_name
        super().__init__(
            f"Renaming to '{new_name}' changes this deployment's identity (slug) from "
            f"'{old_slug}' to '{new_slug}', which also moves its stored credentials. "
            f"Re-run with --reslug (CLI) or reslug=true (agent) to confirm — or leave the "
            f"name unchanged to keep the current slug."
        )


# ---------------------------------------------------------------------------
# Home / registry path
# ---------------------------------------------------------------------------

def get_home() -> Path:
    """Return the per-user config directory (not auto-created here)."""
    override = os.environ.get("CISCO_ISE_MCP_HOME")
    if override:
        return Path(override).expanduser()
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "cisco-ise-mcp"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "cisco-ise-mcp"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "cisco-ise-mcp"


def get_registry_path() -> Path:
    """Path to ``deployments.json`` inside the config home."""
    return get_home() / "deployments.json"


def _load_env() -> None:
    """Load ``<config-home>/.env`` for env-var credential injection, if present.

    Restricted to the config home on purpose — unlike the dotenv default, we never
    read a ``.env`` from the current working directory.
    """
    if _load_dotenv is None:
        return
    env_path = get_home() / ".env"
    if env_path.is_file():
        _load_dotenv(dotenv_path=str(env_path))


_load_env()


# ---------------------------------------------------------------------------
# Slug / name helpers
# ---------------------------------------------------------------------------

def slugify(name: str) -> str:
    """Normalize a display name to a lowercase, hyphenated slug."""
    return re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")


def _slug_to_env(slug: str) -> str:
    """``radius-only`` -> ``RADIUS_ONLY`` for env-var namespacing."""
    return slug.replace("-", "_").upper()


# ---------------------------------------------------------------------------
# Secret-file reader (Docker/K8s ``*_FILE`` convention)
# ---------------------------------------------------------------------------

def _read_secret_file(path: str) -> Optional[str]:
    """Read a secret from a file; return the first stripped line or None."""
    if not path:
        return None
    try:
        p = Path(path)
        if p.is_file():
            return p.read_text().splitlines()[0].strip()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not read secret file %s: %s", path, exc)
    return None


# ---------------------------------------------------------------------------
# Registry load / save  (read fresh every call; write atomically)
# ---------------------------------------------------------------------------

def _empty_registry() -> dict:
    return {"version": _REGISTRY_VERSION, "default": None, "deployments": {}}


def load_registry() -> dict:
    """Load ``deployments.json`` fresh (no caching). Missing file -> empty registry."""
    path = get_registry_path()
    if not path.is_file():
        return _empty_registry()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"Registry file is corrupt ({path}): {exc}. "
            f"Fix the JSON or remove the file and re-add your deployments."
        ) from exc
    if not isinstance(data, dict) or "deployments" not in data:
        raise ConfigError(f"Registry file {path} is not a valid deployments registry.")
    data.setdefault("version", _REGISTRY_VERSION)
    data.setdefault("default", None)
    if not isinstance(data.get("deployments"), dict):
        raise ConfigError(f"Registry file {path}: 'deployments' must be an object.")
    return data


def save_registry(reg: dict) -> Path:
    """Write the registry atomically (tmp + os.replace); chmod 600 on POSIX."""
    path = get_registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not sys.platform.startswith("win"):
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".deployments.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(reg, fh, indent=2, sort_keys=False)
            fh.write("\n")
        if not sys.platform.startswith("win"):
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return path


def ensure_registry() -> Path:
    """
    Create a blank ``deployments.json`` if none exists yet, and return its path.

    Called on first launch (CLI and server entry points) so a new install always
    has a ready-to-configure registry file — NOT seeded with example deployments
    (see ``deployments.example.json`` for the structure). Existing files are left
    untouched.
    """
    path = get_registry_path()
    if not path.is_file():
        save_registry(_empty_registry())
    return path


# ---------------------------------------------------------------------------
# Keyring credentials (per deployment)
# ---------------------------------------------------------------------------

def _keyring_username(slug: str, key: str) -> str:
    return f"{slug}:{key}"


def _env_var_name(slug: str, key: str) -> str:
    return f"CISCO_ISE__{_slug_to_env(slug)}__{key.upper()}"


# Canonical, copy-pasteable form of a CLI command. The documented install runs
# the console script through uv (``uv run cisco-ise-mcp …``), so emitted "run
# this" hints use that prefix; a user in an activated venv can drop ``uv run``.
CLI_PREFIX = "uv run cisco-ise-mcp"


def cli_cmd(sub: str) -> str:
    """Return a full, runnable CLI command string, e.g. ``uv run cisco-ise-mcp test x``."""
    return f"{CLI_PREFIX} {sub}"


def set_credential(slug: str, key: str, value: str) -> None:
    """Store a per-deployment secret in the OS keyring."""
    if not _KEYRING_AVAILABLE:
        raise RuntimeError(
            "The 'keyring' package is not installed. Install it (pip install keyring) "
            f"or inject the secret via the env var {_env_var_name(slug, key)}."
        )
    try:
        _keyring.set_password(_KEYRING_SERVICE, _keyring_username(slug, key), value)
    except _NoKeyringError as exc:  # type: ignore[misc]
        raise RuntimeError(
            f"No usable OS keyring backend was found ({exc}). This is common on "
            f"headless Linux/containers. Inject the secret instead via the env var "
            f"{_env_var_name(slug, key)} (or {_env_var_name(slug, key)}_FILE)."
        ) from exc


def _keyring_get(slug: str, key: str) -> Optional[str]:
    """Best-effort keyring read; never raises.

    On any backend failure (no keyring, locked, offline cloud backend) it records
    the reason in ``_LAST_KEYRING_ERROR`` and returns None, so the caller can tell
    "keyring unavailable" apart from "no password stored".
    """
    global _LAST_KEYRING_ERROR
    if not _KEYRING_AVAILABLE:
        _LAST_KEYRING_ERROR = (
            "the 'keyring' package is not installed"
        )
        return None
    try:
        val = _keyring.get_password(_KEYRING_SERVICE, _keyring_username(slug, key))
        _LAST_KEYRING_ERROR = None
        return val
    except Exception as exc:  # noqa: BLE001
        _LAST_KEYRING_ERROR = f"{type(exc).__name__}: {exc}"
        logger.warning("Keyring lookup failed for '%s:%s': %s", slug, key, exc)
        return None


def delete_credentials(slug: str) -> None:
    """Best-effort removal of a deployment's secrets from the keyring."""
    if not _KEYRING_AVAILABLE:
        return
    for key in (_CRED_ERS, _CRED_DC):
        try:
            _keyring.delete_password(_KEYRING_SERVICE, _keyring_username(slug, key))
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Secret resolution:  env var -> *_FILE -> keyring -> (raise | None)
# ---------------------------------------------------------------------------

def _resolve_secret(slug: str, key: str) -> Optional[str]:
    env = _env_var_name(slug, key)
    val = os.environ.get(env)
    if val:
        return val
    file_val = _read_secret_file(os.environ.get(f"{env}_FILE", ""))
    if file_val:
        return file_val
    return _keyring_get(slug, key)


def _credential_hint(slug: str, key: str) -> str:
    flag = " --dataconnect" if key == _CRED_DC else ""
    env = _env_var_name(slug, key)
    return (
        f"Set it on a terminal with:\n"
        f"  {cli_cmd(f'set-credential {slug}{flag}')}\n"
        f"  (in an activated venv you can drop the 'uv run' prefix)\n"
        f"Headless/containers: export {env}=...  (or {env}_FILE=/path/to/secret)"
    )


def _get_deployment_secret(slug: str, key: str, name: str, required: bool = True) -> Optional[str]:
    val = _resolve_secret(slug, key)
    if val:
        return val
    if required:
        label = "Data Connect password" if key == _CRED_DC else "ERS/Open API password"
        msg = (
            f"{label} for deployment '{name}' (slug '{slug}') is not set.\n"
            + _credential_hint(slug, key)
        )
        if _LAST_KEYRING_ERROR:
            msg += (
                f"\nNOTE: the OS keyring could not be read ({_LAST_KEYRING_ERROR}); "
                f"a stored password (if any) is currently unreachable. Unlock the "
                f"keyring, or inject the secret via the env var above."
            )
        raise ConfigError(msg)
    return None


# ---------------------------------------------------------------------------
# Listing & selection
# ---------------------------------------------------------------------------

def _choices_str(reg: dict) -> str:
    deps = reg["deployments"]
    if not deps:
        return "  (no deployments configured)"
    default = reg.get("default")
    lines = ["Available deployments:"]
    for i, (slug, dep) in enumerate(deps.items(), 1):
        tag = "  [default]" if slug == default else ""
        lines.append(
            f"  {i}. {dep.get('name', slug)}  (slug: {slug}, host: {dep.get('host', '?')}){tag}"
        )
    return "\n".join(lines)


def list_deployments() -> list[dict]:
    """Return all configured deployments with stable 1-based numbers."""
    reg = load_registry()
    default = reg.get("default")
    out: list[dict] = []
    for i, (slug, dep) in enumerate(reg["deployments"].items(), 1):
        dc = {**_DC_DEFAULTS, **dep.get("dataconnect", {})}
        dc_host_explicit = (dc.get("host") or "").strip()
        out.append({
            "number": i,
            "slug": slug,
            "name": dep.get("name", slug),
            "host": dep.get("host", ""),
            "ers_username": dep.get("ers_username", ""),
            "ers_port": dep.get("ers_port", 443),
            "openapi_port": dep.get("openapi_port", 443),
            "verify_ssl": bool(dep.get("verify_ssl", True)),
            "ca_cert_path": (dep.get("ca_cert_path") or "").strip(),
            "is_default": slug == default,
            "dataconnect_enabled": bool(dc["enabled"]),
            "dataconnect_mode": dc["mode"],
            "dataconnect_host": dc_host_explicit or dep.get("host", ""),
            "dataconnect_host_explicit": bool(dc_host_explicit),
            "dataconnect_cert_path": dc["cert_path"],
            "dataconnect_os_trust": bool(dc["os_trust"]),
            "monitoring_enabled": _monitoring_enabled(dep),
            "has_ers_password": _resolve_secret(slug, _CRED_ERS) is not None,
            "has_dataconnect_password": (
                _resolve_secret(slug, _CRED_DC) is not None if dc["enabled"] else None
            ),
        })
    return out


def resolve_deployment(selector: Optional[str] = None) -> str:
    """Resolve a selector (None | number | 'Deployment N' | name | slug) to a slug."""
    reg = load_registry()
    deps = reg["deployments"]
    slugs = list(deps.keys())

    if selector is None or (isinstance(selector, str) and not selector.strip()):
        if len(slugs) == 1:
            return slugs[0]
        default = reg.get("default")
        if default and default in deps:
            return default
        if not slugs:
            raise ConfigError(
                "No ISE deployments are configured yet. Add one with the "
                "ise_add_deployment tool, or run `uv run cisco-ise-mcp add`."
            )
        raise ConfigError(
            "More than one deployment is configured — specify which one by name or "
            "number (e.g. 'RADIUS Only' or 'Deployment 1'), or set a default with "
            "ise_set_default_deployment.\n" + _choices_str(reg)
        )

    s = str(selector).strip()
    m = _NUM_SELECTOR_RE.match(s)
    if m:
        idx = int(m.group(1))
        if 1 <= idx <= len(slugs):
            return slugs[idx - 1]
        raise ConfigError(
            f"Deployment number {idx} is out of range (there are {len(slugs)}).\n"
            + _choices_str(reg)
        )

    low = s.lower()
    for slug, dep in deps.items():
        if str(dep.get("name", "")).strip().lower() == low:
            return slug
    for slug in slugs:
        if slug.lower() == low:
            return slug
    raise ConfigError(f"No deployment matches '{selector}'.\n" + _choices_str(reg))


# ---------------------------------------------------------------------------
# Handler-facing config  (same flat shape the 3 clients already consume)
# ---------------------------------------------------------------------------

def get_deployment_config(selector: Optional[str] = None, surface: Optional[str] = None) -> dict:
    """
    Resolve a deployment and return a flat config dict for the API clients.

    ``surface`` selects which password is required:
      * 'ers' / 'openapi' -> ise_password required (raises with fix guidance if unset)
      * 'dataconnect'     -> Data Connect must be enabled; dataconnect_password required
      * None              -> no secret is required (values may be None)
    """
    reg = load_registry()
    slug = resolve_deployment(selector)
    dep = reg["deployments"][slug]
    name = dep.get("name", slug)

    host = (dep.get("host") or "").strip()
    if not host:
        raise ConfigError(
            f"Deployment '{name}' (slug '{slug}') is missing the required field 'host'. "
            f"Re-add it or fix the registry at {get_registry_path()}."
        )

    dc = {**_DC_DEFAULTS, **dep.get("dataconnect", {})}
    cfg: dict[str, Any] = {
        "_slug": slug,
        "_name": name,
        "ise_host": host,
        "ise_ers_port": int(dep.get("ers_port", 443)),
        "ise_openapi_port": int(dep.get("openapi_port", 443)),
        "ise_username": dep.get("ers_username", ""),
        "verify_ssl": bool(dep.get("verify_ssl", True)),
        "ca_cert_path": (dep.get("ca_cert_path") or "").strip(),
        "monitoring_enabled": _monitoring_enabled(dep),
        "dataconnect_enabled": bool(dc["enabled"]),
        "dataconnect_host": (dc.get("host") or "").strip() or host,
        "dataconnect_port": int(dc["port"]),
        "dataconnect_sid": dc["sid"],
        "dataconnect_user": dc["user"],
        "dataconnect_mode": dc["mode"],
        "dataconnect_cert_path": dc["cert_path"],
        "dataconnect_wallet_path": dc["wallet_path"],
        "dataconnect_verify_ssl": bool(dc["verify_ssl"]),
        "dataconnect_os_trust": bool(dc["os_trust"]),
        "dataconnect_oracle_client_lib": dc["oracle_client_lib"],
    }

    if surface in ("ers", "openapi", "monitoring"):
        if surface == "monitoring" and not cfg["monitoring_enabled"]:
            raise ConfigError(
                f"The Monitoring API (MAPI / MnT) is disabled for deployment '{name}' "
                f"(slug '{slug}'), so ise_mnt_* tools cannot run against it.\n"
                f"Enable it with:\n"
                f"  {cli_cmd(f'update {slug} --enable-monitoring')}\n"
                f"  (agent: ise_update_deployment deployment='{slug}' monitoring_enabled=true)\n"
                f"Also ensure the ERS account is in the ISE 'MnT Admin' admin group."
            )
        if not cfg["ise_username"]:
            raise ConfigError(
                f"Deployment '{name}' (slug '{slug}') has no 'ers_username'. "
                f"Re-add it with a username or fix the registry at {get_registry_path()}."
            )
        cfg["ise_password"] = _get_deployment_secret(slug, _CRED_ERS, name, required=True)
    elif surface == "dataconnect":
        if not cfg["dataconnect_enabled"]:
            raise ConfigError(
                f"Data Connect is disabled for deployment '{name}' (slug '{slug}'). "
                f"Enable it in the registry to run reporting queries against it."
            )
        cfg["dataconnect_password"] = _get_deployment_secret(slug, _CRED_DC, name, required=True)
    else:
        cfg["ise_password"] = _resolve_secret(slug, _CRED_ERS)
        cfg["dataconnect_password"] = _resolve_secret(slug, _CRED_DC)

    return cfg


def get_config(selector: Optional[str] = None, surface: Optional[str] = None) -> dict:
    """Backward-compatible alias used by the tool handlers."""
    return get_deployment_config(selector, surface)


# ---------------------------------------------------------------------------
# Add / remove / default
# ---------------------------------------------------------------------------

def _as_port(value: Any, field: str, errors: list[str]) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        errors.append(f"{field} must be a whole number (got {value!r})")
        return None


def add_deployment(
    name: str,
    host: str,
    ers_username: str = "",
    ers_port: Any = 443,
    openapi_port: Any = 443,
    verify_ssl: bool = True,
    ca_cert_path: str = "",
    monitoring_enabled: bool = False,
    dataconnect_enabled: bool = True,
    dataconnect_host: str = "",
    dataconnect_port: Any = 2484,
    dataconnect_sid: str = "cpm10",
    dataconnect_user: str = "dataconnect",
    dataconnect_mode: str = "thin",
    dataconnect_cert_path: str = "",
    dataconnect_wallet_path: str = "",
    dataconnect_verify_ssl: bool = True,
    dataconnect_os_trust: bool = False,
    dataconnect_oracle_client_lib: str = "",
    make_default: Optional[bool] = None,
) -> dict:
    """Validate and persist a new deployment (non-secret fields only)."""
    errors: list[str] = []
    name = (name or "").strip()
    host = (host or "").strip()
    if not name:
        errors.append("name — a descriptive label, e.g. 'RADIUS Only'")
    elif _NUMERIC_NAME_RE.match(name):
        errors.append(
            "name must not be a bare number or 'Deployment N' (those are reserved for "
            "selecting by number) — choose a descriptive name like 'RADIUS Only'"
        )
    if not host:
        errors.append("host — the ISE admin-node IP or FQDN, e.g. 10.1.1.1")
    mode = (dataconnect_mode or "thin").lower()
    if mode not in ("thin", "thick"):
        errors.append("dataconnect_mode must be 'thin' or 'thick'")
    ca_cert_path = (ca_cert_path or "").strip()
    if ca_cert_path and not os.path.isfile(ca_cert_path):
        errors.append(
            f"ca_cert_path — no readable file at {ca_cert_path!r}. Point it at the "
            "exported ISE root-CA (PEM), or omit it to use the system/certifi store."
        )
    ep = _as_port(ers_port, "ers_port", errors)
    op = _as_port(openapi_port, "openapi_port", errors)
    dp = _as_port(dataconnect_port, "dataconnect_port", errors)
    if errors:
        raise ConfigError(
            "Cannot add the deployment — please provide/fix:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    slug = slugify(name)
    if not slug:
        raise ConfigError("The name must contain letters or numbers to form an identifier.")
    reg = load_registry()
    if slug in reg["deployments"]:
        raise ConfigError(
            f"A deployment named '{name}' (slug '{slug}') already exists. Remove it first "
            f"with ise_remove_deployment, or choose a different name."
        )

    reg["deployments"][slug] = {
        "name": name,
        "host": host,
        "ers_username": ers_username or "",
        "ers_port": ep,
        "openapi_port": op,
        "verify_ssl": bool(verify_ssl),
        "ca_cert_path": ca_cert_path,
        "monitoring_enabled": bool(monitoring_enabled),
        "dataconnect": {
            "enabled": bool(dataconnect_enabled),
            "host": (dataconnect_host or "").strip(),
            "port": dp,
            "sid": dataconnect_sid or "cpm10",
            "user": dataconnect_user or "dataconnect",
            "mode": mode,
            "cert_path": dataconnect_cert_path or "",
            "wallet_path": dataconnect_wallet_path or "",
            "verify_ssl": bool(dataconnect_verify_ssl),
            "os_trust": bool(dataconnect_os_trust),
            "oracle_client_lib": dataconnect_oracle_client_lib or "",
        },
    }
    if make_default or (make_default is None and len(reg["deployments"]) == 1):
        reg["default"] = slug
    save_registry(reg)

    warnings: list[str] = []
    if not verify_ssl:
        warnings.append(
            "TLS verification is OFF for this deployment's ERS/Open API/Monitoring "
            "connection (verify_ssl=false). Admin credentials are sent over a "
            "connection whose certificate is NOT validated — an on-path attacker can "
            "intercept them. Prefer keeping verify_ssl on and, for a private ISE CA, "
            "setting ca_cert_path to the exported root-CA PEM (httpx uses only the "
            "public certifi bundle otherwise — it never reads the OS/Keychain trust "
            f"store). Re-enable with: {cli_cmd(f'update {slug} --verify-ssl')}."
        )
    if (dataconnect_enabled and not dataconnect_os_trust
            and not dataconnect_cert_path and not dataconnect_wallet_path):
        warnings.append(
            "Data Connect is enabled but no cert_path/wallet_path was given and OS trust "
            "is off. Data Connect (reporting) queries will fail until you set one. Export "
            "the ISE Data Connect certificate and re-add with a cert path, enable os_trust "
            "for a CA-signed cert, or edit the registry."
        )
    fix_commands = [cli_cmd(f"set-credential {slug}")]
    if dataconnect_enabled:
        fix_commands.append(cli_cmd(f"set-credential {slug} --dataconnect"))
    number = list(reg["deployments"]).index(slug) + 1
    return {
        "status": "added",
        "slug": slug,
        "name": name,
        "number": number,
        "is_default": reg.get("default") == slug,
        "registry_path": str(get_registry_path()),
        "next_steps": (
            "Set the password(s) on a terminal — they are stored in the OS keyring and "
            "are NEVER shared with the AI agent:"
        ),
        "fix_commands": fix_commands,
        "warnings": warnings,
    }


def _migrate_credentials(old_slug: str, new_slug: str) -> list[str]:
    """
    Move a deployment's stored secrets from ``old_slug`` to ``new_slug`` when its
    slug changes (reslug). Keyring entries are copied then deleted. Env-var/secret-
    file secrets live outside our control, so we can only warn about those.

    Best-effort: never raises; returns a list of human-readable warnings.
    """
    warnings: list[str] = []
    moved_any = False
    for key in (_CRED_ERS, _CRED_DC):
        env = _env_var_name(old_slug, key)
        if os.environ.get(env) or os.environ.get(f"{env}_FILE"):
            warnings.append(
                f"{key}: secret is provided via env var '{env}' and was NOT migrated — "
                f"rename it to '{_env_var_name(new_slug, key)}'."
            )
            continue
        val = _keyring_get(old_slug, key)
        if val is None:
            continue
        try:
            set_credential(new_slug, key, val)
            moved_any = True
        except RuntimeError as exc:  # no keyring backend
            warnings.append(f"{key}: could not move to '{new_slug}' ({exc}). Re-set it with set-credential.")
    if moved_any:
        delete_credentials(old_slug)
    return warnings


def _reslug_registry(reg: dict, old_slug: str, new_slug: str, new_name: str) -> None:
    """Rename a deployment's key in-place, preserving insertion order (numbering)."""
    rebuilt: dict[str, Any] = {}
    for k, v in reg["deployments"].items():
        if k == old_slug:
            v["name"] = new_name
            rebuilt[new_slug] = v
        else:
            rebuilt[k] = v
    reg["deployments"] = rebuilt
    if reg.get("default") == old_slug:
        reg["default"] = new_slug


def update_deployment(selector: str, reslug: bool = False, **fields: Any) -> dict:
    """
    Patch ONLY the provided non-secret fields of an existing deployment.

    Pass any subset of: name, host, ers_username, ers_port, openapi_port,
    verify_ssl, dataconnect_enabled, dataconnect_port, dataconnect_sid,
    dataconnect_user, dataconnect_mode, dataconnect_cert_path,
    dataconnect_wallet_path, dataconnect_verify_ssl,
    dataconnect_oracle_client_lib. Fields that are not passed are left untouched.

    Renaming (``name``): if the new name produces the SAME slug (e.g. only case or
    punctuation differs), only the display label changes. If it produces a
    DIFFERENT slug, that changes the deployment's identity and moves its stored
    credentials — which requires ``reslug=True``; otherwise ``ReslugRequired`` is
    raised so the caller can confirm. Passwords are never set here (use
    ``set_credential``).

    Returns the ``validate_deployment`` summary plus ``status`` and ``changed``
    (and ``warnings`` / ``previous_slug`` on a reslug). Raises ``ConfigError``
    (listing every problem) on an unknown deployment or invalid value.
    """
    slug = resolve_deployment(selector)  # raises ConfigError with choices if not found
    reg = load_registry()
    dep = reg["deployments"][slug]
    dc = {**_DC_DEFAULTS, **dep.get("dataconnect", {})}

    _TOP_STR = {"host", "ers_username"}
    _TOP_PORT = {"ers_port": "ers_port", "openapi_port": "openapi_port"}
    _DC_STR = {
        "dataconnect_host": ("host", ""),
        "dataconnect_sid": ("sid", "cpm10"),
        "dataconnect_user": ("user", "dataconnect"),
        "dataconnect_cert_path": ("cert_path", ""),
        "dataconnect_wallet_path": ("wallet_path", ""),
        "dataconnect_oracle_client_lib": ("oracle_client_lib", ""),
    }
    _KNOWN = ({"name", "verify_ssl", "ca_cert_path", "monitoring_enabled",
               "dataconnect_enabled", "dataconnect_port", "dataconnect_mode",
               "dataconnect_verify_ssl", "dataconnect_os_trust"}
              | _TOP_STR | set(_TOP_PORT) | set(_DC_STR))
    unknown = [k for k in fields if k not in _KNOWN]
    if unknown:
        raise ConfigError(f"Unknown field(s): {', '.join(sorted(unknown))}. Allowed: {', '.join(sorted(_KNOWN))}.")

    errors: list[str] = []
    changed: list[str] = []
    dc_changed = False

    def _set_top(key: str, value: Any) -> None:
        if dep.get(key) != value:
            dep[key] = value
            changed.append(key)

    def _set_dc(key: str, value: Any) -> None:
        nonlocal dc_changed
        if dc.get(key) != value:
            dc[key] = value
            changed.append(f"dataconnect.{key}")
            dc_changed = True

    # name (validated here, applied last so reslug can gate a slug change)
    new_name: Optional[str] = None
    new_slug = slug
    if "name" in fields:
        candidate = (fields["name"] or "").strip()
        if not candidate:
            errors.append("name cannot be empty")
        elif _NUMERIC_NAME_RE.match(candidate):
            errors.append("name must not be a bare number or 'Deployment N' (reserved for numeric selection)")
        else:
            cand_slug = slugify(candidate)
            if cand_slug != slug and cand_slug in reg["deployments"]:
                errors.append(f"another deployment already uses the name '{candidate}' (slug '{cand_slug}')")
            else:
                new_name = candidate
                new_slug = cand_slug

    # top-level strings
    for key in _TOP_STR:
        if key in fields:
            val = (fields[key] or "").strip()
            if key == "host" and not val:
                errors.append("host cannot be empty")
            else:
                _set_top(key, val)

    # top-level ports
    for key in _TOP_PORT:
        if key in fields:
            p = _as_port(fields[key], key, errors)
            if p is not None:
                _set_top(key, p)

    # top-level bool
    if "verify_ssl" in fields:
        _set_top("verify_ssl", bool(fields["verify_ssl"]))
    if "monitoring_enabled" in fields:
        _set_top("monitoring_enabled", bool(fields["monitoring_enabled"]))

    # ERS/Open API CA bundle (empty string clears → falls back to certifi store)
    if "ca_cert_path" in fields:
        val = (fields["ca_cert_path"] or "").strip()
        if val and not os.path.isfile(val):
            errors.append(
                f"ca_cert_path — no readable file at {val!r}. Point it at the exported "
                "ISE root-CA (PEM), or pass '' to clear it."
            )
        else:
            _set_top("ca_cert_path", val)

    # dataconnect bools / port / mode
    if "dataconnect_enabled" in fields:
        _set_dc("enabled", bool(fields["dataconnect_enabled"]))
    if "dataconnect_verify_ssl" in fields:
        _set_dc("verify_ssl", bool(fields["dataconnect_verify_ssl"]))
    if "dataconnect_os_trust" in fields:
        _set_dc("os_trust", bool(fields["dataconnect_os_trust"]))
    if "dataconnect_port" in fields:
        p = _as_port(fields["dataconnect_port"], "dataconnect_port", errors)
        if p is not None:
            _set_dc("port", p)
    if "dataconnect_mode" in fields:
        mode = (fields["dataconnect_mode"] or "thin").lower()
        if mode not in ("thin", "thick"):
            errors.append("dataconnect_mode must be 'thin' or 'thick'")
        else:
            _set_dc("mode", mode)

    # dataconnect strings (empty string clears the value)
    for fkey, (dkey, default) in _DC_STR.items():
        if fkey in fields:
            val = fields[fkey]
            val = default if val is None else str(val)
            _set_dc(dkey, val)

    if errors:
        raise ConfigError(
            "Cannot update the deployment — please fix:\n" + "\n".join(f"  - {e}" for e in errors)
        )

    if dc_changed:
        dep["dataconnect"] = dc

    # Apply the rename last so a slug change can be gated behind reslug.
    warnings: list[str] = []
    final_slug = slug
    if new_name is not None:
        if new_slug == slug:
            # Same slug -> label-only change; identity and credentials untouched.
            if dep.get("name") != new_name:
                dep["name"] = new_name
                changed.append("name")
        else:
            if not reslug:
                raise ReslugRequired(slug, new_slug, new_name)
            warnings = _migrate_credentials(slug, new_slug)
            _reslug_registry(reg, slug, new_slug, new_name)
            final_slug = new_slug
            changed.extend(["name", "slug"])

    if changed:
        save_registry(reg)

    result = validate_deployment(final_slug)
    result["status"] = "updated" if changed else "unchanged"
    result["changed"] = changed
    result["registry_path"] = str(get_registry_path())
    if final_slug != slug:
        result["previous_slug"] = slug
    if warnings:
        result["warnings"] = warnings + result.get("warnings", [])
    return result


def remove_deployment(selector: str, confirm: bool = False) -> dict:
    """Remove a deployment and (best-effort) its keyring secrets."""
    slug = resolve_deployment(selector)
    reg = load_registry()
    name = reg["deployments"][slug].get("name", slug)
    if not confirm:
        raise ConfigError(
            f"Refusing to remove deployment '{name}' (slug '{slug}') without confirmation. "
            f"Pass confirm=true (agent) or --yes (CLI)."
        )
    del reg["deployments"][slug]
    if reg.get("default") == slug:
        reg["default"] = next(iter(reg["deployments"]), None)
    save_registry(reg)
    delete_credentials(slug)
    return {"status": "removed", "slug": slug, "name": name, "new_default": reg.get("default")}


def set_default(selector: str) -> dict:
    slug = resolve_deployment(selector)
    reg = load_registry()
    reg["default"] = slug
    save_registry(reg)
    return {"status": "default_set", "default": slug, "name": reg["deployments"][slug].get("name", slug)}


def get_default() -> Optional[str]:
    return load_registry().get("default")


def get_note() -> Optional[str]:
    """Optional human note stored at the top of the registry (e.g. 'these are examples')."""
    note = load_registry().get("_comment")
    return note or None


# ---------------------------------------------------------------------------
# Non-raising validation (powers ise_test_deployment + `cisco-ise-mcp test`)
# ---------------------------------------------------------------------------

def validate_deployment(selector: Optional[str] = None) -> dict:
    """Aggregate ALL missing fields/credentials for a deployment (never raises)."""
    try:
        slug = resolve_deployment(selector)
    except ConfigError as exc:
        return {"ok": False, "error": str(exc)}
    reg = load_registry()
    dep = reg["deployments"][slug]
    name = dep.get("name", slug)
    dc = {**_DC_DEFAULTS, **dep.get("dataconnect", {})}

    missing_fields: list[str] = []
    if not (dep.get("host") or "").strip():
        missing_fields.append("host")
    if not dep.get("ers_username"):
        missing_fields.append("ers_username")

    missing_credentials: list[str] = []
    fix_commands: list[str] = []
    if _resolve_secret(slug, _CRED_ERS) is None:
        missing_credentials.append("ise_password (ERS / Open API)")
        fix_commands.append(cli_cmd(f"set-credential {slug}"))
    if dc["enabled"]:
        if not dc.get("os_trust") and not (dc["cert_path"] or dc["wallet_path"]):
            missing_fields.append(
                "dataconnect.cert_path or dataconnect.wallet_path "
                "(or enable dataconnect.os_trust for a CA-signed cert)")
        if _resolve_secret(slug, _CRED_DC) is None:
            missing_credentials.append("dataconnect_password")
            fix_commands.append(cli_cmd(f"set-credential {slug} --dataconnect"))

    number = list(reg["deployments"]).index(slug) + 1
    dc_host_explicit = (dc.get("host") or "").strip()

    warnings: list[str] = []
    if not bool(dep.get("verify_ssl", True)):
        warnings.append(
            "verify_ssl is OFF — ERS/Open API/Monitoring admin credentials are sent "
            f"over an unvalidated TLS connection (MITM risk). Fix: {cli_cmd(f'update {slug} --verify-ssl')}"
        )
    if dc["enabled"] and not bool(dc.get("verify_ssl", True)):
        warnings.append(
            "Data Connect verify_ssl is OFF — the reporting DB password is sent over an "
            f"unvalidated TLS connection. Fix: {cli_cmd(f'update {slug} --dc-verify')}"
        )

    return {
        "ok": not missing_fields and not missing_credentials,
        "slug": slug,
        "name": name,
        "number": number,
        "host": dep.get("host", ""),
        "verify_ssl": bool(dep.get("verify_ssl", True)),
        "ca_cert_path": (dep.get("ca_cert_path") or "").strip(),
        "is_default": reg.get("default") == slug,
        "monitoring_enabled": _monitoring_enabled(dep),
        "dataconnect_enabled": bool(dc["enabled"]),
        "dataconnect_host": dc_host_explicit or dep.get("host", ""),
        "dataconnect_host_explicit": bool(dc_host_explicit),
        "dataconnect_os_trust": bool(dc["os_trust"]),
        "missing_fields": missing_fields,
        "missing_credentials": missing_credentials,
        "fix_commands": fix_commands,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Tool-schema injection (shared by every ERS / Open API / Data Connect tool)
# ---------------------------------------------------------------------------

DEPLOYMENT_PROP: dict[str, Any] = {
    "type": "string",
    "description": (
        "Target ISE deployment: name ('RADIUS Only'), slug ('radius-only'), or number "
        "('1' or 'Deployment 1'). Omit to use the only/default deployment. "
        "Call ise_list_deployments to see the choices."
    ),
}


def with_deployment(tool: Tool) -> Tool:
    """Return a copy of ``tool`` with an optional ``deployment`` property added."""
    schema = compat.tool_input_schema(tool)
    props = dict(schema.get("properties", {}))
    if "deployment" not in props:
        props["deployment"] = DEPLOYMENT_PROP
    return Tool(
        name=tool.name,
        description=tool.description,
        inputSchema={**schema, "properties": props},
    )


__all__ = [
    "ConfigError",
    "ReslugRequired",
    "get_home", "get_registry_path",
    "load_registry", "save_registry", "ensure_registry", "slugify",
    "list_deployments", "resolve_deployment",
    "get_deployment_config", "get_config",
    "add_deployment", "update_deployment", "remove_deployment", "set_default", "get_default", "get_note",
    "set_credential", "delete_credentials", "validate_deployment",
    "DEPLOYMENT_PROP", "with_deployment",
]
