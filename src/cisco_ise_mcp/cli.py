"""
Command-line interface for the Cisco ISE MCP server.

Running ``cisco-ise-mcp`` with NO subcommand starts the stdio MCP server (this is
what an MCP client launches), emitting nothing on stdout before the handshake.
The other subcommands are for humans on a terminal. With a `uv` install, prefix
each with ``uv run`` (e.g. ``uv run cisco-ise-mcp list``); in an activated
virtualenv you can run the bare ``cisco-ise-mcp`` form shown below:

  cisco-ise-mcp serve                       start the MCP server (default)
  cisco-ise-mcp list                        list configured deployments
  cisco-ise-mcp add --name "RADIUS Only" --host 10.1.1.1 ...
  cisco-ise-mcp update <name> [--host ... --enable-dataconnect --dc-cert ...]
  cisco-ise-mcp set-credential <name> [--dataconnect]   store a password (getpass)
  cisco-ise-mcp set-default <name>          choose the default deployment
  cisco-ise-mcp test <name> [--no-probe]    check config/credentials (+ live probe)
  cisco-ise-mcp remove <name> [--yes]       remove a deployment
  cisco-ise-mcp validate                    offline health check of ALL deployments
  cisco-ise-mcp refresh [-- ...]            download API specs + rebuild tool catalogs

Passwords are only ever entered here (getpass), never through the AI agent.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import subprocess
import sys
from pathlib import Path

from cisco_ise_mcp import config


def _out(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _err(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 1


def _prompt_yn(question: str, default: bool = False) -> bool:
    """Yes/no prompt (used by the guided `add` flow). Empty input -> default."""
    ans = input(f"{question}{' [Y/n] ' if default else ' [y/N] '}").strip().lower()
    if not ans:
        return default
    return ans in ("y", "yes")


def _prompt_str(question: str, default: str = "") -> str:
    return input(question).strip() or default


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_serve(_args) -> int:
    # Prompt to build the catalogs if any are missing (stdout stays MCP-clean).
    try:
        from cisco_ise_mcp import catalog
        missing = catalog.missing_catalogs()
        if missing:
            print(f"[cisco-ise-mcp] Missing tool catalog(s): {', '.join(missing)}.\n"
                  f"  Build them with:  uv run python scripts/refresh_catalog.py\n"
                  f"  (or:  {config.cli_cmd('refresh')})", file=sys.stderr)
    except Exception:  # noqa: BLE001 — never block serve on the hint
        pass
    from cisco_ise_mcp.server import main as serve_main
    serve_main()
    return 0


def _find_refresh_script() -> Path | None:
    """Locate scripts/refresh_catalog.py (project checkout); None if not found."""
    here = Path(__file__).resolve()
    candidates = [
        Path.cwd() / "scripts" / "refresh_catalog.py",
        here.parents[2] / "scripts" / "refresh_catalog.py",  # src/cisco_ise_mcp/cli.py -> repo root
    ]
    return next((c for c in candidates if c.is_file()), None)


def cmd_refresh(args) -> int:
    """Download the API specs (via links.yaml) and rebuild the tool catalogs."""
    script = _find_refresh_script()
    if script is None:
        return _err(
            "Could not locate scripts/refresh_catalog.py. Run the refresh from a project "
            "checkout:\n  uv run python scripts/refresh_catalog.py")
    forward: list[str] = []
    if args.no_download:
        forward.append("--no-download")
    if args.no_network:
        forward.append("--no-network")
    if args.diff_only:
        forward.append("--diff-only")
    if getattr(args, "all_surfaces", False):
        forward.append("--all")
    if args.only:
        forward += ["--only", args.only]
    print(f"Running {script} {' '.join(forward)}".rstrip() + " ...")
    return subprocess.call([sys.executable, str(script), *forward])


def cmd_list(_args) -> int:
    deps = config.list_deployments()
    default = config.get_default()
    note = config.get_note()
    if not deps:
        print("No deployments configured yet.")
        print("Add one with:  uv run cisco-ise-mcp add --name \"RADIUS Only\" --host 10.1.1.1")
        print(f"Registry file: {config.get_registry_path()}")
        print("See deployments.example.json (in the project) for the file structure.")
        return 0
    if note:
        print(f"NOTE: {note}\n")
    print(f"Configured ISE deployments (registry: {config.get_registry_path()}):\n")
    for d in deps:
        star = " *default" if d["is_default"] else ""
        ers = "set" if d["has_ers_password"] else "MISSING"
        if d["dataconnect_enabled"]:
            dc = "set" if d["has_dataconnect_password"] else "MISSING"
        else:
            dc = "disabled"
        mapi = "enabled" if d["monitoring_enabled"] else "disabled"
        print(f"  {d['number']}. {d['name']}  ({d['slug']}){star}")
        print(f"     host={d['host']}  ers_user={d['ers_username'] or '-'}  "
              f"ers_pw={ers}  dataconnect_pw={dc}  mapi={mapi}")
        if d["dataconnect_enabled"] and d.get("dataconnect_os_trust"):
            print("     dataconnect: OS trust store (CA-signed, no cert file)")
        if d.get("dataconnect_host_explicit"):
            print(f"     dataconnect_host={d['dataconnect_host']}  (separate MnT node)")
    print(f"\nDefault: {default or '(none — specify a deployment per call)'}")
    return 0


def cmd_set_default(args) -> int:
    try:
        res = config.set_default(args.deployment)
    except config.ConfigError as exc:
        return _err(str(exc))
    print(f"Default deployment is now '{res['name']}' (slug '{res['default']}').")
    return 0


def cmd_remove(args) -> int:
    try:
        slug = config.resolve_deployment(args.deployment)
    except config.ConfigError as exc:
        return _err(str(exc))
    if not args.yes:
        if not sys.stdin.isatty():
            return _err("Refusing to remove without --yes (no interactive terminal).")
        ans = input(f"Remove deployment '{slug}' and its stored credentials? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 0
    res = config.remove_deployment(slug, confirm=True)
    print(f"Removed '{res['name']}' (slug '{res['slug']}'). New default: {res['new_default'] or '(none)'}.")
    return 0


def cmd_validate(_args) -> int:
    deps = config.list_deployments()
    if not deps:
        print("No deployments to validate. Add one with `uv run cisco-ise-mcp add`.")
        return 0
    any_bad = False
    for d in deps:
        v = config.validate_deployment(d["slug"])
        status = "OK" if v["ok"] else "INCOMPLETE"
        if not v["ok"]:
            any_bad = True
        print(f"[{status}] {d['number']}. {d['name']} ({d['slug']})")
        for f in v.get("missing_fields", []):
            print(f"    missing field: {f}")
        for c in v.get("missing_credentials", []):
            print(f"    missing credential: {c}")
        for w in v.get("warnings", []):
            print(f"    warning: {w}")
        for fix in v.get("fix_commands", []):
            print(f"    fix: {fix}")
    return 1 if any_bad else 0


def cmd_add(args) -> int:
    name, host = args.name, args.host
    interactive = sys.stdin.isatty()
    if interactive:
        if not name:
            name = input("Deployment name (e.g. 'RADIUS Only'): ").strip()
        if not host:
            host = input("ISE admin host / IP (e.g. 10.1.1.1): ").strip()

    # Data Connect — explicit flags win; otherwise guide the user on a TTY.
    dc_enabled = not args.no_dataconnect
    dc_host, dc_cert, dc_os_trust = args.dc_host, args.dc_cert, args.dc_os_trust
    dc_detail_given = bool(args.dc_host or args.dc_cert or args.dc_wallet or args.dc_os_trust)
    if interactive and not args.no_dataconnect and not dc_detail_given:
        dc_enabled = _prompt_yn(
            "Enable Data Connect (the read-only reporting database)?", default=True)
        if dc_enabled:
            if _prompt_yn("Does Data Connect run on a SEPARATE Monitoring (MnT) node "
                          "(a different IP/FQDN than the admin host)?", default=False):
                dc_host = _prompt_str("  MnT node IP / FQDN for Data Connect: ")
            kind = ""
            while kind not in ("self-signed", "self", "ca", "ca-signed"):
                kind = _prompt_str(
                    "  Is the Data Connect certificate self-signed or CA-signed? "
                    "[self-signed/ca]: ").lower()
            if kind in ("ca", "ca-signed"):
                choice = ""
                while choice not in ("os", "file"):
                    choice = _prompt_str(
                        "  Trust via the OS CA store, or a downloaded root-CA file? "
                        "[os/file]: ").lower()
                if choice == "os":
                    dc_os_trust = True
                else:
                    dc_cert = _prompt_str("  Path to the exported root-CA .pem: ")
            else:
                print("  Export the Data Connect certificate from ISE (Administration > System > "
                      "Certificates) and save it as a .pem first.")
                dc_cert = _prompt_str("  Path to the exported Data Connect .pem: ")

    # Monitoring (MAPI / MnT) — opt-in. Flag wins; otherwise ask on a TTY.
    monitoring_enabled = bool(args.enable_monitoring)
    if interactive and not args.enable_monitoring:
        monitoring_enabled = _prompt_yn(
            "Enable the Monitor API (MAPI / MnT)? It requires the ERS account to be in "
            "ISE's 'MnT Admin' admin group.", default=False)

    try:
        res = config.add_deployment(
            name=name or "", host=host or "",
            ers_username=args.ers_username,
            ers_port=args.ers_port, openapi_port=args.openapi_port,
            verify_ssl=args.verify_ssl,
            ca_cert_path=args.ca_cert or "",
            monitoring_enabled=monitoring_enabled,
            dataconnect_enabled=dc_enabled,
            dataconnect_host=dc_host,
            dataconnect_port=args.dc_port, dataconnect_sid=args.dc_sid,
            dataconnect_user=args.dc_user, dataconnect_mode=args.dc_mode,
            dataconnect_cert_path=dc_cert, dataconnect_wallet_path=args.dc_wallet,
            dataconnect_verify_ssl=not args.dc_no_verify,
            dataconnect_os_trust=dc_os_trust,
            dataconnect_oracle_client_lib=args.dc_oracle_lib,
            make_default=args.default or None,
        )
    except config.ConfigError as exc:
        return _err(str(exc))
    print(f"Added deployment {res['number']}. {res['name']} (slug '{res['slug']}').")
    for w in res.get("warnings", []):
        print(f"  warning: {w}")
    print("\nNext — set the password(s) (stored in the OS keyring, never shared with the agent):")
    for c in res["fix_commands"]:
        print(f"  {c}")
    return 0


def cmd_update(args) -> int:
    # Map CLI attr -> config.update_deployment kwarg. Only attrs that are not
    # None (i.e. the user actually passed the flag) are forwarded, so unspecified
    # fields stay untouched.
    mapping = [
        ("name", "name"), ("host", "host"), ("ers_username", "ers_username"),
        ("ers_port", "ers_port"), ("openapi_port", "openapi_port"),
        ("verify_ssl", "verify_ssl"),
        ("ca_cert", "ca_cert_path"),
        ("monitoring_enabled", "monitoring_enabled"),
        ("dataconnect_enabled", "dataconnect_enabled"),
        ("dc_host", "dataconnect_host"),
        ("dc_port", "dataconnect_port"), ("dc_sid", "dataconnect_sid"),
        ("dc_user", "dataconnect_user"), ("dc_mode", "dataconnect_mode"),
        ("dc_cert", "dataconnect_cert_path"), ("dc_wallet", "dataconnect_wallet_path"),
        ("dataconnect_verify_ssl", "dataconnect_verify_ssl"),
        ("dataconnect_os_trust", "dataconnect_os_trust"),
        ("dc_oracle_lib", "dataconnect_oracle_client_lib"),
    ]
    fields = {kw: getattr(args, attr) for attr, kw in mapping if getattr(args, attr, None) is not None}
    if not fields:
        return _err("Nothing to update. Pass at least one field, "
                    "e.g. --host 10.2.1.5, --enable-dataconnect, or --dc-cert /path/to.pem.")
    try:
        res = config.update_deployment(args.deployment, reslug=args.reslug, **fields)
    except config.ReslugRequired as exc:
        # Renaming would change the slug (identity) + migrate credentials.
        if not sys.stdin.isatty():
            print(str(exc), file=sys.stderr)
            return _err("Re-run with --reslug to authorize the slug change (no interactive terminal).")
        print(str(exc))
        ans = input(f"Proceed and migrate slug '{exc.old_slug}' -> '{exc.new_slug}' "
                    f"(and its stored credentials)? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborted. No changes made.")
            return 0
        try:
            res = config.update_deployment(args.deployment, reslug=True, **fields)
        except config.ConfigError as exc2:
            return _err(str(exc2))
    except config.ConfigError as exc:
        return _err(str(exc))
    if res["changed"]:
        print(f"Updated {res['number']}. {res['name']} (slug '{res['slug']}'). "
              f"Changed: {', '.join(res['changed'])}.")
        if res.get("previous_slug"):
            print(f"  slug changed: '{res['previous_slug']}' -> '{res['slug']}' "
                  f"(stored credentials migrated).")
        for w in res.get("warnings", []):
            print(f"  warning: {w}")
    else:
        print(f"No changes — every value you passed already matched '{res['slug']}'.")
    for f in res.get("missing_fields", []):
        print(f"  still missing field: {f}")
    for c in res.get("missing_credentials", []):
        print(f"  still missing credential: {c}")
    for fix in res.get("fix_commands", []):
        print(f"  fix: {fix}")
    print(f"\nVerify with:  {config.cli_cmd('test ' + res['slug'])}")
    return 0


def cmd_set_credential(args) -> int:
    try:
        slug = config.resolve_deployment(args.deployment)
    except config.ConfigError as exc:
        return _err(str(exc))
    key = "dataconnect_password" if args.dataconnect else "ise_password"
    label = "Data Connect" if args.dataconnect else "ERS/Open API"
    if not sys.stdin.isatty():
        return _err("set-credential needs an interactive terminal (it uses a hidden prompt). "
                    "On headless hosts inject the secret via an env var instead "
                    "(see docs/USER_GUIDE.md > Environment variables).")
    pw = getpass.getpass(f"{label} password for '{slug}': ")
    if not pw:
        return _err("No password entered; aborted.")
    if getpass.getpass("Re-enter to confirm: ") != pw:
        return _err("Passwords did not match; aborted.")
    try:
        config.set_credential(slug, key, pw)
    except RuntimeError as exc:
        return _err(str(exc))
    from cisco_ise_mcp import audit
    audit.record("cli_set_credential", {"key": key}, deployment=slug, status="ok")
    print(f"Stored the {label} password for '{slug}' in the OS keyring.")
    return 0


def cmd_test(args) -> int:
    from cisco_ise_mcp import server as _server
    data = asyncio.run(_server._test_deployment(
        {"deployment": args.deployment, "probe": not args.no_probe}))
    _out(data)
    return 0 if data.get("ok") else 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cisco-ise-mcp",
        description="Cisco ISE MCP server and multi-deployment manager.")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("serve", help="Start the stdio MCP server (default).").set_defaults(func=cmd_serve)
    sub.add_parser("list", help="List configured deployments.").set_defaults(func=cmd_list)

    p = sub.add_parser("add", help="Add a deployment (non-secret fields only).")
    p.add_argument("--name", help="Descriptive label, e.g. 'RADIUS Only'.")
    p.add_argument("--host", help="ISE admin-node IP or FQDN, e.g. 10.1.1.1.")
    p.add_argument("--ers-username", default="", help="ERS/Open API admin username.")
    p.add_argument("--ers-port", type=int, default=443)
    p.add_argument("--openapi-port", type=int, default=443)
    g_add_v = p.add_mutually_exclusive_group()
    g_add_v.add_argument("--verify-ssl", dest="verify_ssl", action="store_true", default=True,
                         help="Verify the ISE admin TLS certificate (default).")
    g_add_v.add_argument("--no-verify-ssl", dest="verify_ssl", action="store_false",
                         help="Do NOT verify the ISE admin TLS certificate (insecure; labs only — "
                              "admin credentials are exposed to MITM).")
    p.add_argument("--ca-cert", dest="ca_cert", default="", metavar="PEM",
                   help="Path to a PEM CA bundle to trust for ERS/Open API/Monitoring TLS. Use with "
                        "verify-ssl when ISE uses a private/internal CA: the HTTP client trusts only "
                        "the built-in certifi roots and never the OS/Keychain store, so a private CA "
                        "must be supplied here. Point it at the exported ISE root CA (Base64/PEM).")
    p.add_argument("--enable-monitoring", action="store_true",
                   help="Enable the Monitoring API (MAPI/MnT) for this deployment (opt-in; the ERS "
                        "account must be in ISE's 'MnT Admin' group).")
    p.add_argument("--no-dataconnect", action="store_true", help="Disable Data Connect for this deployment.")
    p.add_argument("--dc-host", default="",
                   help="Data Connect (MnT/Monitoring node) IP or FQDN. Defaults to --host if omitted.")
    p.add_argument("--dc-port", type=int, default=2484)
    p.add_argument("--dc-sid", default="cpm10")
    p.add_argument("--dc-user", default="dataconnect")
    p.add_argument("--dc-mode", choices=["thin", "thick"], default="thin")
    p.add_argument("--dc-cert", default="", help="Path to THIS deployment's Data Connect certificate (PEM).")
    p.add_argument("--dc-wallet", default="", help="Wallet directory (thick mode / thin ewallet.pem).")
    p.add_argument("--dc-no-verify", action="store_true", help="Do not verify the Data Connect server certificate.")
    p.add_argument("--dc-os-trust", action="store_true",
                   help="CA-signed DC cert: trust via the OS/default CA store instead of a downloaded "
                        "PEM (no --dc-cert needed).")
    p.add_argument("--dc-oracle-lib", default="", help="Oracle Instant Client dir (thick mode).")
    p.add_argument("--default", action="store_true", help="Make this the default deployment.")
    p.set_defaults(func=cmd_add)

    up = sub.add_parser(
        "update",
        help="Modify an existing deployment — only the flags you pass change.")
    up.add_argument("deployment", help="Name, slug, or number of the deployment to modify.")
    up.add_argument("--name", help="New descriptive label (rename; slug/identity and credentials are kept).")
    up.add_argument("--host", help="New ISE admin-node IP or FQDN.")
    up.add_argument("--ers-username", dest="ers_username", help="ERS/Open API admin username.")
    up.add_argument("--ers-port", dest="ers_port", type=int, help="ERS port (443 gateway, or 9060).")
    up.add_argument("--openapi-port", dest="openapi_port", type=int, help="Open API port (443 gateway, or 9070).")
    g_v = up.add_mutually_exclusive_group()
    g_v.add_argument("--verify-ssl", dest="verify_ssl", action="store_true", default=None,
                     help="Verify the ISE admin TLS certificate.")
    g_v.add_argument("--no-verify-ssl", dest="verify_ssl", action="store_false", default=None,
                     help="Do not verify the ISE admin TLS certificate.")
    up.add_argument("--ca-cert", dest="ca_cert", default=None, metavar="PEM",
                    help="Path to a PEM CA bundle to trust for ERS/Open API/Monitoring TLS (private "
                         "ISE CA). Pass '' to clear and fall back to the built-in certifi roots.")
    g_m = up.add_mutually_exclusive_group()
    g_m.add_argument("--enable-monitoring", dest="monitoring_enabled", action="store_true", default=None,
                     help="Enable the Monitoring API (MAPI/MnT) for this deployment.")
    g_m.add_argument("--disable-monitoring", dest="monitoring_enabled", action="store_false", default=None,
                     help="Disable the Monitoring API (MAPI/MnT) for this deployment.")
    g_dc = up.add_mutually_exclusive_group()
    g_dc.add_argument("--enable-dataconnect", dest="dataconnect_enabled", action="store_true", default=None,
                      help="Enable Data Connect (reporting DB) for this deployment.")
    g_dc.add_argument("--disable-dataconnect", dest="dataconnect_enabled", action="store_false", default=None,
                      help="Disable Data Connect for this deployment.")
    up.add_argument("--dc-host", dest="dc_host",
                    help="Data Connect (MnT/Monitoring node) IP or FQDN. Pass '' to clear and fall back to --host.")
    up.add_argument("--dc-port", dest="dc_port", type=int)
    up.add_argument("--dc-sid", dest="dc_sid")
    up.add_argument("--dc-user", dest="dc_user")
    up.add_argument("--dc-mode", dest="dc_mode", choices=["thin", "thick"])
    up.add_argument("--dc-cert", dest="dc_cert",
                    help="Path to this deployment's Data Connect certificate (PEM). Pass '' to clear.")
    up.add_argument("--dc-wallet", dest="dc_wallet", help="Wallet directory (thick mode / thin ewallet.pem).")
    g_dv = up.add_mutually_exclusive_group()
    g_dv.add_argument("--dc-verify", dest="dataconnect_verify_ssl", action="store_true", default=None,
                      help="Verify the Data Connect server certificate.")
    g_dv.add_argument("--dc-no-verify", dest="dataconnect_verify_ssl", action="store_false", default=None,
                      help="Do not verify the Data Connect server certificate.")
    g_ot = up.add_mutually_exclusive_group()
    g_ot.add_argument("--dc-os-trust", dest="dataconnect_os_trust", action="store_true", default=None,
                      help="CA-signed DC cert: trust via the OS/default CA store (no cert file needed).")
    g_ot.add_argument("--dc-no-os-trust", dest="dataconnect_os_trust", action="store_false", default=None,
                      help="Disable OS-trust for Data Connect (use a pinned cert/wallet instead).")
    up.add_argument("--dc-oracle-lib", dest="dc_oracle_lib", help="Oracle Instant Client dir (thick mode).")
    up.add_argument("--reslug", action="store_true",
                    help="Authorize changing the slug (identity) when --name produces a different slug; "
                         "migrates stored credentials. Required for such renames.")
    up.set_defaults(func=cmd_update)

    sc = sub.add_parser("set-credential", help="Store a deployment password (hidden prompt).")
    sc.add_argument("deployment", help="Name, slug, or number.")
    sc.add_argument("--dataconnect", action="store_true",
                    help="Set the Data Connect password instead of the ERS/Open API password.")
    sc.set_defaults(func=cmd_set_credential)

    sd = sub.add_parser("set-default", help="Set the default deployment.")
    sd.add_argument("deployment", help="Name, slug, or number.")
    sd.set_defaults(func=cmd_set_default)

    rm = sub.add_parser("remove", help="Remove a deployment and its stored credentials.")
    rm.add_argument("deployment", help="Name, slug, or number.")
    rm.add_argument("--yes", action="store_true", help="Do not prompt for confirmation.")
    rm.set_defaults(func=cmd_remove)

    t = sub.add_parser("test", help="Check a deployment's config/credentials (+ optional live probe).")
    t.add_argument("deployment", nargs="?", help="Name, slug, or number (default/only if omitted).")
    t.add_argument("--no-probe", action="store_true", help="Skip the live connection attempt.")
    t.set_defaults(func=cmd_test)

    sub.add_parser("validate", help="Offline health check of ALL deployments.").set_defaults(func=cmd_validate)

    rf = sub.add_parser(
        "refresh",
        help="Download the API specs (via iseapi_yaml/links.yaml) and rebuild the tool catalogs.")
    rf.add_argument("--all", dest="all_surfaces", action="store_true",
                    help="Build ALL catalogs (ers,openapi,dc,monitoring) regardless of which "
                         "deployments enable Data Connect / Monitoring.")
    rf.add_argument("--no-download", action="store_true",
                    help="Build from the local iseapi_yaml specs; do not download.")
    rf.add_argument("--no-network", action="store_true",
                    help="Skip ALL network (no spec download, no DevNet scrape).")
    rf.add_argument("--diff-only", action="store_true",
                    help="Report catalog changes without writing.")
    rf.add_argument("--only", help="Comma list of catalogs to build: ers,dc,openapi,monitoring.")
    rf.set_defaults(func=cmd_refresh)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    # First launch: materialize a blank registry so the user has a file to grow.
    # Best-effort — a read-only HOME must not block the command (esp. `serve`).
    try:
        config.ensure_registry()
    except Exception:  # noqa: BLE001
        pass
    if getattr(args, "command", None) is None:
        return cmd_serve(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

