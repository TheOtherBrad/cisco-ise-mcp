"""
Oracle database client for Cisco ISE Data Connect.

Connects to the ISE monitoring database via Oracle TCPS (SSL) on port 2484 and
provides read-only access to the documented database views.

TLS trust supports two modes:

  * **thin** (default, no Oracle client install) — python-oracledb's pure-Python
    driver. Trust is established with a Python ``ssl.SSLContext``.
    - With a **pinned PEM** (``cert_path``/wallet) the exported ISE certificate IS
      the identity, so hostname checking is disabled (``ssl_server_dn_match=False``);
      trust is by certificate, not name.
    - With ``os_trust=True`` (CA-signed certs) the chain is validated against the
      OS/default CA store (``load_default_certs``) AND the hostname is verified
      (``check_hostname=True``) — otherwise any CA-signed cert would be accepted.
  * **thick** (Oracle Instant Client) — calls ``init_oracle_client()`` and trusts
    the server via an auto-login wallet directory (``cwallet.sso``, e.g. built
    with ``orapki``).

Security:
  * Only ``SELECT`` statements are accepted.
  * Filter values and limits are passed as **bind variables** (never string
    interpolation). Identifiers are validated against a strict pattern and
    quoted+upper-cased so reserved-word columns such as ``TIMESTAMP`` work.
"""

from __future__ import annotations

import os
import re as _re
import ssl
from typing import Any, Optional

_IDENT = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# FROM/JOIN targets in a raw SELECT, used to confine ise_dc_query to known views.
_FROM_JOIN = _re.compile(r"\b(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_.\"]*)", _re.IGNORECASE)
# SQL comment markers that must not appear in a raw query.
_SQL_COMMENT = _re.compile(r"--|/\*|\*/")
_OP_MAP = {
    "EQ": "=", "NEQ": "!=", "CONTAINS": "LIKE", "LIKE": "LIKE",
    "GT": ">", "LT": "<", "GTE": ">=", "LTE": "<=",
}


def validate_raw_select(sql: str, allowed_views: set) -> None:
    """Guard the raw ise_dc_query path (Finding #6).

    Layers on top of the read-only ``dataconnect`` DB account:
      * must be a single SELECT (no stacked statements),
      * no SQL comments (``--`` / ``/* */``) that could hide intent,
      * every FROM/JOIN target must be an allow-listed catalog view (or DUAL).

    ``allowed_views`` is a set of UPPER-CASED view names. Raises ``ValueError``.
    """
    if not _re.match(r"^\s*SELECT\s", sql, _re.IGNORECASE):
        raise ValueError("Only SELECT statements are permitted.")
    if _SQL_COMMENT.search(sql):
        raise ValueError("SQL comments ('--', '/* */') are not allowed in ise_dc_query.")
    # A trailing ';' is tolerated; an interior ';' means stacked statements.
    if ";" in sql.rstrip().rstrip(";"):
        raise ValueError("Multiple/stacked SQL statements are not allowed.")
    targets = {t.strip('"').split(".")[-1].upper() for t in _FROM_JOIN.findall(sql)}
    if not targets:
        raise ValueError("Could not identify a FROM target; query a known Data Connect view.")
    disallowed = sorted(t for t in targets if t != "DUAL" and t not in allowed_views)
    if disallowed:
        raise ValueError(
            "ise_dc_query is restricted to Data Connect catalog views. "
            f"Not allowed: {', '.join(disallowed)}. Use ise_dc_list_views to see valid views."
        )

# init_oracle_client() is global and may be called only once per process.
_THICK_INITIALIZED = False


def _quote_ident(name: str) -> str:
    """Validate and quote an Oracle identifier (upper-cased to match view columns)."""
    if not _IDENT.match(name):
        raise ValueError(f"Invalid column name: {name!r}")
    return '"' + name.upper() + '"'


def build_query(view_name: str, arguments: dict, time_col: Optional[str] = None) -> tuple[str, dict]:
    """
    Build a parameterized SELECT for a view.

    Supports filter_column/filter_value/filter_op, days_back (against ``time_col``),
    order_by, and limit — all via bind variables. Returns ``(sql, binds)``.
    """
    if not _IDENT.match(view_name):
        raise ValueError(f"Invalid view name: {view_name!r}")

    binds: dict[str, Any] = {}
    where: list[str] = []

    filter_col = arguments.get("filter_column")
    filter_val = arguments.get("filter_value")
    filter_op = (arguments.get("filter_op") or "EQ").upper()

    if filter_col and filter_val is not None:
        col = _quote_ident(filter_col)
        sql_op = _OP_MAP.get(filter_op)
        if sql_op is None:
            raise ValueError(f"Invalid filter operator: {filter_op}")
        if filter_op in ("CONTAINS", "LIKE"):
            where.append(f"{col} LIKE :fval")
            binds["fval"] = f"%{filter_val}%"
        else:
            try:
                binds["fval"] = float(filter_val) if "." in str(filter_val) else int(filter_val)
            except (ValueError, TypeError):
                binds["fval"] = filter_val
            where.append(f"{col} {sql_op} :fval")

    days_back = arguments.get("days_back")
    if days_back:
        if time_col:
            where.append(f'{_quote_ident(time_col)} >= SYSTIMESTAMP - NUMTODSINTERVAL(:days_back, \'DAY\')')
            binds["days_back"] = int(days_back)
        # If the view has no time column, days_back is silently inapplicable.

    order_sql = ""
    order_by = arguments.get("order_by")
    if order_by:
        clean = order_by.lstrip("-+")
        direction = "DESC" if order_by.startswith("-") else "ASC"
        order_sql = f" ORDER BY {_quote_ident(clean)} {direction}"

    limit = min(int(arguments.get("limit", 100)), 10000)
    binds["maxrows"] = limit

    sql = f"SELECT * FROM {view_name}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += order_sql
    sql += " FETCH FIRST :maxrows ROWS ONLY"
    return sql, binds


class ISEDataConnectClient:
    """Oracle TCPS client for Cisco ISE Data Connect (read-only)."""

    def __init__(
        self,
        host: str,
        port: int = 2484,
        password: str = "",
        user: str = "dataconnect",
        sid: str = "cpm10",
        wallet_path: str = "",
        cert_path: str = "",
        mode: str = "thin",
        verify_ssl: bool = True,
        os_trust: bool = False,
        oracle_client_lib: str = "",
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.sid = sid
        self.wallet_path = wallet_path
        self.cert_path = cert_path
        self.mode = (mode or "thin").lower()
        self.verify_ssl = verify_ssl
        self.os_trust = os_trust
        self.oracle_client_lib = oracle_client_lib
        self._conn = None

    def _dsn(self) -> str:
        return (
            f"(DESCRIPTION="
            f"(ADDRESS=(PROTOCOL=tcps)(HOST={self.host})(PORT={self.port}))"
            f"(CONNECT_DATA=(SID={self.sid})))"
        )

    def _thin_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if self.verify_ssl:
            if self.os_trust:
                # CA-signed cert whose root is trusted by the OS/default CA store.
                # Validate the chain AND bind to the hostname: with a public/OS CA
                # anchor, skipping the hostname check would accept any CA-signed
                # cert (incl. an attacker's own) — so keep check_hostname on. The
                # CA-signed Data Connect cert is expected to carry the node's SAN.
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.check_hostname = True
                ctx.load_default_certs()
                return ctx
            # Pinned-certificate trust: identity comes from the pinned PEM
            # itself, so hostname matching is disabled ONLY when a real pinned
            # cert/wallet is present (the ISE node cert's CN/SAN rarely matches
            # the IP/FQDN you dial). Without a pin we must NOT fall back to the
            # OS CA store with check_hostname off — that would accept any
            # CA-signed cert for any hostname (CWE-297). os_trust handles the
            # legitimate CA-store case above with the hostname check kept on;
            # here we refuse and tell the operator exactly what to configure.
            cafile = self.cert_path
            if not cafile and self.wallet_path:
                pem = os.path.join(self.wallet_path, "ewallet.pem")
                cafile = pem if os.path.isfile(pem) else ""
            if cafile and os.path.isfile(cafile):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(cafile=cafile)
                return ctx
            raise ValueError(
                "Data Connect verify_ssl is on but no pinned certificate/wallet "
                "was found and os_trust is off, so the server's identity cannot "
                "be verified safely. Fix one of:\n"
                "  - self-signed cert: set dataconnect_cert_path to the exported PEM\n"
                "  - CA-signed cert:   set dataconnect_os_trust=true\n"
                "  - wallet:           set dataconnect_wallet_path (with ewallet.pem)\n"
                "  - lab only:         set dataconnect_verify_ssl=false (disables MITM protection)."
            )
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _connect(self):
        import oracledb

        if self.mode == "thick":
            global _THICK_INITIALIZED
            if not _THICK_INITIALIZED:
                oracledb.init_oracle_client(lib_dir=self.oracle_client_lib or None)
                _THICK_INITIALIZED = True
            # Thick mode trusts via the wallet directory (cwallet.sso) / sqlnet.ora.
            return oracledb.connect(
                user=self.user,
                password=self.password,
                dsn=self._dsn(),
                config_dir=self.wallet_path or None,
                wallet_location=self.wallet_path or None,
            )

        # thin mode (default) — trust via a Python SSLContext.
        params = oracledb.ConnectParams(
            protocol="tcps",
            host=self.host,
            port=self.port,
            service_name=self.sid,
            user=self.user,
            password=self.password,
            ssl_context=self._thin_ssl_context(),
            ssl_server_dn_match=False,
        )
        return oracledb.connect(params=params)

    def _get_connection(self):
        if self._conn is None:
            self._conn = self._connect()
        return self._conn

    def execute_query(self, sql: str, binds: Optional[dict] = None,
                      max_rows: Optional[int] = None) -> list[dict[str, Any]]:
        """Execute a read-only SELECT (with optional bind variables) and return rows as dicts.

        ``max_rows`` caps how many rows are read from the cursor (Oracle streams, so
        a runaway ``SELECT *`` won't be fully materialized) — a memory-safety bound
        for the raw-query path where the caller may omit ``FETCH FIRST``.
        """
        if not _re.match(r"^\s*SELECT\s", sql, _re.IGNORECASE):
            raise ValueError("Only SELECT statements are permitted")
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(sql, binds or {})
            columns = [col[0] for col in cursor.description] if cursor.description else []
            rows = cursor.fetchmany(max_rows) if max_rows is not None else cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]
        finally:
            cursor.close()

    def get_available_views(self) -> list[str]:
        """List all views the dataconnect user can read (live, from the DB)."""
        rows = self.execute_query("SELECT view_name FROM user_views ORDER BY view_name ASC")
        return [row["VIEW_NAME"] for row in rows]

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None
