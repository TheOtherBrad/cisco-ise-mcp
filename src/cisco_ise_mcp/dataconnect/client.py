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

import logging
import os
import re as _re
import ssl
from typing import Any, Optional

logger = logging.getLogger(__name__)

from cisco_ise_mcp.limits import LimitExceeded  # noqa: E402 — after logger, no cycle

# Driver codes meaning "call_timeout expired": the statement was cancelled on the
# server via an out-of-band break. DPI-1080 additionally means the connection is
# no longer usable.
_TIMEOUT_CODES = ("DPY-4024", "DPI-1067", "DPI-1080")


def _is_call_timeout(exc: BaseException) -> bool:
    return any(code in str(exc) for code in _TIMEOUT_CODES)


_IDENT = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# FROM/JOIN targets in a raw SELECT, used to confine ise_dc_query to known views.
_FROM_JOIN = _re.compile(r"\b(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_.\"]*)", _re.IGNORECASE)
# SQL comment markers that must not appear in a raw query.
_SQL_COMMENT = _re.compile(r"--|/\*|\*/")

# ---------------------------------------------------------------------------
# Raw-query cost-guard patterns.
#
# All are written without nested quantifiers so they cannot backtrack
# catastrophically (ReDoS) on hostile input — these run against agent-supplied
# SQL before it ever reaches the database.
# ---------------------------------------------------------------------------
# An existing row bound; when absent one is injected rather than refused.
_ROW_BOUND = _re.compile(r"\b(?:FETCH\s+(?:FIRST|NEXT)|ROWNUM|ROW_NUMBER\s*\()", _re.IGNORECASE)
# Aggregation — gets the larger default row limit (aggregate rows are cheap to return).
_AGGREGATE = _re.compile(
    r"\b(?:GROUP\s+BY|COUNT\s*\(|SUM\s*\(|AVG\s*\(|MIN\s*\(|MAX\s*\()", _re.IGNORECASE)
# CTE names in `WITH a AS ( ... ), b AS ( ... ) SELECT ...` — treated as local aliases.
_CTE_NAME = _re.compile(r"(?:\bWITH\s+|,\s*)([A-Za-z_][A-Za-z0-9_]*)\s+AS\s*\(", _re.IGNORECASE)
_JOIN_KW = _re.compile(r"\bJOIN\b", _re.IGNORECASE)
_NATURAL_JOIN = _re.compile(r"\bNATURAL\s+(?:INNER\s+|OUTER\s+|LEFT\s+|RIGHT\s+|FULL\s+)*JOIN\b",
                            _re.IGNORECASE)
_CROSS_JOIN = _re.compile(r"\bCROSS\s+JOIN\b", _re.IGNORECASE)
_ON_OR_USING = _re.compile(r"\b(?:ON|USING)\b", _re.IGNORECASE)
_WHERE_KW = _re.compile(r"\bWHERE\b", _re.IGNORECASE)
_EQ_PREDICATE = _re.compile(r"=")
_LEADING_STMT = _re.compile(r"^\s*(?:SELECT|WITH)\s", _re.IGNORECASE)

_OP_MAP = {
    "EQ": "=", "NEQ": "!=", "CONTAINS": "LIKE", "LIKE": "LIKE",
    "GT": ">", "LT": "<", "GTE": ">=", "LTE": "<=",
}


class RawQueryRejected(ValueError):
    """A raw SELECT failed a cost guard that cannot be auto-corrected."""

    def __init__(self, rule: str, reason: str, example: str = ""):
        self.rule = rule
        self.example = example
        msg = f"[{rule}] {reason}"
        if example:
            msg += f"\n\nCorrected example:\n  {example}"
        super().__init__(msg)


def _cte_names(sql: str) -> set:
    """Local CTE aliases, upper-cased. They are not catalog views and must not be
    rejected by the allow-list — but their bodies are still scanned for facts."""
    return {m.group(1).upper() for m in _CTE_NAME.finditer(sql)}


def _check_joins(sql: str, target_count: int) -> None:
    """Reject joins that can explode into a cartesian product.

    ``N`` joined tables need at least ``N-1`` join conditions. This catches a
    forgotten ``ON`` clause, which is far more damaging than a correctly written
    multi-view join — the failure mode a plain view-count limit misses entirely.
    Heuristic by design; ``call_timeout`` remains the backstop.
    """
    if _CROSS_JOIN.search(sql):
        raise RawQueryRejected(
            "join-condition",
            "CROSS JOIN produces a cartesian product of both views and is not permitted "
            "against the ISE monitoring database.",
            "... FROM radius_authentications ra JOIN network_devices nd "
            "ON nd.ip_mask = ra.nas_ip_address ...")
    if target_count < 2:
        return
    natural = len(_NATURAL_JOIN.findall(sql))
    explicit = len(_JOIN_KW.findall(sql)) - natural       # NATURAL JOIN implies its condition
    conditions = len(_ON_OR_USING.findall(sql))
    if explicit > conditions:
        raise RawQueryRejected(
            "join-condition",
            f"{explicit} JOIN clause(s) but only {conditions} ON/USING condition(s). "
            "A join without a condition is a cartesian product.",
            "SELECT ra.username, nd.name FROM radius_authentications ra "
            "JOIN network_devices nd ON nd.ip_mask = ra.nas_ip_address "
            "WHERE ra.\"TIMESTAMP\" >= SYSTIMESTAMP - NUMTODSINTERVAL(7,'DAY') "
            "FETCH FIRST 100 ROWS ONLY")

    # Old-style comma joins ("FROM a, b") need equality predicates in the WHERE.
    comma_joins = target_count - 1 - explicit - natural
    if comma_joins > 0:
        where = _WHERE_KW.split(sql, maxsplit=1)
        equals = len(_EQ_PREDICATE.findall(where[1])) if len(where) > 1 else 0
        if equals < comma_joins:
            raise RawQueryRejected(
                "join-condition",
                f"{comma_joins + 1} views are comma-joined but the WHERE clause has only "
                f"{equals} equality condition(s), so the result is (partly) a cartesian product.",
                "SELECT ... FROM radius_authentications ra, network_devices nd "
                "WHERE nd.ip_mask = ra.nas_ip_address AND ra.\"TIMESTAMP\" >= "
                "SYSTIMESTAMP - NUMTODSINTERVAL(7,'DAY') FETCH FIRST 100 ROWS ONLY")


def _check_fact_time_bounds(sql: str, facts: set, view_meta: dict, max_facts: int) -> None:
    """Every referenced fact view must be time-bounded, and not too many at once.

    This stays a *rejection* rather than an injection: appending to the end of a
    statement is safe, but rewriting someone's WHERE clause is not — it would mean
    reasoning about AND/OR precedence, subqueries and which alias owns the time
    column. Silently altering predicate logic is a worse failure than refusing.
    """
    if not facts:
        return
    if len(facts) > max_facts:
        raise RawQueryRejected(
            "fact-view-limit",
            f"This query references {len(facts)} large event views "
            f"({', '.join(sorted(facts))}) but at most {max_facts} may be joined. "
            "Small configuration/lookup views (network_devices, security_groups, "
            "failure_code_cause, ...) are exempt and may be joined without limit.",
            "Split the correlation into separate queries, or aggregate one side first.")

    for view in sorted(facts):
        time_col = view_meta.get(view)
        if not time_col:
            continue
        # Require the time column in a comparison, not merely in the SELECT list.
        # The optional closing quote matters: reserved-word columns are written
        # `"TIMESTAMP" >= ...`, so the quote sits between the name and the operator.
        bounded = _re.search(
            rf"\b{_re.escape(time_col)}\b\"?\s*(?:>=|<=|<>|!=|>|<|=|\bBETWEEN\b)",
            sql, _re.IGNORECASE)
        if not bounded:
            raise RawQueryRejected(
                "time-predicate",
                f"'{view}' is a high-volume event view, so it must be time-bounded on its "
                f"'{time_col}' column. Without one, Oracle scans the entire view and can "
                f"saturate the ISE Monitoring node.",
                f"SELECT ... FROM {view} WHERE \"{time_col}\" >= SYSTIMESTAMP - "
                f"NUMTODSINTERVAL(7,'DAY') FETCH FIRST 100 ROWS ONLY")


def validate_raw_select(sql: str, allowed_views: set, *,
                        fact_views: Optional[set] = None,
                        view_time_cols: Optional[dict] = None,
                        policy: Optional[Any] = None) -> str:
    """Guard the raw ``ise_dc_query`` path and return the SQL to execute.

    Layers on top of the read-only ``dataconnect`` DB account:
      * must be a single SELECT (or WITH ... SELECT); no stacked statements,
      * no SQL comments (``--`` / ``/* */``) that could hide intent,
      * every FROM/JOIN target must be an allow-listed catalog view (or DUAL),
      * with ``policy``: fact views must be time-bounded, joins must have
        conditions, the fact-view ceiling applies, and a **missing row bound is
        injected rather than refused**.

    ``allowed_views`` is a set of UPPER-CASED view names. The cost guards are
    applied only when ``policy`` is supplied, so the structural checks remain
    usable standalone. Returns the (possibly row-bounded) SQL.
    """
    if not _LEADING_STMT.match(sql):
        raise ValueError("Only SELECT statements (optionally preceded by WITH ... AS) are permitted.")
    if _SQL_COMMENT.search(sql):
        raise ValueError("SQL comments ('--', '/* */') are not allowed in ise_dc_query.")
    # A trailing ';' is tolerated; an interior ';' means stacked statements.
    if ";" in sql.rstrip().rstrip(";"):
        raise ValueError("Multiple/stacked SQL statements are not allowed.")

    local = _cte_names(sql)
    targets = {t.strip('"').split(".")[-1].upper() for t in _FROM_JOIN.findall(sql)}
    if not targets:
        raise ValueError("Could not identify a FROM target; query a known Data Connect view.")
    real_targets = {t for t in targets if t not in local and t != "DUAL"}
    disallowed = sorted(t for t in real_targets if t not in allowed_views)
    if disallowed:
        raise ValueError(
            "ise_dc_query is restricted to Data Connect catalog views. "
            f"Not allowed: {', '.join(disallowed)}. Use ise_dc_list_views to see valid views."
        )

    if policy is None:
        return sql

    facts = {t for t in real_targets if t in (fact_views or set())}
    # Count real views only: a CTE reference (`FROM recent`) is not a join, and
    # counting it as one would reject every valid `WITH ... SELECT * FROM cte`.
    # Views used *inside* CTE bodies are still in real_targets, so a genuine
    # comma join through a CTE is still caught.
    _check_joins(sql, len(real_targets))
    _check_fact_time_bounds(sql, facts, view_time_cols or {},
                            int(getattr(policy, "max_fact_views", 3)))
    return _inject_row_bound(sql, policy)


def _inject_row_bound(sql: str, policy: Any) -> str:
    """Append a default row bound when the query has none.

    Appends rather than wrapping: ``SELECT * FROM (<sql>) WHERE ROWNUM <= n`` is
    syntactically safer but raises ORA-00918 ("column ambiguously defined") the
    moment the inner query selects same-named columns from two views — exactly
    the multi-view report case. Appending also bounds a UNION as a whole.

    The limit is ``int()``-coerced from configuration (never agent input), so it
    cannot carry injected SQL.
    """
    if _ROW_BOUND.search(sql):
        return sql
    aggregating = bool(_AGGREGATE.search(sql))
    limit = int(policy.default_agg_row_limit if aggregating else policy.default_row_limit)
    if limit <= 0:
        return sql
    return f"{sql.rstrip().rstrip(';').rstrip()} FETCH FIRST {limit} ROWS ONLY"


# init_oracle_client() is global and may be called only once per process.
_THICK_INITIALIZED = False

# Process-wide Oracle session pools, keyed by user@host:port/sid. Pooling replaces
# a full TCPS handshake + Oracle authentication + dedicated server process on the
# MnT node for EVERY query — on Oracle, connection establishment is often costlier
# than the query itself.
_POOLS: dict = {}
# Endpoints where pool creation was refused (e.g. an ssl_context the pool path does
# not accept). Those fall back to per-call connect rather than weakening TLS.
_POOL_UNSUPPORTED: set = set()


def close_all_pools() -> None:
    """Close every Data Connect pool (shutdown / test teardown)."""
    for key, pool in list(_POOLS.items()):
        try:
            pool.close(force=True)
        except Exception:  # noqa: BLE001 — teardown must not raise
            pass
        _POOLS.pop(key, None)


def _quote_ident(name: str) -> str:
    """Validate and quote an Oracle identifier (upper-cased to match view columns)."""
    if not _IDENT.match(name):
        raise ValueError(f"Invalid column name: {name!r}")
    return '"' + name.upper() + '"'


def resolve_days_back(arguments: dict, time_col: Optional[str],
                      policy: Any) -> tuple[Optional[int], str]:
    """Decide the time window for a structured view query.

    Returns ``(days, source)`` where source is one of:
      * ``"n/a"``     — the view has no time column (small config view; exempt)
      * ``"explicit"`` — the caller supplied a value within the maximum
      * ``"default"``  — nothing supplied, so the default window was injected
      * ``"clamped"``  — the caller asked for more than the maximum, so it was
        reduced rather than rejected (a 120-day request runs as 90)

    Clamping keeps the call succeeding instead of forcing an agent into an
    error-recovery loop for a request that can be served safely. It is silent in
    the payload — the response shape is unchanged — so the caller is told via the
    tool schema, the user guide, and a WARNING log emitted by the caller.
    """
    if not time_col:
        return None, "n/a"
    maximum = int(getattr(policy, "max_days_back", 0) or 0)
    default = int(getattr(policy, "default_days_back", 0) or 0)

    raw = arguments.get("days_back")
    if raw in (None, "", 0):
        return (default, "default") if default > 0 else (None, "none")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return (default, "default") if default > 0 else (None, "none")
    if value <= 0:
        return (default, "default") if default > 0 else (None, "none")
    if maximum > 0 and value > maximum:
        return maximum, "clamped"
    return value, "explicit"


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
        max_sessions: int = 0,
        acquire_wait_s: float = 0.0,
        query_timeout_s: int = 0,
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
        self.max_sessions = int(max_sessions or 0)
        self.acquire_wait_s = float(acquire_wait_s or 0.0)
        self.query_timeout_s = int(query_timeout_s or 0)
        self._conn = None
        self._pooled = False

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

    def _pool_key(self) -> str:
        return f"{self.user}@{self.host}:{self.port}/{self.sid}:{self.mode}"

    def _get_pool(self):
        """Return a session pool for this endpoint, or ``None`` to connect directly.

        ``min=0`` is deliberate: in thin mode python-oracledb opens pool
        connections on a daemon thread, so a non-zero minimum would attempt a
        background Data Connect connection at pool-creation time. The previous
        behaviour was strictly lazy — nothing connected until the first query —
        and ``min=0`` preserves that, so a deployment with Data Connect enabled
        but unused, or an unreachable MnT node, behaves exactly as before.

        If the driver refuses the pool (for example an ``ssl_context`` the pool
        path will not accept), fall back to per-call connect. TLS configuration is
        never relaxed to make pooling work.
        """
        if self.max_sessions <= 0:
            return None
        key = self._pool_key()
        if key in _POOL_UNSUPPORTED:
            return None
        pool = _POOLS.get(key)
        if pool is not None:
            return pool
        import oracledb

        try:
            kwargs = self._connect_kwargs()
            pool = oracledb.create_pool(
                min=0,
                max=self.max_sessions,
                increment=1,
                homogeneous=True,
                getmode=oracledb.POOL_GETMODE_WAIT,
                # Wait in the driver as well, so the pool cannot outlast the
                # caller-side queue budget.
                wait_timeout=int(max(self.acquire_wait_s, 1.0) * 1000),
                **kwargs,
            )
        except Exception as exc:  # noqa: BLE001 — any pool refusal falls back safely
            _POOL_UNSUPPORTED.add(key)
            logger.warning(
                "Data Connect session pooling unavailable for %s (%s: %s); falling back to "
                "per-call connections. Concurrency is still bounded by the MCP limiter.",
                key, type(exc).__name__, exc)
            return None
        _POOLS[key] = pool
        return pool

    def _connect_kwargs(self) -> dict:
        """Connection parameters shared by the pooled and direct paths.

        The TLS trust decision lives entirely in ``_thin_ssl_context()`` /
        the thick-mode wallet and is identical either way.
        """
        if self.mode == "thick":
            return {
                "user": self.user,
                "password": self.password,
                "dsn": self._dsn(),
                "config_dir": self.wallet_path or None,
                "wallet_location": self.wallet_path or None,
            }
        return {
            "protocol": "tcps",
            "host": self.host,
            "port": self.port,
            "service_name": self.sid,
            "user": self.user,
            "password": self.password,
            "ssl_context": self._thin_ssl_context(),
            "ssl_server_dn_match": False,
        }

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
            if self.mode == "thick":
                # init_oracle_client() must run before any thick-mode pool is built.
                global _THICK_INITIALIZED
                if not _THICK_INITIALIZED:
                    import oracledb
                    oracledb.init_oracle_client(lib_dir=self.oracle_client_lib or None)
                    _THICK_INITIALIZED = True
            pool = self._get_pool()
            if pool is not None:
                self._conn = pool.acquire()
                self._pooled = True
            else:
                self._conn = self._connect()
                self._pooled = False
            if self.query_timeout_s > 0:
                try:
                    # Bounds a single round trip. On expiry the driver sends an
                    # out-of-band break so the MnT node STOPS executing the
                    # statement — the client merely giving up would leave Oracle
                    # burning CPU on an abandoned query.
                    self._conn.call_timeout = self.query_timeout_s * 1000
                except Exception as exc:  # noqa: BLE001 — older clients may not support it
                    logger.warning("Could not set Data Connect call_timeout: %s", exc)
        return self._conn

    def execute_query(self, sql: str, binds: Optional[dict] = None,
                      max_rows: Optional[int] = None) -> list[dict[str, Any]]:
        """Execute a read-only SELECT (with optional bind variables) and return rows as dicts.

        ``max_rows`` caps how many rows are read from the cursor (Oracle streams, so
        a runaway ``SELECT *`` won't be fully materialized) — a memory-safety bound
        for the raw-query path where the caller may omit ``FETCH FIRST``.
        """
        if not _re.match(r"^\s*(?:SELECT|WITH)\s", sql, _re.IGNORECASE):
            raise ValueError("Only SELECT statements are permitted")
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(sql, binds or {})
            columns = [col[0] for col in cursor.description] if cursor.description else []
            rows = cursor.fetchmany(max_rows) if max_rows is not None else cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]
        except Exception as exc:  # noqa: BLE001 — re-raised, or translated below
            if _is_call_timeout(exc):
                # The statement was cancelled server-side. Surface actionable
                # guidance instead of a raw Oracle code.
                raise LimitExceeded({
                    "error": "query_timeout",
                    "surface": "dataconnect",
                    "reason": (
                        f"The query exceeded the {self.query_timeout_s}s Data Connect time "
                        f"limit and was cancelled on the ISE Monitoring node."),
                    "remediation": (
                        "Narrow it: reduce days_back, add a filter on an indexed column, or "
                        "aggregate in SQL (GROUP BY) instead of returning raw rows."),
                    "limits": {"query_timeout_seconds": self.query_timeout_s},
                }) from exc
            raise
        finally:
            cursor.close()

    def get_available_views(self) -> list[str]:
        """List all views the dataconnect user can read (live, from the DB)."""
        rows = self.execute_query("SELECT view_name FROM user_views ORDER BY view_name ASC")
        return [row["VIEW_NAME"] for row in rows]

    def close(self):
        """Return the connection to the pool, or close it when unpooled."""
        if self._conn is not None:
            try:
                if self._pooled:
                    pool = _POOLS.get(self._pool_key())
                    if pool is not None:
                        pool.release(self._conn)
                    else:  # pragma: no cover — pool disappeared under us
                        self._conn.close()
                else:
                    self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None
            self._pooled = False
