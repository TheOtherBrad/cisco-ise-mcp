"""Parser-based allow-list guard for the raw ``ise_dc_query`` path.

Why a parser: SQL quoting (``'..'``, ``"..."``, ``q'[..]'``) and scope (CTEs,
inline views, parenthesised joins, APPLY, SAMPLE/PIVOT clauses) cannot be
modelled with regular expressions — an earlier regex-based guard was bypassable
through exactly those constructs. This module uses sqlglot's Oracle lexer
and parser and FAILS CLOSED: anything it cannot tokenize or parse is rejected.

Layers (all must pass):
  1. Lexical — real tokens, so text inside literals / quoted identifiers can never
     trigger or hide a rule: no comments, no ``@`` db links, no ``q'``/raw
     strings, no deny-listed package / URI / XML type names, no qualified calls
     (``x.y(`` or ``"X"."Y"(``).
  2. Structural — exactly one statement, a SELECT/UNION tree only, no
     ``FOR UPDATE``.
  3. Allow-list — EVERY table node anywhere in the tree must be a catalog view or
     ``DUAL``, unless scope analysis proves it is a reference to a CTE visible in
     that scope. Schema / catalog / db-link qualified tables are rejected.

The read-only grants of the ISE ``dataconnect`` account remain the final backstop.
"""

from __future__ import annotations

from typing import Iterable

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.scope import traverse_scope
from sqlglot.tokens import Token, TokenType

_DIALECT = "oracle"

# Package / type / constructor names that reach outside the monitoring views:
# network (UTL_HTTP, UTL_INADDR, HTTPURITYPE ...), files, scheduler, dynamic SQL,
# and XML/URI constructors that can fetch remote resources. Matched against
# identifier TOKENS (prefix match for the *_ families), never against literals.
_DENIED_PREFIXES = ("DBMS_", "UTL_", "CTX_", "OWA_", "SDO_", "ORD_", "APEX_", "WWV_")
_DENIED_NAMES = frozenset({
    "HTP", "HTF", "SYS", "SYSTEM", "MDSYS", "XDB", "CTXSYS", "ORDSYS", "LBACSYS",
    "HTTPURITYPE", "DBURITYPE", "XDBURITYPE", "URIFACTORY",
    "XMLTYPE", "XMLQUERY", "XMLTABLE", "XMLPARSE", "XMLEXISTS", "EXTRACTVALUE",
    "JAVA",
    # Session/host metadata disclosure (DB host, OS user, client IP).
    "SYS_CONTEXT", "USERENV",
})
_IDENT_TOKENS = {TokenType.VAR, TokenType.IDENTIFIER}
_STRING_TOKENS = {TokenType.STRING, TokenType.NATIONAL_STRING}


class SqlGuardError(ValueError):
    """The raw SELECT is not permitted (security rule, not a cost rule)."""


def _tokens(sql: str) -> list[Token]:
    try:
        return sqlglot.Dialect.get_or_raise(_DIALECT).tokenize(sql)
    except SqlglotError as exc:
        raise SqlGuardError(f"ise_dc_query could not tokenize the SQL safely: {exc}") from None


def _is_denied_name(name: str) -> bool:
    up = name.upper()
    return up in _DENIED_NAMES or up.startswith(_DENIED_PREFIXES)


def _lexical_checks(sql: str, toks: list[Token]) -> None:
    for tok in toks:
        if tok.comments:
            raise SqlGuardError("SQL comments ('--', '/* */') are not allowed in ise_dc_query.")
        # `view@link` lexes as one VAR; `view @ link` / `"V"@"L"` as a PARAMETER '@'.
        if tok.token_type not in _STRING_TOKENS and tok.token_type != TokenType.IDENTIFIER \
                and "@" in tok.text:
            raise SqlGuardError("Database links ('@') are not allowed in ise_dc_query.")
        if tok.token_type in _IDENT_TOKENS:
            if _is_denied_name(tok.text):
                raise SqlGuardError(
                    f"'{tok.text}' is not allowed in ise_dc_query: system schemas/packages, "
                    "network/URI types and XML constructors are blocked. Query the Data "
                    "Connect views directly (see ise_dc_list_views).")
        if tok.token_type not in _STRING_TOKENS and tok.token_type.name.endswith("STRING"):
            # Allow-list: only plain '...' and N'...' literals. q'[..]', nq'..',
            # raw/byte/bit/hex/heredoc strings are all refused.
            raise SqlGuardError("Oracle alternative quoting (q'[...]') and non-standard "
                                "string literals are not allowed in ise_dc_query.")
    # Qualified call:  <ident> . <ident> (   — any schema/package-qualified function.
    for a, dot, b, paren in zip(toks, toks[1:], toks[2:], toks[3:]):
        if (a.token_type in _IDENT_TOKENS and dot.token_type == TokenType.DOT
                and b.token_type in _IDENT_TOKENS and paren.token_type == TokenType.L_PAREN):
            raise SqlGuardError(
                "Schema- or package-qualified function calls (x.y(...)) are not allowed in "
                "ise_dc_query. Use built-in SQL functions only.")
    # The text between tokens must be whitespace only — anything else means the
    # lexer skipped something we did not inspect.
    pos = 0
    for tok in toks:
        gap = sql[pos:tok.start]
        if gap.strip() and gap.strip() != ";":
            raise SqlGuardError("ise_dc_query contains text the SQL guard could not classify.")
        pos = tok.end + 1


def _parse_one(sql: str) -> exp.Expression:
    try:
        stmts = [s for s in sqlglot.parse(sql, read=_DIALECT) if s is not None]
    except SqlglotError as exc:
        raise SqlGuardError(
            f"ise_dc_query could not parse the SQL (only standard Oracle SELECT syntax is "
            f"accepted): {str(exc).splitlines()[0][:200]}") from None
    if len(stmts) != 1:
        raise SqlGuardError("Multiple/stacked SQL statements are not allowed.")
    tree = stmts[0]
    if not isinstance(tree, (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.Subquery)):
        raise SqlGuardError("Only SELECT statements (optionally preceded by WITH ... AS) are permitted.")
    if tree.find(exp.Lock):
        raise SqlGuardError("SELECT ... FOR UPDATE is not allowed (Data Connect is read-only).")
    if tree.find(exp.Lateral):
        raise SqlGuardError("LATERAL / CROSS APPLY / OUTER APPLY sources are not allowed in ise_dc_query.")
    # Every FROM / JOIN source must be a plain table reference or a parenthesised
    # query. Anything else (bare identifiers inside other constructs, table
    # functions, VALUES, UNNEST ...) is refused rather than reasoned about.
    for node in tree.find_all(exp.From, exp.Join):
        src = node.this
        if not isinstance(src, (exp.Table, exp.Subquery)):
            raise SqlGuardError(
                f"Unsupported FROM/JOIN source in ise_dc_query ({type(src).__name__}); "
                "select from Data Connect views or subqueries only.")
    for bad in (exp.Insert, exp.Update, exp.Delete, exp.Merge, exp.Create, exp.Drop,
                exp.Alter, exp.Command, exp.Into):
        if tree.find(bad):
            raise SqlGuardError("Only read-only SELECT statements are permitted.")
    return tree


def _cte_table_ids(tree: exp.Expression) -> set[int]:
    """ids of Table nodes that scope analysis resolves to a CTE in their own scope."""
    out: set[int] = set()
    try:
        scopes = traverse_scope(tree)
    except Exception:  # noqa: BLE001 — unresolvable scope => treat nothing as a CTE
        return out
    for scope in scopes:
        cte_names = {name.upper() for name in scope.cte_sources}
        for table in scope.tables:
            if not table.db and not table.catalog and table.name.upper() in cte_names:
                out.add(id(table))
    return out


def check(sql: str, allowed_views: Iterable[str]) -> set[str]:
    """Validate ``sql``; return the set of REAL (non-CTE, non-DUAL) view names used.

    ``allowed_views`` are upper-cased catalog view names. Raises SqlGuardError.
    """
    allowed = {v.upper() for v in allowed_views}
    toks = _tokens(sql)
    if not toks:
        raise SqlGuardError("Empty query.")
    _lexical_checks(sql, toks)
    tree = _parse_one(sql)

    cte_ids = _cte_table_ids(tree)
    real: set[str] = set()
    disallowed: set[str] = set()
    tables = list(tree.find_all(exp.Table))
    if not tables:
        raise SqlGuardError("Could not identify a FROM target; query a known Data Connect view.")
    for table in tables:
        if table.args.get("db") or table.args.get("catalog"):
            raise SqlGuardError(
                f"Schema-qualified object names are not allowed in ise_dc_query "
                f"({table.sql(_DIALECT)}). Use the bare Data Connect view name.")
        if not isinstance(table.this, exp.Identifier):
            # TABLE(func(...)), lateral function sources, etc.
            raise SqlGuardError(
                "Table functions and computed FROM sources are not allowed in ise_dc_query; "
                "select from Data Connect views only.")
        if id(table) in cte_ids:
            continue
        name = table.name.upper()
        if name == "DUAL":
            continue
        if name in allowed:
            real.add(name)
        else:
            disallowed.add(name)
    if disallowed:
        raise SqlGuardError(
            "ise_dc_query is restricted to Data Connect catalog views. "
            f"Not allowed: {', '.join(sorted(disallowed))}. Use ise_dc_list_views to see valid views.")
    return real


def blank_literals(sql: str) -> str:
    """Token-accurate copy of ``sql`` with every string literal replaced by ``''``.

    Used by the (non-security) cost heuristics so text inside a literal can never
    satisfy a time predicate or count as a join condition. Quoted identifiers are
    kept intact.
    """
    toks = _tokens(sql)
    out, pos = [], 0
    for tok in toks:
        out.append(sql[pos:tok.start])
        out.append("''" if tok.token_type in _STRING_TOKENS else sql[tok.start:tok.end + 1])
        pos = tok.end + 1
    out.append(sql[pos:])
    return "".join(out)


def cte_names(sql: str) -> set[str]:
    """Upper-cased names of every CTE defined anywhere in the statement."""
    try:
        tree = _parse_one(sql)
    except SqlGuardError:
        return set()
    return {cte.alias_or_name.upper() for cte in tree.find_all(exp.CTE)}
