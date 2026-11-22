# Changelog

Each entry lists the date the changes were implemented, followed by one numbered
item per modification. Entries marked **BREAKING CHANGE** alter existing
behaviour and explain what stops working, why, and how to adapt.

## 2026/11/22 — v1.1.0 (security & token optimization)

1. **BREAKING CHANGE** — Tool arguments are now validated against each tool's input schema before anything runs, on both MCP SDK majors (the 2.x low-level server never validated them). Wrong types, missing required fields, and values outside an `enum` now return `{"error": "invalid_arguments", "details": [...]}` instead of being passed through. The reply names the failing field and rule but never echoes the value. A numeric `deployment` selector (`1`) is still accepted. Set `CISCO_ISE_MCP_VALIDATE_ARGS=0` to restore the old pass-through behaviour.
2. `confirm`, `reslug` and `probe` are interpreted strictly. Only JSON `true` (or the strings `true`/`1`/`yes`/`on`) counts as consent. Previously the string `"false"` *authorized* a destructive call, because `bool("false")` is `True` in Python.
3. **BREAKING CHANGE** — More operations are now gated as destructive: they require `CISCO_ISE_MCP_ALLOW_DESTRUCTIVE=1` and `confirm=true`, and are written to the audit log.
   - MnT CoA re-authenticate and disconnect: `ise_mnt_coa_reauth`, and any `ise_mnt_request` path containing `/CoA/` or `/Session/Delete/`, whatever the method. CoA is a GET in the MnT API, so it previously bypassed the gate.
   - Open API patch and hot-patch install, plus system and trusted certificate import.
   - `ise_openapi_request` calls with any non-GET method to install, rollback, restore, import or reset paths.

   Paths are percent-decoded before they are classified.
4. `CISCO_ISE_MCP_BLOCKED_TOOLS` now applies to **every** tool, read-only tools included. It is checked before anything else; previously it only took effect for destructive calls.
5. **BREAKING CHANGE** — `ise_dc_query` is now checked by a real Oracle-dialect SQL parser (`sqlglot`), replacing regex checks that could be bypassed. The query must parse as exactly one read-only SELECT (`WITH`, `UNION`, `INTERSECT` and `MINUS` are allowed), and **every** table anywhere in it — in FROM, joins, subqueries, `EXISTS`, scalar subqueries and set operations — must be a Data Connect catalog view or `DUAL`. CTE names are resolved per scope, so a CTE cannot shadow a real object. Unparseable SQL is rejected. The following are now refused:
   - database links (`@`), schema-qualified names, and qualified function calls (`x.y(...)`, `"X"."Y"(...)`);
   - system schemas and packages (`SYS`, `DBMS_*`, `UTL_*`, `CTX_*`, `SDO_*`, …) and URI/XML types (`HTTPURITYPE`, `XMLTYPE`, `XMLTABLE`, …);
   - `SYS_CONTEXT`;
   - `FOR UPDATE`, `LATERAL`/`CROSS APPLY`/`OUTER APPLY`, and table functions such as `TABLE(...)` and `JSON_TABLE`;
   - SQL comments, and `q'…'` quoting.

   The time-predicate and join heuristics run on a copy with string literals blanked, so a literal can no longer fake them. Several valid queries the old checks rejected now pass: a literal `'q'`, `(+)` outer joins, `WITH r (n) AS …`, and columns or aliases named like `system_name`. The tool's own example has been corrected.
6. The raw passthroughs (`ise_ers_request`, `ise_openapi_request`, `ise_mnt_request`) now reject percent-encoded `.`, `/`, `\` and `%`, as well as backslash, `?`, `#`, `;` (path parameters), empty segments (`//`), control characters and dot-segments in `path`. Pass query parameters through `params`. Typed MnT tools now URL-encode each path parameter (colons are kept, so MAC addresses are unchanged), as Open API tools already did, and reject `.`, `..` and empty values.
7. Refusals and errors (invalid arguments, blocklist, destructive gate, unknown tool, resource limits, exceptions) now return `isError: true` so clients and models can tell them apart from success. Successful results are unchanged.
8. Every tool now carries MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) so clients can auto-approve reads and prompt on destructive calls. These are hints only; the server-side gates remain authoritative.
9. **BREAKING CHANGE** — Admin TLS (ERS, Open API, MnT) now uses an explicit `ssl.SSLContext` with a TLS 1.2 minimum, replacing httpx's deprecated `verify=<path>`. Hostname checking stays on. The httpx clients set `trust_env=False`, so the `HTTP(S)_PROXY`, `SSL_CERT_FILE` and `SSL_CERT_DIR` environment variables no longer affect admin connections: credentials go only to the configured host, trusting only `ca_cert_path` or certifi. If you relied on a proxy variable, connect directly. Data Connect thin-mode TLS also has a 1.2 minimum.
10. `cisco-ise-mcp refresh` only runs the project's own `scripts/refresh_catalog.py`. It no longer runs one found in the current directory.
11. Tool results are serialized as compact JSON (no indentation; non-ASCII kept as-is). Information is unchanged. Result text is about 24% smaller on representative payloads.
12. Repeated schema text was shortened: the `deployment` property (on about 190 tools), `confirm`, the Data Connect filter properties, and the add/update deployment tools, which now share one field table. Property names, types, enums, defaults and required fields are unchanged, and key guidance is pinned by tests. `tools/list` went from 168,775 to 132,150 characters (−22%, about 9k fewer tokens per session) after absorbing the new annotations.
13. ERS GET responses drop per-row and per-object `link {rel,href,type}` objects. `previousPage`/`nextPage` link objects become `has_previous`/`has_next` booleans next to `total`. A 100-row list shrinks by about 63%. Set `CISCO_ISE_MCP_RAW_ERS=1` to get raw responses.
14. **BREAKING CHANGE** (MCP 2.x clients only) — `structuredContent` is no longer sent by default. No tool declares an `outputSchema`, so it was a duplicate of the text block, and response size roughly halves. Set `CISCO_ISE_MCP_STRUCTURED=1` if your client reads `structuredContent`.
15. Server logs now go to **stderr** (level from `CISCO_ISE_MCP_LOG_LEVEL`, default WARNING). Previously nothing configured logging, so security and limit warnings could be lost. stdout stays reserved for JSON-RPC.
16. Dependency changes:
    - Floors raised to `mcp>=1.30`, excluding 2.0.x and 2.1.x (security advisories). Extras: `v1` is `>=1.30,<2`, `v2` is `>=2.2,<3`.
    - Upper bounds added for the major versions of httpx, python-dotenv, oracledb, keyring and pyyaml.
    - `jsonschema` is now declared as a direct dependency, and `sqlglot` (`>=30,<31`, pure Python) has been added for the SQL guard.
    - Lockfile upgrades: mcp 2.3.0 / 1.30.0, pyjwt 2.15.1, httpx2/httpcore2 2.16.0, opentelemetry-api 1.45.2, anyio 4.16.0, certifi 2026.10.23 (removes a CA root with compromised intermediates), cryptography 50.0.2.

    `pip-audit` reports no known vulnerabilities.
17. Added `tests/test_security_20261106.py`, with regression tests for every item above, including every bypass found by an independent security review of this release. The suite grew from 147 to 366 tests, and passes on both MCP SDK 1.30 and 2.3.
18. **BREAKING CHANGE** — **Read-only by default.** Unless `CISCO_ISE_MCP_ALLOW_DESTRUCTIVE=1` is set, the server makes no create, update or delete call of any kind: no ERS/Open API writes, no CoA, no session deletes, no backup/restore/patch, and no deployment add/update/remove by the agent. `CISCO_ISE_MCP_ALLOW_DESTRUCTIVE` is now the single write switch; it used to gate only deletes, restores, rollbacks and similar, so creates and updates previously ran without it.
    - Tools that could make a change are **not loaded**: `tools/list` shows 163 of 203 tools and is about 27% smaller.
    - The raw passthroughs stay available but accept `GET` only, and a GET to an MnT CoA path is still refused.
    - A client with a stale tool list that calls a hidden tool receives `read_only_mode` with `isError: true`.
    - With the switch on, all tools load and destructive calls still require `confirm=true`.
    - Tools listed in `CISCO_ISE_MCP_BLOCKED_TOOLS` are never loaded, in either mode.
    - **To adapt:** set `CISCO_ISE_MCP_ALLOW_DESTRUCTIVE=1` to keep making changes, and manage deployments with the `cisco-ise-mcp` CLI while in read-only mode. The README now has a read-only callout near the top.
19. **BREAKING CHANGE** — **Every tool call is now audited**, reads included, in daily files at `<config home>/logs/YYYY-MM-DD.log` (local date). These replace the single `audit.log`, which previously recorded only changes; an existing `audit.log` is left in place and no longer written.
    - **Line format:** each line starts with the local date and time with UTC offset (e.g. `2026-11-06T14:03:22.123-06:00`), followed by a JSON object with:
      - `tool` — the function called;
      - `access` — `read`, `write`, `destructive`, `registry` or `cli`;
      - `status` — `attempt`, `ok`, `error` or `denied`;
      - `deployment`, `duration_ms`, `error`;
      - the sanitized `arguments`.
    - **Request bodies** are now recorded (sanitized) so the log shows what was created or changed.
    - **Secrets:** values of secret-like keys at any depth, `password=`/`token:` text, and `Bearer`/`Basic` credentials are replaced by `*****`.
    - **Permissions:** the folder is `0700` and files are `0600`, re-applied on every write. Log files are never written through a symlink.
    - **Retention:** new variable `CISCO_ISE_MCP_LOG_RETENTION_DAYS` (default 365, kept within 90–3650). It is an environment variable rather than a `deployments.json` setting so the AI agent cannot shorten its own audit trail. Only files named exactly `YYYY-MM-DD.log` are deleted.
    - **Personal data:** arguments such as usernames, MAC/IP filters and SQL are logged; treat the logs as sensitive.
20. `.gitignore` now also excludes `logs/`, `*.log`, private-key and certificate exports (`*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.crt`, `*.cer`, `*.der`), and tool caches.
21. The minimum allowed versions of `python-dotenv` (now `>=1.2.2`) and, in the `dev` extra, `pytest` (now `>=9.0.3`) were raised so a plain `pip install` cannot pick a version with a published advisory. Every other declared minimum already excluded all known advisories, and all locked versions are free of them.
22. `docs/USER_GUIDE.md` §10 has been rewritten as a full configuration reference:
    - **Variable tables.** Every user-settable variable is listed with its function, accepted values and default, grouped as access control, audit/output, resource limits, and locations/passwords. Values were checked against the code, including how zero and out-of-range values behave.
    - **Where to set variables.** Covers the MCP client `env` block (with examples), the `.env` file in the config home (with per-OS paths), and the shell or container environment. It explains the order of precedence: client/shell environment beats the config-home `.env`, which beats the built-in defaults. A restart is needed after changes.
    - **Corrections.** The previous text said `.env` is read from the project folder; it is read only from the config home. `CISCO_ISE_MCP_HOME` cannot be set inside `.env`.
    - **`deployments.json` field reference.** A new table describes every field.
    - **`.env.example`** was updated to match.

## 2026/08/27

1. Added a shared resource-governance framework (`src/cisco_ise_mcp/limits.py`) providing per-deployment, per-surface concurrency semaphores, token-bucket rate limiting, and structured limit-exceeded refusals. Environment variables act as hard ceilings that per-deployment registry values may only tighten, so an AI agent cannot raise its own budget.
2. Replaced the per-call Data Connect Oracle connection with a pooled connection (5 concurrent sessions by default), eliminating a TCPS handshake, authentication and dedicated server process on the Monitoring node for every single query. The pool uses `min=0` so connections stay lazy, matching the previous behaviour, and falls back to per-call connections if the driver refuses the pool rather than weakening TLS.
3. Added a 60-second Data Connect query timeout via `oracledb` `call_timeout`, which sends an out-of-band break so the Monitoring node stops executing the statement instead of the client merely abandoning it. Reports that previously ran longer than 60 seconds will now be cancelled and return actionable guidance.
4. Moved Data Connect query execution off the asyncio event loop with `asyncio.to_thread`, so a slow SQL query no longer stalls concurrent ERS, Open API and MnT tool calls.
5. Added a default 7-day `days_back` window to Data Connect views that have a time column, preventing unbounded full scans of large event views such as `radius_authentications`. Values above the 90-day maximum are clamped down to 90 rather than rejected, so a request for 120 days returns 90 days of data and is logged at WARNING with both values. Result shapes are unchanged and both behaviours are stated in each tool's schema, but queries that previously omitted `days_back` and returned all-time data now return only the last 7 days.
6. **BREAKING CHANGE** — `ise_dc_query` now enforces cost guards on raw SELECT statements. A missing row limit is no longer an error: a query without a `FETCH FIRST` clause automatically receives one (500 rows, or 5000 when the query aggregates), and an explicit limit is honoured unchanged. Three conditions still cause rejection, because they cannot be corrected automatically without rewriting the operator's own logic: a large event ("fact") view referenced with no time predicate, a join missing its `ON` condition, and joining more than three fact views (`CISCO_ISE_MCP_DC_MAX_FACT_VIEWS`). A query such as `SELECT username, nas_ip_address FROM radius_authentications WHERE username='bob'` will now be rejected for the missing time predicate. Small configuration and lookup views such as `network_devices`, `security_groups` and `failure_code_cause` are classified as dimensions and may still be joined without limit, so multi-view reports remain possible. This was enforced immediately rather than phased in because an unbounded ad-hoc query against the monitoring database is the primary resource-exhaustion risk this release exists to close; a warn-only period would have left the ISE Monitoring node exposed for another release cycle. The refusal message names the rule that was missed and shows a corrected example.
7. Added per-deployment Data Connect rate limiting of 30 queries per minute to bound sustained load that a concurrency cap alone does not catch, such as an agent issuing queries in a loop.
8. Capped ERS, Open API and MnT concurrency at 10, 15 and 5 respectively — a small fraction of Cisco's documented 100 and 150 connection limits, which are deployment-wide and shared with pxGrid, the admin GUI and other integrations. The HTTP socket pools are bounded to match.
9. Added a `limits` sub-configuration to the deployment registry, surfaced through `get_deployment_config` and settable via `ise_add_deployment`, `ise_update_deployment` and the CLI. Existing registries without a `limits` block load unchanged and receive the documented defaults; no migration or version bump is required.
10. Added the `ise_limits_status` meta tool reporting configured caps, effective values after environment clamping, and live usage. `ise_test_deployment` now also reports effective limits and warns when a per-deployment value was reduced by an environment ceiling.
11. Added operator-side Data Connect query logging (view, applied window and its source, duration, row count, outcome), keeping the existing mutation-only audit trail unchanged. Filter values and raw SQL are deliberately not logged, since filter values are typically usernames, MAC addresses or IPs. A one-time startup log records which limit defaults were applied when a registry has no `limits` block.
12. Updated `README.md` and `docs/USER_GUIDE.md` — including a new "Upgrade impact" section — plus `deployments.example.json` and `.env.example`, to document the new limits, the default `days_back` window, the `ise_dc_query` breaking change and the new tool.
13. `ise_dc_query` now accepts common table expressions (`WITH ... AS ( ... ) SELECT ...`), which the previous SELECT-only check rejected outright. CTE names are treated as local aliases, while every existing guard — catalog view allow-listing, no SQL comments, no stacked statements, row bounds, time predicates and join conditions — continues to apply inside CTE bodies.
14. Added `tests/test_limits.py` (37 tests) covering env-ceiling precedence, limiter refusals and slot release, `days_back` defaulting and clamping, row-bound injection, CTE handling, the fact-view classification, and the upgrade path for a registry with no `limits` block.
