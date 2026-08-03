# Authentication Design — agent ↔ MCP server

Status: **phase 1 shipped (abstraction + local allow/deny); phase 2 designed, not built.**

## Why this exists

Today the server runs over **stdio only** (`_mcpcompat.serve` → `stdio_server`).
On stdio the connected agent and the local OS user are the trust boundary — the
process is launched by, and inherits the privileges of, the user who holds the
deployment registry and keyring. So there is nothing to authenticate at the MCP
layer, and the default `NullAuthenticator` authorizes every request.

Authentication becomes meaningful only when the server is **network-reachable**
for multiple users. This document captures that design so it can be implemented
as a reviewed, self-contained phase without reworking the core.

## Phase 1 (shipped)

- `src/cisco_ise_mcp/auth.py`
  - `Authenticator` protocol: `authenticate(credentials) -> Principal | None`.
  - `NullAuthenticator` — stdio default.
  - `AllowListAuthenticator` — local permit/deny on client id / bearer token,
    fail-closed (empty allow = deny all), constant-time comparison, policy read
    from `<config-home>/auth.json` (`0o600`, same hygiene as `deployments.json`).
  - `build_authenticator()` factory: env `CISCO_ISE_MCP_AUTH` > `auth.json` mode
    > `null`.
- `server.RUNTIME_TRANSPORT` (`local` | `remote`) + `server.set_transport()`.
  Consumed today by the Finding #7 error-verbosity path (`_error_payload`):
  verbose on `local`, generalized message + `error_id` on `remote`.

`auth.json` example (only used when a network transport is active):

```json
{ "mode": "allowlist", "allow": ["client-abc", "client-def"], "deny": [] }
```

## Phase 2 (designed, not built)

### Transport
Add a Streamable-HTTP transport alongside stdio in `_mcpcompat`. The CLI gains a
`serve --http --host --port` path that, on startup, calls
`server.set_transport("remote")` so error redaction and the allow-list activate
automatically. stdio remains the default (smallest attack surface).

### Enforcement point
A single authentication middleware in front of `call_tool`:
1. extract credentials from the request (bearer token / validated claims),
2. `principal = authenticator.authenticate(credentials)`,
3. on `None` → MCP auth error (no tool dispatch, audited as `denied`),
4. on success → attach `principal` to the audit record and (future) per-principal
   deployment scoping.

### OAuth2 (two modes)
- **External IdP (recommended):** validate IdP-issued access tokens (signature,
  `iss`, `aud`, `exp`, scopes) using the MCP SDK's auth support. Add an
  `OAuthAuthenticator` that maps validated claims → `Principal`.
- **Local authorization server (optional):** a bundled minimal AS for isolated
  deployments without an external IdP.

### Per-principal authorization (future)
Extend the registry so a `Principal` maps to the deployments/surfaces/verbs it
may use — composing with the destructive-tool gate (`CISCO_ISE_MCP_ALLOW_DESTRUCTIVE`
+ `CISCO_ISE_MCP_BLOCKED_TOOLS`) so "who" and "what" are both constrained.

## New attack surface phase 2 introduces (must be reviewed before shipping)
- A listening socket (network exposure; bind/TLS/rate-limiting concerns).
- Token validation logic (signature/`aud`/`exp`/replay).
- Credential storage/rotation for the local-AS mode.
- Multi-tenant isolation: one principal must not reach another's deployments.

Ship phase 2 behind its own security review; keep stdio as the default so the
initial public release carries no network attack surface.
