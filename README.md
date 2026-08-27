# Cisco ISE MCP Server

An [MCP](https://modelcontextprotocol.io) server that gives an AI agent programmatic access to **one or more** Cisco Identity Services Engine (ISE) deployments through four complementary API surfaces. When more than one surface can serve a request, they are used in **precedence order — Open API → ERS → Data Connect → Monitor API** — falling back to a lower surface only if the higher one can't serve the task or errors:

- **Open API** (ISE 3.1+) — repository, backup/restore, certificates, policy, TrustSec, patch, licensing, deployment/nodes, plus a generic passthrough for any `/api/` endpoint. *Highest precedence.*
- **ERS** (External RESTful Services) — full CRUD on ISE configuration objects and current state.
- **Data Connect** (ISE 3.2+) — read-only SQL against the ISE monitoring database. The surface for **reporting / historical / aggregate / audit** data that no higher surface exposes.
- **Monitoring (MnT)** — legacy `/admin/API/mnt` live session / CoA / failure-reason queries (returns XML). *Lowest precedence — use only when no higher surface serves the request.*

### Multiple deployments

One running server can target many ISE deployments (e.g. a RADIUS deployment, a TACACS+ deployment, a VPN deployment). You pick the target per request by **name** or **number**:

> "List all RADIUS policy sets on **Deployment 1**"
> "Add network device 'Office' (10.10.10.10) to the **TACACS Only** deployment"

- Non-secret config lives in a per-user registry (`deployments.json`); **passwords are stored separately in the OS keyring** (or injected via env vars on headless hosts).
- Each deployment has its **own Data Connect certificate**.
- Add deployments straight from the AI agent (no file editing) or with the CLI.

Tool surfaces are built from the Cisco-published OpenAPI **YAML specs** (ERS, Open API, Monitoring) — downloaded via `iseapi_yaml/links.yaml` and compiled into versioned JSON catalogs under `src/cisco_ise_mcp/catalog/` by `scripts/refresh_catalog.py`; Data Connect views are scraped from Cisco DevNet. On a **first install** run `uv run python scripts/refresh_catalog.py --all` to build all four catalogs; later runs (`scripts/refresh_catalog.py` or `cisco-ise-mcp refresh`) auto-build ERS + Open API and only rebuild the Data Connect / Monitor API catalogs if a deployment enables them. Target release: **Cisco ISE 3.4**. **203 tools** (82 ERS, 66 Open API, 17 Monitoring, 27 Data Connect, 11 meta).

### Resource limits

Cisco documents roughly **100 concurrent ERS** and **150 concurrent Open API** connections per deployment — budgets shared with pxGrid, the admin GUI and every other integration — and publishes **no limits at all** for Data Connect. Since the ISE `dataconnect` account is a read-only Oracle user with no DBA rights, server-side database governance is unavailable, so this server enforces its own limits client-side and claims only a small slice of the documented budgets:

- **Data Connect** — 5 concurrent pooled sessions, a 60-second query timeout that cancels the statement *on the Monitoring node*, 30 queries/minute, and a default 7-day window on time-series views (larger requests are reduced to 90 days, not rejected).
- **ERS / Open API / MnT** — 10 / 15 / 5 concurrent calls.

Every value is tunable. Environment variables (`CISCO_ISE_MCP_*`, see `.env.example`) are **hard ceilings**; a per-deployment `limits` block may only tighten them. Call `ise_limits_status` or `cisco-ise-mcp test <slug>` to see what is in force.

## What changed

**[docs/UPDATES.md](docs/UPDATES.md)** is the change log for this server — every release lists, by date, each modification that was made and why. Check it after pulling a new version: entries marked **BREAKING CHANGE** describe behaviour that differs from previous releases, what stops working, and how to adapt.

## Quick start (with [uv](https://docs.astral.sh/uv/))

```bash
uv venv && uv pip install -e .
uv run python scripts/validate.py                    # offline self-test (no ISE needed)
uv run python scripts/refresh_catalog.py --all       # FIRST RUN: build all four catalogs (later refreshes auto-gate to enabled surfaces)
uv run cisco-ise-mcp add --name "RADIUS Only" --host 10.1.1.1 --ers-username ers-admin
uv run cisco-ise-mcp set-credential radius-only      # secure password prompt
uv run cisco-ise-mcp update radius-only --host 10.1.1.9   # fix/add fields later (optional)
uv run cisco-ise-mcp list
uv run cisco-ise-mcp                                 # start the stdio MCP server
```

New to this? Start with **[QUICKSTART.md](docs/QUICKSTART.md)**.

### MCP SDK v1 vs v2

The server runs under **either** major of the `mcp` Python SDK — the same code
auto-detects which one the venv installed. Only one `mcp` can be installed per
environment, so pick the major with an install extra (separate venvs from this
one repo):

```bash
uv pip install -e '.[v1]'    # mcp 1.x   (or:  uv sync --extra v1)
uv pip install -e '.[v2]'    # mcp 2.x   (or:  uv sync --extra v2)
```

Plain `uv pip install -e .` accepts either major (`mcp>=1.28,<3`). On **v2**,
tool results additionally carry a machine-readable `structuredContent` payload;
**v1** returns text only. Both start the server the same way — `cisco-ise-mcp`,
`python -m cisco_ise_mcp`, or `python -m cisco_ise_mcp.server`.


Full setup (Windows / macOS / Linux), credential security, Data Connect certificates, adding multiple deployments, connecting Claude Desktop / Hermes / other MCP clients, the tool list, and troubleshooting are in **[USER_GUIDE.md](docs/USER_GUIDE.md)**. Recent changes are listed in **[UPDATES.md](docs/UPDATES.md)**.
