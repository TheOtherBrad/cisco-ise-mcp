# Cisco ISE MCP Server — User Guide

A complete guide to installing, configuring, and running the Cisco ISE MCP
server, written for **all skill levels**. If you just want the fastest path,
read **[QUICKSTART.md](QUICKSTART.md)** first, then come back here for detail.

> **Multiple deployments:** one server can manage **multiple ISE deployments**.
> You choose the target per request by **name** or **number**, each deployment
> stores its credentials and Data Connect certificate **separately and securely**,
> and you can add deployments straight from the AI agent — no file editing.

## Table of Contents

1. [What this server does](#1-what-this-server-does)
   - [Upgrade impact (read this after updating)](#upgrade-impact-read-this-after-updating)
2. [Choosing the right surface (routing)](#2-choosing-the-right-surface-routing)
3. [Prerequisites](#3-prerequisites)
4. [Installation (Windows / macOS / Linux)](#4-installation-windows--macos--linux)
5. [The deployment model](#5-the-deployment-model)
6. [Adding & managing deployments](#6-adding--managing-deployments)
7. [Credentials & secure storage](#7-credentials--secure-storage)
8. [Data Connect setup (per deployment)](#8-data-connect-setup-per-deployment)
9. [Running the server](#9-running-the-server)
10. [Environment variables](#10-environment-variables)
11. [Connecting an AI agent](#11-connecting-an-ai-agent)
12. [Available tools](#12-available-tools)
13. [Usage examples](#13-usage-examples)
14. [Testing & validation](#14-testing--validation)
15. [Troubleshooting](#15-troubleshooting)
16. [Security notes](#16-security-notes)

## 1. What this server does

The server exposes a Cisco ISE deployment to an AI agent (Claude Desktop, Hermes,
or any [MCP](https://modelcontextprotocol.io) client) as a set of **tools**. It
covers four ISE API surfaces:

| Surface | Use it for | Transport |
| --- | --- | --- |
| **Open API** (`ise_openapi_*`) | *Highest precedence.* System, lifecycle & current state: policy sets, certificates, backup/restore, repositories, patches, licensing, deployment/nodes | HTTPS `/api/` (Basic auth), port 443 gateway or 9070 |
| **ERS** (`ise_ers_*`) | Configuration CRUD & current state: endpoints, network devices, users, identity/endpoint groups, SGT/SGACL, portals, guests | HTTPS `/ers/config` (Basic auth), port 443 or 9060 |
| **Data Connect** (`ise_dc_*`) | **Reporting / historical / aggregate / audit** data no higher surface exposes: authentications, accounting, audits, posture, profiling, sessions | Oracle TCPS (read-only SQL), port 2484 |
| **Monitoring (MnT)** (`ise_mnt_*`) | *Lowest precedence.* Legacy live queries: active session count/list, session by MAC/IP/username, CoA reauth/disconnect, failure reasons | HTTPS `/admin/API/mnt` (Basic auth), returns **XML** |

Every tool also accepts an optional **`deployment`** argument so the same
toolset can act on any of your configured ISE nodes. Target release: **Cisco ISE 3.4**.

### Upgrade impact (read this after updating)

Upgrading an existing installation requires **no configuration changes**. A registry
written by an earlier version has no `limits` block; it loads unchanged and receives the
documented defaults, and no registry version bump or migration is involved.

Four behaviours *do* change, because this release adds resource limits that protect the
ISE Monitoring node (see [Resource limits](#resource-limits-data-connect) in section 8):

| Change | What you will notice |
| --- | --- |
| **`ise_dc_query` cost guards** — **BREAKING** | A raw `SELECT` with no row limit now has one added automatically (500 rows, or 5000 when aggregating) instead of failing. But a query is **rejected** if it references a large event view without a time predicate, has a `JOIN` with no `ON` condition, or joins more than three large event views. `SELECT username, nas_ip_address FROM radius_authentications WHERE username='bob'` worked before and is now refused — add `AND "TIMESTAMP" >= SYSTIMESTAMP - NUMTODSINTERVAL(7,'DAY')`. Small lookup views (`network_devices`, `security_groups`, `failure_code_cause`, ...) are exempt and still join freely. |
| **7-day default window** | A view query that omits `days_back` used to return *all* history; it now returns the last 7 days. There is no error — just a narrower result. Pass `days_back` explicitly to widen it. |
| **90-day maximum** | `days_back` above 90 is **reduced to 90, not rejected** — a request for 120 days returns 90 days of data and is logged at WARNING. |
| **Concurrency and rate caps** | More than 5 simultaneous Data Connect queries (or 10 ERS / 15 Open API / 5 MnT calls) per deployment are refused with guidance after a short wait. A single query is also cancelled after 60 seconds. |

Why enforce the breaking change immediately rather than warn first: an unbounded ad-hoc
query against the monitoring database is the specific risk this release exists to close,
and a warn-only period would leave the Monitoring node exposed for another release.

Run `ise_limits_status` (or `cisco-ise-mcp test <slug>`) after upgrading to see the
effective limits. Full details are in [docs/UPDATES.md](UPDATES.md).

## 2. Choosing the right surface (routing)

> **Note.** Data Connect queries are rate-limited and time-bounded by default to protect
> the ISE Monitoring node — see [Resource limits](#resource-limits-data-connect) in section 8.

The rule the agent follows (and that you can ask it about with the `ise_route`
and `ise_capabilities` tools): surfaces are ranked by **precedence** — when more
than one can serve a request, the agent uses the highest-ranked and only falls
back to a lower one if the higher surface can't serve the task, isn't enabled for
the deployment, or errors.

1. **Open API** (`ise_openapi_*`) — system / policy / certificate / backup / patch / license / deployment lifecycle **and current state**.
2. **ERS** (`ise_ers_*`) — configuration object CRUD & current state (used when Open API has no endpoint for the object).
3. **Data Connect** (`ise_dc_*`) — reporting / historical / aggregate / audit data that **only** the monitoring database exposes (authentications, accounting, posture, profiling, sessions, config-change audit).
4. **Monitor API / MnT** (`ise_mnt_*`) — legacy live session / CoA / failure-reason lookups with no higher equivalent (returns XML).

Precedence is a **tiebreaker among surfaces that can actually serve the task.** A
"list network devices" read prefers ERS over a Data Connect view, but "how many
endpoints onboarded last week" still routes to Data Connect — no higher surface
holds that history. Data Connect always outranks the Monitor API, so it's preferred
for any reporting it can serve. You rarely need to think about this — ask in plain
language and the agent picks the surface.

**A surface has to be configured for that deployment to be used.** Data Connect must be
enabled with a certificate (or OS trust) and its password; the Monitor API (MnT) is
**opt-in** per deployment. If you ask for something that needs a surface that isn't set up,
the tool isn't attempted — you're told which configuration (Data Connect or MAPI) to add.

## 3. Prerequisites

### ISE side (per deployment)

Do this on **each** ISE deployment you intend to manage:

1. **Enable ERS** — Enable API Services on the Primary Administration Node.\
   *Administration → System → Settings → API Settings → API Service Settings → ERS (Read/Write)*.
2. **Create/identify an ERS account** — Create or modify an existing account for API access.
   You will provide this username when you add the deployment, and its password
   when you run `set-credential`. The user account will need to be assigned to
   either **ERS Admin** (Read/Write) or **ERS Operator** (Read-Only) admin group. Optionally, to 
   use the Monitor API, this user account will need to be assigned to the **MNT
   Admin** group.\
   *Administration → System → Admin Access → Administrators → Admin Users*
3. **(For reporting) Enable Data Connect** —  Enable Data Connect, set the `dataconnect` user password, 
   and **export the Data Connect certificate** (you will save this as a `.pem` file per deployment —
   see [section 8](#8-data-connect-setup-per-deployment)).

Ports: ERS/Open API use **443** through the admin gateway by default (some
deployments use **9060**/**9070** for the dedicated listeners). Data Connect uses
**2484**.

### Client side (where this server runs)

- A computer running **Windows, macOS, or Linux**.
- **[uv](https://docs.astral.sh/uv/)** (recommended — it installs Python for you),
  or an existing **Python 3.10+**.
- Network reachability from this computer to each ISE node on the ports above.
- For OS-keyring password storage (the default): a desktop OS keyring is present
  automatically on Windows and macOS; on Linux see
  [Troubleshooting](#15-troubleshooting) if you are headless.

## 4. Installation (Windows / macOS / Linux)

### Recommended: with `uv`

`uv` manages Python and the project's dependencies in one tool, identically on
every OS.

**Install uv**

- **Windows (PowerShell):**
  ```powershell
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  ```
- **macOS / Linux (Terminal):**
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

Reopen your terminal, then check: `uv --version`.

**Install the server** — from the **project root** (the folder above this
`docs/` directory, containing `pyproject.toml`):

```bash
uv venv
uv pip install -e .
```

`uv` automatically downloads a suitable Python if you don't have one. Every command
below is run with the `uv run` prefix, which uses this environment — you do not need
to manually "activate" it.

**MCP SDK v1 vs v2.** This server runs under either major of the `mcp` Python SDK and
auto-detects which one your environment installed — only one `mcp` can be installed per
venv. The plain `uv pip install -e .` above accepts either (`mcp>=1.28,<3`). To pin a
major, use an install extra (build a separate venv per major from this one repo):

```bash
uv pip install -e '.[v1]'    # mcp 1.x   (or:  uv sync --extra v1)
uv pip install -e '.[v2]'    # mcp 2.x   (or:  uv sync --extra v2)
```

On **v2**, tool results additionally carry a machine-readable `structuredContent` payload
alongside the text; on **v1** results are text only. Everything else — the tools, the CLI,
and how you start the server — is identical across majors.

Verify (offline self-test, no ISE required):
```bash
uv run python scripts/validate.py
```
Expect `All checks passed.`

**Build the tool catalogs — first install.** The tool surfaces are compiled from the Cisco
OpenAPI YAML specs listed in `iseapi_yaml/links.yaml` into JSON catalogs under
`src/cisco_ise_mcp/catalog/`. Pre-built catalogs ship with the project, but on a **first
install** build all four fresh — run this right after the self-test above:
```bash
uv run python scripts/refresh_catalog.py --all   # first run: build ERS + Open API + Data Connect + Monitor API
```

**Later refreshes.** To pull the latest specs (downloaded into
`iseapi_yaml/{ers,openapi,monitoring}/`) and re-scrape the Data Connect views, run:
```bash
uv run python scripts/refresh_catalog.py        # or:  uv run cisco-ise-mcp refresh
```
Add `--no-download` to rebuild from the already-downloaded local specs without
fetching, or `--only ers,dc` to rebuild a specific subset. The server reads only the compiled
JSON catalogs at runtime, so it starts fast and offline.

**Auto-gating by what you use.** ERS and Open API are always built. **Data Connect** and
**Monitoring** are built (and their specs downloaded) only when at least one configured
deployment enables them — so if no deployment uses Data Connect, its views aren't re-scraped,
and if none uses the Monitor API, the Monitoring spec isn't fetched. A skipped surface leaves
its existing catalog file untouched. Pass **`--all`** to force all four regardless (as on a
first install), or `--only …` to pick an explicit set (either overrides the auto-selection).

### Alternative: with plain `pip`

If you already have **Python 3.10+** and prefer `pip`:

- **Windows (PowerShell):**
  ```powershell
  python -m venv .venv
  .venv\Scripts\Activate.ps1
  pip install -e .
  ```
  (If activation is blocked, run once:
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.)
- **macOS / Linux (Terminal):**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e .
  ```

With `pip`, drop the `uv run` prefix from later commands (the virtual environment is
already activated), e.g. just `cisco-ise-mcp list`.

### Developer extras (optional)

To run the unit tests, install the `dev` extras: `uv pip install -e ".[dev]"`,
then `uv run pytest -q`.

## 5. The deployment model

A **deployment** is one ISE system (one admin node you talk to). Each deployment has:

- a **name** you choose (e.g. `RADIUS Only`) and a **number** (1, 2, 3 … in the order
  added) and a **slug** (the lower-case, hyphenated name, e.g. `radius-only`);
- non-secret settings (host/IP, ports, TLS flags, Data Connect host + mode + certificate path);
- **secrets** (the ERS/Open API password and, if used, the Data Connect password).

**Non-secret settings** are stored in a registry file, `deployments.json`. **Secrets are
never stored there** — they live in your OS keyring (or are injected via environment
variables). The registry lives in a per-user config folder:

| OS | Default location |
| --- | --- |
| **Windows** | `%APPDATA%\cisco-ise-mcp\deployments.json` |
| **macOS** | `~/Library/Application Support/cisco-ise-mcp/deployments.json` |
| **Linux** | `$XDG_CONFIG_HOME/cisco-ise-mcp/deployments.json` (else `~/.config/cisco-ise-mcp/…`) |

You can override the folder with the `CISCO_ISE_MCP_HOME` environment variable (useful
for containers or for keeping certs and registry together). On first launch the server
(or any `cisco-ise-mcp` command) **auto-creates a blank `deployments.json`** for you —
ready to fill in, with **no example/placeholder deployments**. A sample showing the file
structure is in **`deployments.example.json`** (reference only) — but you normally never
edit the registry by hand; use the agent or the CLI below.

You refer to a deployment in any tool by **name, slug, or number**:

> "List RADIUS policy sets on **Deployment 1**" · "…on **RADIUS Only**" · "…on **radius-only**"

### Data Connect on a separate node (PAN vs MnT)

The deployment's **host** is the primary **Admin** node (PAN) used for ERS and Open API.
**Data Connect** (the read-only reporting database, port 2484) runs on the **Monitoring
(MnT)** persona, which is frequently a *different* node/IP in distributed deployments.

Each deployment also has an optional **Data Connect host**:

- **Leave it empty** (the default) and Data Connect uses the same admin host — correct for
  a standalone node or any setup where PAN and MnT are co-located. Existing registries that
  predate this field behave exactly this way.
- **Set it** to the MnT node's IP/FQDN when Monitoring lives elsewhere. Only Data Connect
  uses it; ERS/Open API stay on the admin host.

> "Add **Campus ISE**, host **10.1.1.1** (the PAN), with Data Connect on **10.1.1.5** (the MnT node)."
>
> "On **RADIUS Only**, point Data Connect at **10.1.1.5**." · "…clear the Data Connect host so it uses the admin node again."

The Data Connect **certificate** you export is the MnT node's — trust is by certificate, not
hostname, so a separate host works with no extra TLS configuration.

## 6. Adding & managing deployments

### Option A — from the AI agent (no file editing)

Just ask. For example:

> "Add an ISE deployment named **TACACS Only**, host **10.2.1.1**, ERS username **ers-admin**."

The agent calls the `ise_add_deployment` tool, which saves the **non-secret** settings
and replies with the exact terminal command to set the password (passwords are never
entered through the agent). If you leave out something required, it tells you **everything
that's missing at once**:

> *Cannot add the deployment — please provide/fix:*
> *- name — a descriptive label, e.g. 'RADIUS Only'*
> *- host — the ISE admin-node IP or FQDN, e.g. 10.1.1.1*

**The agent walks you through the optional surfaces** (it asks rather than assuming):

1. **Required basics** — it confirms a `name`, `host`, and `ers_username` (the ERS/Open
   API account).
2. **Data Connect (reporting)?** — if you didn't mention it, the agent asks whether you
   need Data Connect reporting, or **ERS API only**. Choosing "ERS only" disables Data
   Connect for this deployment.
3. **Same node or a separate MnT node?** — if Data Connect is on a different node than the
   admin host, the agent records that as the **Data Connect host** (see
   [section 5](#data-connect-on-a-separate-node-pan-vs-mnt)).
4. **Certificate trust** — the agent asks whether the Data Connect certificate is
   **self-signed** or **CA-signed**:
   - **self-signed** → it guides you to export the certificate and save the `.pem`, then
     stores that path.
   - **CA-signed** → you can either use the **OS trust store** (no file to download) or
     point it at the exported **root-CA** file. See [section 8](#8-data-connect-setup-per-deployment).
5. **Monitor API (MAPI / MnT)?** — the agent asks whether to enable the legacy Monitoring
   API for this deployment (it's **off by default** and needs the ERS account in ISE's
   **MnT Admin** group). Data Connect is always preferred over MAPI for reporting.

**Required vs optional, at a glance:** *required* — `name`, `host`, and `ers_username`
(for any ERS/Open API/MnT use). *Optional* — everything else: Data Connect (on by default,
needs a cert **or** OS trust + its own password), the Monitor API (off by default), ports,
TLS flags, and the Data Connect host/mode.

> **Surfaces must be configured to be used.** If you ask for a report on a deployment that
> has Data Connect disabled, or an `ise_mnt_*` query where the Monitor API is off, the tool
> is **not** attempted — the agent tells you exactly which configuration (Data Connect or
> MAPI) to add. Turn it on later with `ise_update_deployment` (see *Editing a deployment*).

Other things you can ask the agent: *"List the deployments available"* (`ise_list_deployments`),
*"On Deployment 2, change the host to 10.2.1.5"* (`ise_update_deployment`),
*"Make Deployment 2 the default"* (`ise_set_default_deployment`), *"Check the VPN Only
deployment"* (`ise_test_deployment`), *"Remove the tacacs-only deployment"*
(`ise_remove_deployment`, which requires a confirm).

### Option B — from the command line

**Standalone node** (Data Connect on the same host as the admin/PAN, self-signed cert):

```bash
uv run cisco-ise-mcp add --name "RADIUS Only" --host 10.1.1.1 --ers-username ers-admin \
    --dc-cert /opt/cisco-ise-mcp/certs/radius-only-dataconnect.pem
```

**Separate Monitoring (MnT) node** for Data Connect (`--dc-host` ≠ `--host`):

```bash
uv run cisco-ise-mcp add --name "Campus ISE" --host 10.1.1.1 --ers-username ers-admin \
    --dc-host 10.1.1.5 \
    --dc-cert /opt/cisco-ise-mcp/certs/campus-dataconnect.pem
```

**CA-signed Data Connect cert via the OS trust store** (no cert file to export) and the
Monitor API turned on:

```bash
uv run cisco-ise-mcp add --name "Prod ISE" --host ise-pan.example.com --ers-username ers-admin \
    --dc-os-trust --enable-monitoring
```

**Guided prompts:** when you run `add` in a real terminal and omit the Data Connect /
certificate / Monitor-API choices, it walks you through the same questions the AI agent
asks (enable Data Connect? same or separate node? self-signed or CA-signed? enable MAPI?).
Pass the flags to skip the prompts, or run non-interactively (a script/pipe) to use flags
and defaults only.

**All `add` options:**

| Flag | Required? | What it's for |
| --- | --- | --- |
| `--name` | **yes** | Descriptive label (not a bare number / "Deployment N"). |
| `--host` | **yes** | ISE admin-node (PAN) IP or FQDN — used for ERS, Open API, and MnT. |
| `--ers-username` | for ERS/Open API/MnT | The ERS/Open API admin account (also used by MnT). |
| `--ers-port` | no (443) | ERS port — 443 gateway, or the dedicated `9060`. |
| `--openapi-port` | no (443) | Open API port — 443 gateway, or the dedicated `9070`. |
| `--verify-ssl` | no (off) | Verify the ISE **admin** TLS cert (turn on once nodes present CA-signed certs). |
| `--ca-cert` | for `--verify-ssl` + private CA² | Path to a PEM CA bundle to trust for ERS/Open API/MnT. Point it at the exported ISE **root CA** when ISE uses an internal CA. |
| `--enable-monitoring` | no (off) | Enable the Monitor API (MAPI / MnT, `ise_mnt_*`). Needs the ERS account in the **MnT Admin** group. |
| `--no-dataconnect` | no | Disable Data Connect (reporting) for this deployment. |
| `--dc-host` | no (= `--host`) | Data Connect / MnT node IP or FQDN when it differs from the admin host. |
| `--dc-cert` | for Data Connect¹ | Path to this node's exported Data Connect `.pem` (self-signed cert, or a CA root file). |
| `--dc-os-trust` | for Data Connect¹ | CA-signed cert: validate against the **OS** CA store instead of a `--dc-cert` file. |
| `--dc-port` | no (2484) | Data Connect Oracle TCPS port. |
| `--dc-mode` | no (thin) | `thin` (PEM cert, no Oracle client) or `thick` (Instant Client + wallet). |
| `--dc-wallet` | thick mode | Wallet directory (`cwallet.sso`), or a thin `ewallet.pem`. |
| `--dc-no-verify` | no | Don't verify the Data Connect server cert (labs only; not recommended). |
| `--dc-user` / `--dc-sid` | no | Data Connect DB user (`dataconnect`) / SID (`cpm10`) — defaults are correct for ISE. |
| `--dc-oracle-lib` | thick mode | Oracle Instant Client directory. |
| `--default` | no | Make this the default deployment. |

¹ When Data Connect is enabled you need **either** `--dc-cert` (self-signed, or a CA root
file) **or** `--dc-os-trust` (CA-signed via the OS store) — not both. Run
`uv run cisco-ise-mcp add --help` for the authoritative list.

² See [Admin TLS trust (ERS / Open API / MnT)](#admin-tls-trust-ers--open-api--mnt) below —
`--verify-ssl` alone trusts only the built-in public-CA (certifi) bundle, so a private ISE
CA additionally needs `--ca-cert`.

### Admin TLS trust (ERS / Open API / MnT)

`--verify-ssl` turns on certificate validation for the three HTTPS admin surfaces (ERS,
Open API, Monitor API). The HTTP client (httpx) validates against the built-in
[**certifi**](https://pypi.org/project/certifi/) bundle of **public** root CAs — and
**nothing else**. In particular it does **not** read the OS trust store, so on macOS
importing your CA into the **Keychain** and marking it *Always Trust* has **no effect** on
this server, and neither does importing the intermediate.

So with a private/enterprise ISE CA (the usual case), `--verify-ssl` on its own fails the
handshake even though the chain is otherwise valid. The fix is to hand the server your CA
explicitly:

1. In ISE, **Administration → System → Certificates → Trusted Certificates**, export the
   **root CA** that signed the admin (EAP/Admin/HTTPS) certificate, in **Base64 / PEM**
   form. Save it as, e.g., `~/certs/ise-root-ca.pem`.
   - You only need the **root**. ISE sends its leaf **and** intermediate in the handshake,
     so once the root is trusted the whole chain validates. (If your ISE does *not* send
     the intermediate, put root **and** intermediate in the same PEM file, root last.)
2. Point the deployment at it:
   ```bash
   cisco-ise-mcp add --name "Prod" --host ise.example.com --ers-username admin \
     --verify-ssl --ca-cert ~/certs/ise-root-ca.pem
   ```
   or add it to an existing deployment:
   ```bash
   cisco-ise-mcp update prod --verify-ssl --ca-cert ~/certs/ise-root-ca.pem
   ```
   From the AI agent, the equivalent field is `ca_cert_path` on `ise_add_deployment` /
   `ise_update_deployment`.

Notes:
- **Hostname checking stays on.** Trust comes from your CA, but the server still verifies
  the admin cert's SAN matches the `--host` you dial — so use the node's FQDN (matching the
  certificate), not an IP, when `--verify-ssl` is on.
- This is the ERS/Open API analogue of Data Connect's `--dc-cert` (root-CA file). The two
  are configured separately: Data Connect trust does not carry over to the admin surfaces.
- Pass `--ca-cert ''` on `update` to clear it and fall back to the certifi bundle (only
  works if the admin cert chains to a public CA).
- `--no-verify-ssl` disables validation entirely — labs only; it exposes admin credentials
  to man-in-the-middle interception.

### Editing a deployment (fix a typo, or add Data Connect later)

Use `update` when a value was entered wrong, or when you need to add information to an
existing deployment (for example, turning on Data Connect and pointing it at a certificate
after the fact). **Only the fields you provide change** — everything else, including stored
passwords, is left exactly as it was.

From the AI agent (no file editing):

> "On the **TACACS Only** deployment, fix the host to **10.2.1.5** and turn on Data Connect
> using cert **/opt/cisco-ise-mcp/certs/tacacs.pem**."

The agent calls `ise_update_deployment`. From the command line the same change is:

```bash
uv run cisco-ise-mcp update tacacs-only \
    --host 10.2.1.5 --enable-dataconnect \
    --dc-cert /opt/cisco-ise-mcp/certs/tacacs.pem
uv run cisco-ise-mcp test "TACACS Only"     # confirm the change works
```

Flags mirror `add`, plus paired on/off switches so you can flip a setting either way:
`--verify-ssl` / `--no-verify-ssl`, `--enable-dataconnect` / `--disable-dataconnect`,
`--enable-monitoring` / `--disable-monitoring`, `--dc-verify` / `--dc-no-verify`,
`--dc-os-trust` / `--dc-no-os-trust`. Pass `--dc-cert ""` (or `--dc-host ""`) to clear a
value — e.g. when switching a node from a self-signed cert to `--dc-os-trust`, clear the
old `--dc-cert`. Run `uv run cisco-ise-mcp update --help` for the full list.

Notes:
- **Passwords are never changed here.** Use `set-credential` (see [§7](#7-credentials--secure-storage)) for those.
- If you pass values that already match, it reports *"No changes"* — safe to re-run.
- It re-checks the deployment afterward and lists anything still missing, with the fix command.

### Renaming a deployment (and `--reslug`)

Every deployment has a short **slug** derived from its name (e.g. *"RADIUS Only"* → `radius-only`).
The slug is the deployment's identity: it's how credentials are stored and how you select it.

- **Cosmetic rename** (the new name produces the *same* slug — e.g. fixing capitalization
  *"radius only"* → *"RADIUS Only"*): just works, nothing else changes.
- **Real rename** (the new name produces a *different* slug — e.g. *"RADIUS Only"* →
  *"RADIUS Prod"*, slug `radius-prod`): this changes the identity and **moves the stored
  passwords** to the new slug, so it must be confirmed with **`--reslug`**.

If you rename to a new slug **without** `--reslug`, the command stops and asks:

```text
$ uv run cisco-ise-mcp update radius-only --name "RADIUS Prod"
Renaming to 'RADIUS Prod' changes this deployment's identity (slug) from 'radius-only'
to 'radius-prod', which also moves its stored credentials. ...
Proceed and migrate slug 'radius-only' -> 'radius-prod' (and its stored credentials)? [y/N]
```

Answer **y** to proceed (same as having passed `--reslug`), or **N** to cancel with no changes.
To skip the prompt, pass it up front:

```bash
uv run cisco-ise-mcp update radius-only --name "RADIUS Prod" --reslug
```

> **From the AI agent:** ask it to rename and it will report that a slug change needs
> confirmation; tell it to *"rename and reslug"* (it sets `reslug=true`).
>
> **Heads-up for env-var credentials:** passwords kept in the OS keyring migrate
> automatically. Passwords injected via environment variables
> (`CISCO_ISE__<SLUG>__ISE_PASSWORD`) can't be moved for you — the command warns you to
> rename the variable to match the new slug.

### Listing, numbering, default, and removal

```bash
uv run cisco-ise-mcp list                 # show all deployments with their numbers
uv run cisco-ise-mcp set-default "TACACS Only"
uv run cisco-ise-mcp remove vpn-only --yes
```

- **Numbers are stable** and follow the order you added deployments.
- If you have **one** deployment, it is used automatically when you don't name one.
- With **several**, name one per request — or set a **default** that's used when you don't.

## 7. Credentials & secure storage

Each deployment can have up to two passwords, stored **separately** and **per deployment**:

- **ERS / Open API password** (always, for configuration & system tools)
- **Data Connect password** (only if Data Connect is enabled for reporting)

### Default: the OS keyring (recommended)

```bash
uv run cisco-ise-mcp set-credential radius-only                # ERS / Open API password
uv run cisco-ise-mcp set-credential radius-only --dataconnect  # Data Connect password
```

You are prompted twice (hidden input). The password is saved in your OS's secure store
and is **never written to a file** or seen by the AI agent:

| OS | Keyring backend |
| --- | --- |
| **Windows** | Windows Credential Manager |
| **macOS** | Keychain |
| **Linux (desktop)** | Secret Service (GNOME Keyring / KWallet) |

To change a password later, just run `set-credential` again. Removing a deployment also
removes its stored passwords.

### Headless servers / containers: environment variables

If there is no desktop keyring (e.g. a Linux server, Docker, Kubernetes), inject each
password as an environment variable instead. The variable name is built from the
deployment **slug**: upper-case it and turn hyphens into underscores.

```
slug "radius-only"  ->  CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD
                        CISCO_ISE__RADIUS_ONLY__DATACONNECT_PASSWORD
```

```bash
export CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD='…'
# Docker/K8s secrets: point at a file instead of an inline value
export CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD_FILE=/run/secrets/radius_ise_pw
```

See `.env.example` for a template. **Resolution order per deployment:**
environment variable → `*_FILE` secret file → OS keyring. The first one found wins.

## 8. Data Connect setup (per deployment)

Data Connect is the read-only reporting database. Each deployment uses its **own**
certificate, so set this up once per node that you want to report on. Skip this section
for deployments you added with `--no-dataconnect`.

### Step 1 — Export the certificate from ISE

In the ISE GUI:
**Enable Data Connect**: *Administration → System → Settings → Data Connect*, enable it, and set the
`dataconnect` user's password.

**Export the Data Connect certificate**.: Only required when not using OS trust store. 

- **Cisco ISE 3.2**: Export the Data Connect certificate from System Certificates.\
  *Administration → System → Certificates → Certificate Management → System Certificates*
- **Cisco ISE 3.3+**: Export the admin certificate for the Data Connect node from System Certificates or the root CA certificate from 
  Trusted Certificates if the admin certificate is CA signed.\
  *Administration → System → Certificates → Certificate Management → Trusted Certificates*

Save it as a `.pem` file with a name that identifies the deployment, e.g.:

- **Windows:** `C:\cisco-ise-mcp\certs\radius-only-dataconnect.pem`
- **macOS / Linux:** `/opt/cisco-ise-mcp/certs/radius-only-dataconnect.pem`

### Self-signed vs CA-signed (do I even need the file?)

How you trust the Data Connect node depends on its certificate:

- **Self-signed** (common in labs, ISE 3.2 Data Connect cert) — there's no public chain to
  validate, so you **must** export the certificate and point the deployment at the `.pem`
  (`--dc-cert <path>`, agent: `dataconnect_cert_path`).
- **CA-signed** (the admin/Data Connect cert is issued by your enterprise or a public CA) —
  you have two choices:
  - **OS trust store** (`--dc-os-trust`, agent: `dataconnect_os_trust=true`) — validate the
    chain against the operating system's CA store, **no file to export**. Simplest when the
    signing root is already trusted by the host.
  - **Root-CA file** — export the **root CA** certificate (Trusted Certificates) to a `.pem`
    and use `--dc-cert <root-ca.pem>`. Use this when the root isn't in the OS store.

Trust is by **certificate chain, not hostname** in every mode (the ISE node's cert CN is its
FQDN and you often connect by IP), so a separate Data Connect host works with no extra TLS
config. Two caveats for `--dc-os-trust`:

- **macOS:** the trust check reads the **OpenSSL/certifi** bundle, **not** the login/System
  Keychain. A *private* enterprise root added only to Keychain won't be seen — add it to the
  bundle, or just export the root-CA file and use `--dc-cert`. Windows and Linux read the
  system store directly.
- Use it only with `verify_ssl` on (the default); it's a CA-validation feature, not a way to
  skip verification.

### Step 2 — Point the deployment at its certificate (or use OS trust)

At add time, pass **either** `--dc-cert <path>` (self-signed, or a CA root file) **or**
`--dc-os-trust` (CA-signed via the OS store). You can also update an existing deployment
later (`cisco-ise-mcp update <slug> --dc-cert …` or `--dc-os-trust`, or ask the agent), or by
editing `cert_path` / `os_trust` for that deployment in `deployments.json`. Because
the path is stored per deployment, **two deployments never share a certificate**.

### Step 3 — Set the Data Connect password

```bash
uv run cisco-ise-mcp set-credential radius-only --dataconnect
```

### thin vs thick mode

- **thin** (default) — no Oracle client to install. Trust is established with the exported
  `.pem` certificate (`--dc-cert`), or — for a CA-signed cert — the **OS trust store**
  (`--dc-os-trust`). This is what most users want.
- **thick** — uses Oracle Instant Client + an auto-login wallet directory
  (`--dc-mode thick --dc-wallet <dir>`, optionally `--dc-oracle-lib <dir>`). Use only if
  your environment standardizes on the Oracle client. (`--dc-os-trust` is a thin-mode
  option; thick mode trusts via the wallet.)

Verify it with `uv run cisco-ise-mcp test radius-only` (it runs a read-only
`SELECT 1` against Data Connect when everything is configured).

### Resource limits (Data Connect)

Cisco publishes **no** limits for Data Connect, and the ISE `dataconnect` account is a
read-only Oracle user with no rights to configure database-side governance. This server
therefore bounds Data Connect load itself:

| Limit | Default | What it protects |
| --- | --- | --- |
| Concurrent queries | 5 | Oracle sessions on the Monitoring node (also the connection-pool size) |
| Queue wait | 5 s | How long a call waits for a free slot before being refused |
| Query timeout | 60 s | Cancels the statement **on the Monitoring node**, not just client-side |
| Sustained rate | 30/min | A runaway loop that a concurrency cap alone would not catch |
| Default `days_back` | 7 days | Prevents an unbounded full scan of large event views |
| Maximum `days_back` | 90 days | Larger values are **reduced to 90, not rejected** |
| Injected row limit | 500 (5000 for aggregates) | Bounds `ise_dc_query` when it supplies no `FETCH FIRST` |
| Fact views per query | 3 | Large event views joinable at once; lookup views are exempt |

**The `days_back` default.** Views with a time column (`radius_authentications`,
`radius_accounting`, `tacacs_*`, ...) get a 7-day window when you do not specify one:

```
"Show RADIUS authentications for user bob"        -> last 7 days   (default applied)
"Show RADIUS authentications for bob, 30 days"    -> last 30 days  (explicit)
"Show RADIUS authentications for bob, 120 days"   -> last 90 days  (clamped to the maximum)
```

Small configuration views without a time column (`network_devices`, `security_groups`,
`endpoint_identity_groups`, ...) are exempt entirely.

**`ise_dc_query` (raw SQL).** A query with no row limit gets one appended automatically.
It is rejected only when it cannot be corrected safely: a large event view with no time
predicate, a `JOIN` with no `ON` condition, or more than three large event views. Common
table expressions (`WITH ... AS ( ... ) SELECT ...`) are supported. Note the asymmetry —
the 90-day clamp applies to the structured `days_back` parameter; a hand-written time
predicate in raw SQL is *not* clamped, so the 60-second timeout is the backstop there.

**Tuning.** Environment variables (`CISCO_ISE_MCP_*`, see [section 10](#10-environment-variables))
are hard ceilings; a per-deployment override may only tighten them:

```bash
cisco-ise-mcp update radius-only --dc-max-concurrent 3 --dc-query-timeout-s 30
```

Check what is actually in force with `ise_limits_status` or `cisco-ise-mcp test <slug>`.

## 9. Running the server

The server speaks MCP over **stdio** — it is normally started by your AI client, not by
you. To start it manually (for testing):

```bash
uv run cisco-ise-mcp          # or:  uv run python -m cisco_ise_mcp.server
```

It waits silently for an MCP client to connect (no output is normal). Press `Ctrl+C` to
stop. The other CLI subcommands (`list`, `add`, `set-credential`, `test`, …) are for
managing deployments and are covered above.

## 10. Environment variables

You normally configure the server with the CLI or the AI agent — **no environment
variables are required**. The variables below are for advanced situations: relocating
the registry, injecting passwords on a headless host, gating destructive tools, and
tuning resource limits.

The `CISCO_ISE_MCP_*` limit variables are **hard ceilings**: a per-deployment `limits`
block in `deployments.json` may only *tighten* them, never raise them.

**Configuration Source** is *where you set the variable*: the agent's MCP-config `env`
block (see [section 11](#11-connecting-an-ai-agent)), a `.env` file in the project root
(read at startup via python-dotenv — see `.env.example`), or the server process's shell /
container environment. The per-deployment password variables are typically set via `.env`
or container secrets.

| Variable | Description | Configuration Source | Values | Default |
| --- | --- | --- | --- | --- |
| `CISCO_ISE_MCP_HOME` | Override the folder holding the registry (`deployments.json`) and any certificates. | Agent MCP-config `env` block · `.env` · shell/container env | Any writable directory path. | OS-specific: Windows `%APPDATA%\cisco-ise-mcp`; macOS `~/Library/Application Support/cisco-ise-mcp`; Linux `$XDG_CONFIG_HOME/cisco-ise-mcp` (else `~/.config/cisco-ise-mcp`). |
| `CISCO_ISE_MCP_ALLOW_DESTRUCTIVE` | Enable destructive ISE-side tools (delete, restore, rollback, CoA disconnect). Each call **also** requires `confirm=true`. | Agent MCP-config `env` block · `.env` · shell/container env | `1`, `true`, `yes`, `on` = enabled; any other value = disabled. | disabled (unset / `0`) |
| `CISCO_ISE_MCP_BLOCKED_TOOLS` | Tools that are **always denied**, overriding the allow flag — use it to force the most disruptive actions through the ISE GUI. | Agent MCP-config `env` block · `.env` · shell/container env | Comma-separated tool names, e.g. `ise_ers_delete,ise_openapi_backup_restore`. | empty (nothing extra blocked) |
| `CISCO_ISE_MCP_DC_MAX_CONCURRENT` | Max simultaneous Data Connect queries per deployment (also the Oracle pool size). | Agent MCP-config `env` block · `.env` · shell/container env | Whole number ≥ 1. | `5` |
| `CISCO_ISE_MCP_DC_ACQUIRE_WAIT_S` | Seconds a call waits for a free Data Connect slot before being refused. | Agent MCP-config `env` block · `.env` · shell/container env | Number of seconds, capped at 15. | `5` |
| `CISCO_ISE_MCP_DC_QUERY_TIMEOUT_S` | Seconds a single query may run before it is cancelled **on the Monitoring node**. | Agent MCP-config `env` block · `.env` · shell/container env | Whole number of seconds. | `60` |
| `CISCO_ISE_MCP_DC_QPM` | Sustained Data Connect queries per minute per deployment. | Agent MCP-config `env` block · `.env` · shell/container env | Whole number. | `30` |
| `CISCO_ISE_MCP_DC_DEFAULT_DAYS_BACK` | Window applied when a view query omits `days_back`. | Agent MCP-config `env` block · `.env` · shell/container env | Whole number of days. | `7` |
| `CISCO_ISE_MCP_DC_MAX_DAYS_BACK` | Largest `days_back` allowed; larger requests are reduced to it, not rejected. | Agent MCP-config `env` block · `.env` · shell/container env | Whole number of days. | `90` |
| `CISCO_ISE_MCP_DC_DEFAULT_ROW_LIMIT` | Row bound injected into `ise_dc_query` when it has none. | Agent MCP-config `env` block · `.env` · shell/container env | Whole number of rows. | `500` |
| `CISCO_ISE_MCP_DC_DEFAULT_AGG_ROW_LIMIT` | Row bound injected when the raw query aggregates (`GROUP BY`/`COUNT`/...). | Agent MCP-config `env` block · `.env` · shell/container env | Whole number of rows. | `5000` |
| `CISCO_ISE_MCP_DC_MAX_FACT_VIEWS` | Large event views joinable in one `ise_dc_query`; lookup views are exempt. | Agent MCP-config `env` block · `.env` · shell/container env | Whole number. | `3` |
| `CISCO_ISE_MCP_ERS_MAX_CONCURRENT` | Max simultaneous ERS calls, out of Cisco's deployment-wide ~100. | Agent MCP-config `env` block · `.env` · shell/container env | Whole number ≥ 1. | `10` |
| `CISCO_ISE_MCP_OPENAPI_MAX_CONCURRENT` | Max simultaneous Open API calls, out of Cisco's deployment-wide ~150. | Agent MCP-config `env` block · `.env` · shell/container env | Whole number ≥ 1. | `15` |
| `CISCO_ISE_MCP_MNT_MAX_CONCURRENT` | Max simultaneous Monitoring (MnT) calls. | Agent MCP-config `env` block · `.env` · shell/container env | Whole number ≥ 1. | `5` |
| `CISCO_ISE__<SLUG>__ISE_PASSWORD` | Inject a deployment's ERS / Open API password instead of using the OS keyring (headless / container). | `.env` · container secret env | The password string. | unset → try `*_FILE`, then OS keyring |
| `CISCO_ISE__<SLUG>__ISE_PASSWORD_FILE` | File-path variant of the ERS password (Docker / Kubernetes secrets). | `.env` · container secret env | Path to a file whose contents are the password. | unset |
| `CISCO_ISE__<SLUG>__DATACONNECT_PASSWORD` | Inject a deployment's Data Connect password (only if Data Connect is enabled). | `.env` · container secret env | The password string. | unset → try `*_FILE`, then OS keyring |
| `CISCO_ISE__<SLUG>__DATACONNECT_PASSWORD_FILE` | File-path variant of the Data Connect password. | `.env` · container secret env | Path to a file whose contents are the password. | unset |

**Building the per-deployment variable name.** Replace `<SLUG>` with the deployment slug
upper-cased and with hyphens turned into underscores (see
[section 7](#7-credentials--secure-storage)):

```
slug "radius-only"  ->  CISCO_ISE__RADIUS_ONLY__ISE_PASSWORD
                        CISCO_ISE__RADIUS_ONLY__DATACONNECT_PASSWORD
```

**Resolution order per password** (first match wins): the environment variable → the
`*_FILE` secret file → the OS keyring. See
[section 7](#7-credentials--secure-storage) for the keyring path and `.env.example` for a
copy-paste template. Enabling and blocking destructive tools is covered in more detail in
[section 16](#16-security-notes).

## 11. Connecting an AI agent

Configure your MCP client to launch the server with `uv`. The key is to point `uv` at
**this project folder** with `--directory`.

### Claude Desktop

Edit the config file:

- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "cisco-ise": {
      "command": "uv",
      "args": ["--directory", "/ABSOLUTE/PATH/TO/cisco-ise-mcp", "run", "cisco-ise-mcp"]
    }
  }
}
```

- On **Windows**, use a full path with escaped backslashes, e.g.
  `"C:\\Users\\you\\cisco-ise-mcp"`.
- If `uv` isn't found, use its full path (`which uv` / `where uv`) as `command`.
- To use a custom registry/cert folder, add an `env` block:
  ```json
  "env": { "CISCO_ISE_MCP_HOME": "/opt/cisco-ise-mcp" }
  ```
  The `env` block is also where you set any other server variable (see
  [section 10](#10-environment-variables)).

Restart Claude Desktop after editing. The Cisco ISE tools then appear in the client.

### Hermes / other MCP clients

Any MCP client that launches a stdio server works the same way — give it the command and
args:

```
command:  uv
args:     --directory  /ABSOLUTE/PATH/TO/cisco-ise-mcp  run  cisco-ise-mcp
```

If your client can't pass `--directory`, either run it from inside the project folder, or
use the absolute path to the installed console script (after `uv pip install -e .`, find it
under `.venv/bin/cisco-ise-mcp` on macOS/Linux or `.venv\Scripts\cisco-ise-mcp.exe` on
Windows). Pass deployment selection per request ("…on Deployment 2"); set
`CISCO_ISE_MCP_HOME` in the client's environment if you relocated the registry.

## 12. Available tools

**203 tools total** — every ERS / Open API / Monitoring / Data Connect tool accepts an
optional `deployment` argument (name, slug, or number).

| Family | Count | Prefix | What |
| --- | --- | --- | --- |
| Meta / management | 11 | — | Routing, catalog info, and deployment management (below) |
| ERS | 82 | `ise_ers_` | Configuration CRUD (generic + typed per-resource) |
| Open API | 66 | `ise_openapi_` | System/policy/cert/backup/patch/license + raw passthrough |
| Monitoring (MnT) | 17 | `ise_mnt_` | Legacy live session / CoA / failure-reason queries (XML) + raw passthrough |
| Data Connect | 27 | `ise_dc_` | Read-only reporting views + custom `SELECT` (row-bounded and time-bounded — see section 8) |

**Meta tools:**

- `ise_capabilities` — summarize the four surfaces + routing rule.
- `ise_route` — recommend a surface/tools for a natural-language request.
- `ise_catalog_info` — catalog provenance & counts.
- `ise_catalog_diff` — compare the local catalog against the upstream specs / Cisco DevNet (read-only).
- `ise_list_deployments` — list configured deployments (number, name, credential status).
- `ise_add_deployment` — add a deployment (non-secret fields only).
- `ise_update_deployment` — modify an existing deployment's non-secret fields (only what you pass changes).
- `ise_remove_deployment` — remove a deployment (requires `confirm`).
- `ise_set_default_deployment` — choose the default.
- `ise_test_deployment` — check config/credentials and report effective resource limits, then an optional live read-only probe.
- `ise_limits_status` — show the resource limits protecting each deployment and their live usage (in-flight calls, refusals).

Discover the rest at runtime: ask the agent, or call `ise_ers_resources` /
`ise_dc_list_views` / `ise_openapi_request` / `ise_mnt_request` (the live spec is at
`https://<ise>/api/swagger-ui/index.html`).

## 13. Usage examples

Natural-language prompts to your agent, and what they do:

| You ask | What happens |
| --- | --- |
| "List the deployments available." | `ise_list_deployments` |
| "How many failed RADIUS authentications in the last day on **Deployment 1**?" | Data Connect query on deployment 1 |
| "Add network device **Office** (10.10.10.10) to the **TACACS Only** deployment." | ERS create on `tacacs-only` |
| "Show the RADIUS policy sets on **VPN Only**." | Open API `network-access/policy-set` on `vpn-only` |
| "Add a deployment **Lab ISE** at 10.5.5.5, ERS user ers-admin." | `ise_add_deployment` (then it tells you the `set-credential` command) |
| "On **TACACS Only**, fix the host to 10.2.1.5 and enable Data Connect with cert /opt/ise/t.pem." | `ise_update_deployment` (only those fields change) |
| "On **RADIUS Only**, point Data Connect at the MnT node 10.1.1.5." | `ise_update_deployment` (`dataconnect_host`) |
| "Make **Deployment 2** the default." | `ise_set_default_deployment` |
| "Test the **VPN Only** deployment." | `ise_test_deployment` (config + live probe) |

With a single deployment configured, you can drop the "on Deployment N" part — it's used
automatically. With several, name one (or set a default).

## 14. Testing & validation

- **Check one deployment** (config + live read-only probe):
  ```bash
  uv run cisco-ise-mcp test "RADIUS Only"
  ```
  Reports every missing field/credential at once, with the exact fix command. If complete,
  it tries a real ERS GET and a Data Connect `SELECT 1`.
- **Check all deployments** (offline, no connection):
  ```bash
  uv run cisco-ise-mcp validate
  ```
- **Self-test the install** (offline; verifies tools, catalogs, and the deployment layer):
  ```bash
  uv run python scripts/validate.py
  ```
- **Run the unit tests** (after `uv pip install -e ".[dev]"`):
  ```bash
  uv run pytest -q
  ```

## 15. Troubleshooting

### Resource-limit refusals

These are deliberate protections, not faults. Each refusal names the limit and how to proceed.

| Message | Meaning | What to do |
| --- | --- | --- |
| `concurrency_limited` | All Data Connect / ERS / Open API / MnT slots for this deployment were busy and none freed within the queue wait. | Run fewer calls at once. Slots are held by long queries, so retrying instantly will not help — narrow each query so it finishes faster. |
| `rate_limited` | The per-minute call budget for this deployment is exhausted. | Aggregate in SQL (`GROUP BY`) instead of querying in a loop, or wait a few seconds. |
| `query_timeout` | The query ran past the 60-second limit and was cancelled **on the Monitoring node**. | Reduce `days_back`, filter on an indexed column, or aggregate rather than returning raw rows. |
| `[time-predicate] ...` | A raw `ise_dc_query` referenced a large event view with no time bound. | Add e.g. `WHERE "TIMESTAMP" >= SYSTIMESTAMP - NUMTODSINTERVAL(7,'DAY')`. The refusal shows a corrected example. |
| `[join-condition] ...` | A `JOIN` had no `ON`/`USING`, or a `CROSS JOIN` was used — a cartesian product. | Add the join condition. |
| `[fact-view-limit] ...` | More than three large event views in one query. | Split the correlation, or aggregate one side first. Lookup views do not count. |

Run `ise_limits_status` to see the configured caps and live usage, and
[section 8](#resource-limits-data-connect) to tune them.

**"I get fewer rows than I expected."** Views with a time column default to a **7-day**
window when `days_back` is omitted, and any `days_back` above 90 is reduced to 90. Pass
`days_back` explicitly to widen the range.



**"More than one deployment is configured — specify which one."**
Name a deployment in your request (by name or number), or set a default:
`uv run cisco-ise-mcp set-default "RADIUS Only"`.

**"… password … is not set."**
Run the command from the message, e.g. `uv run cisco-ise-mcp set-credential radius-only`
(add `--dataconnect` for the Data Connect password). On a headless host, set the
`CISCO_ISE__<SLUG>__ISE_PASSWORD` environment variable instead.

**Linux: "No usable OS keyring backend was found."**
There's no desktop keyring on your server. Either inject passwords via environment
variables (see [section 7](#7-credentials--secure-storage)), or install a backend
(e.g. `gnome-keyring` / `libsecret`, or `pip install keyrings.alt` for file-based storage).

**ERS calls return 401 / 403.**
The username or password is wrong, or ERS isn't enabled on that node, or the account lacks
ERS access. Re-check [Prerequisites](#3-prerequisites) and re-run `set-credential`.

**Can't reach ERS/Open API.**
Some deployments don't use the 443 gateway — try the dedicated listeners by re-adding with
`--ers-port 9060` and/or `--openapi-port 9070`.

**ERS/Open API TLS errors with `--verify-ssl` on** (e.g. `CERTIFICATE_VERIFY_FAILED`,
`unable to get local issuer certificate`).
ISE is using a private/enterprise CA that the client doesn't trust. The admin HTTP client
validates only against the built-in public-CA (certifi) bundle — it does **not** read the
macOS **Keychain** or any OS trust store, so importing the root/intermediate there won't
help. Export the ISE **root CA** (Trusted Certificates → Base64/PEM) and point the
deployment at it: `cisco-ise-mcp update <name> --verify-ssl --ca-cert /path/to/ise-root-ca.pem`.
See [Admin TLS trust](#admin-tls-trust-ers--open-api--mnt). If verification still fails,
confirm you dialed the node's **FQDN** (matching the cert SAN), not an IP — hostname
checking stays on. Then re-test with `uv run cisco-ise-mcp test <name>`.

**Data Connect connection/TLS errors.**
Confirm Data Connect is enabled on the node, the exported certificate matches **that**
deployment, and `cert_path` points at the right `.pem`. Test with
`uv run cisco-ise-mcp test <name>`. For lab self-signed setups you can set
`dataconnect.verify_ssl` to `false` in the registry (not recommended in production).

**The agent doesn't show the ISE tools.**
Check the client config path and JSON syntax, ensure the `--directory` path is correct and
absolute, confirm `uv` is found (use its full path if not), then restart the client.

**Running `cisco-ise-mcp` prints nothing.**
That's correct — the server waits silently for an MCP client over stdio.

**Where is my config?**
`uv run cisco-ise-mcp list` prints the registry path. Override the location with
`CISCO_ISE_MCP_HOME`.

## 16. Security notes

**Resource limits cannot be raised by the agent.** The `CISCO_ISE_MCP_*` environment
variables are hard ceilings, and a per-deployment `limits` block may only tighten them.
This matters because an AI agent *can* edit non-secret registry fields through
`ise_update_deployment` — the ordering stops it granting itself a larger budget against
your ISE deployment. Only an operator with access to the server's environment can raise a
ceiling.

**Data Connect query logging.** Data Connect reads are recorded in `audit.log` alongside
the mutation trail (tagged `kind="dc_query"`) so monitoring-database load is visible. The
log records the view, applied time window, duration, row count and outcome — deliberately
**not** filter values or raw SQL, since a filter value is typically a username, MAC or IP.



- **Passwords are never stored in files** by default — they go to the OS keyring, and are
  never passed through the AI agent. The agent only ever writes non-secret settings.
- **`.gitignore`** excludes `.env`, `deployments.json`, and `*.pem` so secrets and host
  details aren't committed. Keep it that way.
- On macOS/Linux the registry is written with `0600` permissions (owner-only).
- Use a **least-privilege** ISE admin account for ERS/Open API where possible; Data Connect
  access is **read-only** by design.
- `verify_ssl` defaults to **on** (TLS certificate verification enabled) for both the
  ERS/Open API admin interface and Data Connect. Turn it **off** only for a self-signed lab
  (`--no-verify` / registry `verify_ssl: false`), which disables MITM protection for admin
  credentials — the server warns when you do. Data Connect additionally refuses to connect
  when `verify_ssl` is on but no pinned certificate/wallet is configured and `os_trust` is
  off, rather than silently trusting the OS CA store without a hostname check.
- Treat `CISCO_ISE_MCP_HOME` and any certificate files as sensitive — store them where only
  the intended user can read them.

### Destructive tools are disabled by default

Destructive ISE-side operations are **denied unless an operator explicitly enables them**,
and every such call also requires `confirm=true`. Each attempt is written to the audit log
before and after execution.

- **Enable:** set `CISCO_ISE_MCP_ALLOW_DESTRUCTIVE=1` in the server environment. It is
  `0` (off) by default. With it off, these tools return a refusal and make no changes.
- **`confirm=true` is always required**, even when destructive tools are enabled — a call
  without it is refused with a dry-run description.
- **Block specific verbs (force GUI):** `CISCO_ISE_MCP_BLOCKED_TOOLS` is a comma-separated
  list of tool names that are **always denied**, overriding the allow flag — use it to force
  the most disruptive actions through the ISE GUI only. Example:
  `CISCO_ISE_MCP_BLOCKED_TOOLS=ise_openapi_backup_restore,ise_openapi_patch_rollback,ise_ers_delete`

Tools classified destructive (per surface):

| ERS | Open API | Monitor API |
|-----|----------|-------------|
| `ise_ers_delete` | `ise_openapi_cert_system_delete` | `ise_mnt_coa_disconnect` |
| `ise_ers_request` (DELETE) | `ise_openapi_cert_trusted_delete` | `ise_mnt_session_delete_by_mac` |
| | `ise_openapi_repo_delete` | `ise_mnt_session_delete_by_id` |
| | `ise_openapi_radius_policy_set_delete` | `ise_mnt_request` (DELETE) |
| | `ise_openapi_tacacs_policy_set_delete` | |
| | `ise_openapi_patch_rollback` | |
| | `ise_openapi_hotpatch_rollback` | |
| | `ise_openapi_backup_restore` | |
| | `ise_openapi_request` (DELETE) | |

(`ise_remove_deployment` edits only the local registry and keeps its own separate `confirm`.)
