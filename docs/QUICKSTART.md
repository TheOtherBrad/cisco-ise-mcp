# Quick Start — Cisco ISE MCP Server

This is the 5-minute path for first-time users. It assumes nothing — if you get
stuck, the full **[USER_GUIDE.md](USER_GUIDE.md)** explains every step in detail.

You will: install the server, add one ISE deployment, store its password securely,
test it, and connect it to an AI agent.

---

## 1. Install `uv` (the recommended Python tool)

`uv` is a single tool that manages Python and packages for you. Pick your OS:

**Windows** (PowerShell):
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**macOS / Linux** (Terminal):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Close and reopen your terminal afterward so `uv` is on your PATH. Verify:
```bash
uv --version
```

---

## 2. Install the server

Open a terminal **in the project root** (the folder above this `docs/` directory,
containing `pyproject.toml`), then:

```bash
uv venv
uv pip install -e .
```

`uv venv` creates an isolated environment; `uv pip install -e .` installs the
server into it. You do not need to "activate" anything — just prefix commands
with `uv run` (shown below).

> **MCP SDK v1 or v2?** The server works with either major of the `mcp` SDK and
> auto-detects which is installed. `uv pip install -e .` accepts either; to pin
> one per venv use `uv pip install -e '.[v1]'` (mcp 1.x) or `'.[v2]'` (mcp 2.x)
> — equivalently `uv sync --extra v1|v2`. On v2, tool results also include a
> machine-readable `structuredContent` payload; v1 is text only. If unsure,
> the default install is fine.

Confirm it works (this runs an offline self-test — no ISE connection needed):
```bash
uv run python scripts/validate.py
```
You should see `All checks passed.`

On a **first install**, build all four tool catalogs fresh (needs internet to fetch
the Cisco specs — pre-built catalogs also ship, so you can skip this if offline):
```bash
uv run python scripts/refresh_catalog.py --all
```

> Later, `uv run cisco-ise-mcp refresh` (no flag) pulls the latest Cisco API specs and
> rebuilds ERS + Open API, plus Data Connect / Monitor API only if a deployment enables
> them. You can skip refreshes until you want the newest specs.

---

## 3. Add your first ISE deployment

Replace the name, IP, and username with your own. The name is just a friendly
label you will use later (e.g. "Lab ISE", "RADIUS Only").

```bash
uv run cisco-ise-mcp add --name "RADIUS Only" --host 10.1.1.1 --ers-username ers-admin
```

> The username is the ISE admin account enabled for ERS / Open API access.
> Don't know it? See USER_GUIDE.md → "Prerequisites → ISE side".
>
> Run in a terminal? `add` walks you through the optional choices — Data Connect
> (reporting), its certificate (self-signed vs CA-signed), and the Monitor API (MnT).
> Pass flags such as `--dc-os-trust` or `--enable-monitoring` to skip the questions.
>
> Your registry file (`deployments.json`) is created **blank** automatically the first
> time you run any `cisco-ise-mcp` command — this `add` writes your first entry into it.

---

## 4. Store the password (securely, never in a file)

```bash
uv run cisco-ise-mcp set-credential radius-only
```

It prompts you twice for the password and stores it in your operating system's
**keyring** (macOS Keychain, Windows Credential Manager, or Linux Secret Service).
The password is never written to disk in plain text and is never seen by the AI.

> `radius-only` is the *slug* — the lower-case, hyphenated version of the name.
> Running `uv run cisco-ise-mcp list` shows the slug for every deployment.

---

## 5. Test the deployment

```bash
uv run cisco-ise-mcp test "RADIUS Only"
```

This checks that everything is configured and then tries a read-only connection.
If something is missing, it tells you exactly what and how to fix it.

> Using Data Connect (reporting)? You also need that node's certificate — export it and
> use `--dc-cert <path>`, or for a **CA-signed** cert add `--dc-os-trust` to validate
> against the OS trust store (no file) — plus a second password. See USER_GUIDE.md →
> "Data Connect setup".
>
> Want the legacy Monitor API (MnT)? It's **opt-in** — add `--enable-monitoring` (the ERS
> account must be in ISE's "MnT Admin" group).
>
> Data Connect on a **different node** than the admin host? Add `--dc-host <MnT-IP>`
> (it defaults to `--host`). See USER_GUIDE.md → "Data Connect on a separate node".

---

## 5b. Made a typo? Change a deployment later

You don't have to remove and re-add. `update` patches **only** the fields you name
(passwords and everything else are kept):

```bash
uv run cisco-ise-mcp update radius-only --host 10.1.1.9      # fix the host
uv run cisco-ise-mcp update radius-only --enable-dataconnect \
    --dc-cert /opt/cisco-ise-mcp/certs/radius.pem            # add Data Connect later
```

Or just tell your AI agent: *"On the RADIUS Only deployment, change the host to 10.1.1.9."*
Re-run `test` afterward to confirm.

**Renaming?** Changing the name to something with a different slug also moves the stored
password, so it needs confirmation. Add `--reslug` (or answer **y** when prompted):

```bash
uv run cisco-ise-mcp update radius-only --name "RADIUS Prod" --reslug
```

---

## 6. Connect it to your AI agent

**Claude Desktop** — open its config file:
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

Add this (use the **full path** to this project folder, and keep the `\\` on Windows):

```json
{
  "mcpServers": {
    "cisco-ise": {
      "command": "uv",
      "args": ["--directory", "C:\\path\\to\\cisco-ise-mcp", "run", "cisco-ise-mcp"]
    }
  }
}
```

On macOS/Linux the path looks like `/Users/you/cisco-ise-mcp`. Restart Claude
Desktop. Other clients (Hermes, etc.) are covered in USER_GUIDE.md.

---

## 7. Try it

Ask your agent:

> "List the deployments available."
> "How many failed RADIUS authentications were there in the last day on Deployment 1?"

To add more ISE deployments later, just ask the agent — for example:

> "Add an ISE deployment named 'TACACS Only' with host 10.2.1.1 and ERS username ers-admin."

The agent saves the non-secret settings; it then tells you the one command to run
in your terminal to set that deployment's password. That's it.
