# Customer alpha quickstart

`mcpsec` is a CLI-first security scanner for MCP configuration files. This page is the fastest customer-alpha path: install one pinned tag, audit a real config, then optionally export JSON/SARIF for CI or code-scanning tools.

> Alpha note: findings are static heuristics for human review. Expect false positives and false negatives; do not treat `mcpsec` as the only security control.

## 1. Install the pinned alpha

```sh
python3 -m pip install "git+https://github.com/PFgo/mcpsec.git@v0.1.0-alpha.2"
```

If the `mcpsec` command is not found after install, add your Python user scripts directory to `PATH` and open a new shell:

```sh
python3 -m site --user-base
export PATH="$(python3 -m site --user-base)/bin:$PATH"
```

Verify:

```sh
mcpsec --version
```

## 2. Audit a real MCP config

Use the friendly audit entry point for app configs:

```sh
mcpsec audit ~/.hermes/config.yaml
mcpsec audit ~/.cursor/mcp.json
mcpsec audit "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
```

No path is required when you want auto-discovery across known locations:

```sh
mcpsec audit
```

`audit` prints a permission-oriented review with a top-level decision (`APPROVE`, `REVIEW`, or `DENY`), high-risk servers, risky permissions, and concrete fix guidance. It is equivalent to `review`, but named for customer-facing use.

Machine-readable review:

```sh
mcpsec audit ~/.hermes/config.yaml --json > mcpsec-audit.json
```

## 3. Run the bundled real-shape demos

From a checkout of this repository:

```sh
PYTHONPATH=src python3 -m mcpsec audit examples/hermes-config.yaml
PYTHONPATH=src python3 -m mcpsec audit examples/cursor-mcp.json
PYTHONPATH=src python3 -m mcpsec audit examples/claude_desktop_config.json
```

Expected highlights:

- `examples/hermes-config.yaml`: flags filesystem root access and unpinned/auto-install `npx`; HTTPS remote endpoint is reported for review.
- `examples/cursor-mcp.json`: flags a plaintext remote endpoint and redacts token-like environment values.
- `examples/claude_desktop_config.json`: flags shell execution and risky filesystem/package execution patterns.

## 4. CI / automation options

Fail CI on blocking findings:

```sh
mcpsec check ~/.cursor/mcp.json
```

Generate SARIF for a code-scanning dashboard:

```sh
mcpsec scan ~/.cursor/mcp.json --sarif > mcpsec.sarif
```

Create a starter policy, then edit it to document accepted servers/rules:

```sh
mcpsec policy suggest ~/.cursor/mcp.json --output mcpsec.policy.json
mcpsec check ~/.cursor/mcp.json --policy mcpsec.policy.json
```
