# mcpsec — Threat model & limitations

This document describes what `mcpsec` is designed to do, what it deliberately
does **not** do, and the heuristic nature of its findings. Read it before
relying on a scan result as a security gate.

## What mcpsec is

`mcpsec` is a **static, read-only configuration scanner** for MCP (Model Context
Protocol) configs. Given a config file (or a directory, or a set of well-known
discovery locations), it:

1. Parses the JSON (or, best-effort, YAML if PyYAML is installed) into a list of
   declared MCP servers.
2. Applies a fixed set of static heuristics (see the rule table in the
   [README](../README.md)) to each server's declared command, arguments,
   environment variables, URL, headers, and sampling flag.
3. Reports the matches as a human report, JSON, or SARIF.

It is intended as a fast, dependency-free **first-pass triage** of MCP
configurations — to surface obviously risky settings (hardcoded secrets,
shell wrappers, world-readable filesystem mounts, plaintext transports, unpinned
auto-installed packages) so a human can review them.

## What mcpsec does NOT do

- **No execution of servers.** `mcpsec` never runs the `command`, never spawns a
  process, and never imports server code. It only reads what the config
  *declares*.
- **No runtime or behavioural analysis.** It cannot observe what a server
  actually does once running — what tools it exposes, what files it touches, or
  what data it exfiltrates. It reasons only about the static config.
- **No network analysis.** It does not connect to any `url`, resolve hostnames,
  fetch packages, validate TLS certificates, or check whether a remote endpoint
  is reachable or trustworthy. A `https://` endpoint is flagged for *human*
  review (MCPSEC008), not verified.
- **No broad home-directory or filesystem scanning.** `mcpsec` reads only the
  paths you give it explicitly, plus a small fixed list of well-known config
  locations during discovery (Claude Desktop, Cursor, Hermes, and
  `./mcp.json` / `./.mcp.json`). It does not crawl your home directory or disk
  looking for files, and it does not open any file other than the configs it
  reports.
- **No package / supply-chain inspection.** It checks whether an `npx`/`uvx`
  package is version-pinned, but it does not download, unpack, or audit the
  package contents, registry, or maintainers.
- **No secret validation.** When it flags a possible inline secret (MCPSEC001),
  it does not test the credential against any service; it only pattern-matches
  the value or the key name. Secret *values* are never printed (e.g. `explain`
  shows only env/header key names).
- **No automatic remediation.** It suggests a `fix:` for each finding but never
  edits your configs.

## Findings are heuristic — human review required

Every finding is the result of a static heuristic and should be treated as a
**prompt for human judgment**, not a verdict. Severities are defaults; a finding
that is acceptable in your context can be ignored, and the absence of findings
does **not** mean a config is safe.

### Known false positives

- **MCPSEC001 (inline secret)** keys on secret-*named* keys (`*TOKEN*`,
  `*SECRET*`, `*PASSWORD*`, `*API_KEY*`) holding any non-empty value, and on
  values matching common credential patterns. A non-secret value stored under a
  secret-sounding key (e.g. a placeholder, a feature-flag named `..._TOKEN`, or
  an env-var *reference* rather than a literal) is flagged even though it is not
  a real leaked credential.
- **MCPSEC008 (remote https review)** is informational and fires for **every**
  `https://` endpoint, including endpoints you fully trust. It is a reminder to
  confirm the operator, not a defect in the config.
- **MCPSEC006 (shell wrapper)** flags any `bash -c …` / pipe-to-shell pattern,
  including benign wrappers that happen to use a shell for legitimate reasons.
- **MCPSEC003 / MCPSEC004 (npx/uvx)** flag unpinned versions and `-y`/`--yes`
  auto-install even when you intend to track the latest release of a package you
  trust.

### Known false negatives

- A genuinely malicious server with a perfectly "clean" config (pinned package,
  `https://`, scoped paths, no inline secrets) will produce **no findings** —
  the danger is in the code it runs, which `mcpsec` never inspects.
- Secrets that don't match the built-in patterns and aren't stored under a
  secret-sounding key are not detected.
- Plaintext transports declared in ways the parser doesn't model, custom or
  proprietary config shapes beyond `mcpServers` / `servers`, and risks expressed
  through fields `mcpsec` does not read will be missed.
- YAML configs are silently skipped when PyYAML is not installed (a warning is
  printed); those servers are not scanned at all.

## In short

`mcpsec` reduces the time to spot common, statically-detectable MCP
misconfigurations. It is one layer of defence. Pair it with code review of the
servers you enable, runtime sandboxing, and least-privilege configuration.
