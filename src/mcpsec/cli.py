"""Command-line interface for mcpsec.

``scan`` discovers (or reads) MCP configs, inventories their servers, and runs
the risk-rule engine, reporting findings as a human-readable report (default),
``--json``, or ``--sarif`` (SARIF 2.1.0). ``explain`` focuses the same machinery
on a single named server, ``review`` renders a permission-oriented security
review for humans or automation, ``policy init`` writes a policy template, and
``check`` re-runs the rules as a CI gate that exits non-zero when a finding is at
or above a (policy-configurable) severity threshold.
"""

import argparse
import dataclasses
import json
import os
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from typing import List, Optional, Tuple

from mcpsec import __version__
from mcpsec.models import Finding, ServerDef
from mcpsec.parser import load_config, normalize
from mcpsec.rules import (
    RULE_METADATA,
    SEVERITY_ORDER,
    _looks_like_secret_value,
    rule_descriptions,
    run_rules,
)


def _collect_target_files(path: str) -> List[str]:
    """Resolve a scan target into a concrete list of config files.

    A file path yields itself; a directory yields its top-level ``*.json`` files
    plus ``.mcp.json`` (which the ``*.json`` glob skips because of the leading
    dot).
    """
    if os.path.isdir(path):
        found = []
        for name in sorted(os.listdir(path)):
            if name.endswith(".json"):
                found.append(os.path.join(path, name))
        dotted = os.path.join(path, ".mcp.json")
        if os.path.isfile(dotted) and dotted not in found:
            found.append(dotted)
        return found
    return [path]


def _gather(files: List[str]) -> Tuple[List[Tuple[str, List[ServerDef]]], List[str]]:
    """Parse each file, returning ``(per-file servers, skipped files)``."""
    results: List[Tuple[str, List[ServerDef]]] = []
    skipped: List[str] = []
    for config_path in files:
        try:
            data = load_config(config_path)
        except FileNotFoundError:
            print("warning: no such file: {0}".format(config_path), file=sys.stderr)
            skipped.append(config_path)
            continue
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            print(
                "warning: skipping {0} ({1})".format(config_path, exc),
                file=sys.stderr,
            )
            skipped.append(config_path)
            continue
        if data is None:  # YAML file skipped by load_config (no PyYAML).
            skipped.append(config_path)
            continue
        results.append((config_path, normalize(config_path, data)))
    return results, skipped


# Marker substituted for any value that might be a secret.
_REDACTED = "<redacted>"

# A flag whose (dash-stripped) name contains one of these is assumed to carry a
# credential, so its value is masked. ``key`` subsumes ``api-key``/``apikey``
# but all are listed to match the review's set explicitly.
_SECRET_FLAG_FRAGMENTS = (
    "token",
    "secret",
    "password",
    "api-key",
    "apikey",
    "key",
    "auth",
)


def _flag_name_is_secret(flag: str) -> bool:
    """True if ``flag`` names a credential (e.g. ``--token``, ``--api-key``)."""
    name = flag.lstrip("-").lower()
    return any(fragment in name for fragment in _SECRET_FLAG_FRAGMENTS)


def _redact_args(args: List[str]) -> List[str]:
    """Return a copy of ``args`` with likely-secret values masked.

    Three cases are masked (everything else prints verbatim):
      (a) the value after a secret-named flag: ``--token X`` -> ``--token <redacted>``
      (b) an inline ``--flag=VALUE`` whose flag is secret-named -> ``--flag=<redacted>``
      (c) a standalone arg that looks like a secret value (reusing the rule
          engine's patterns) -> ``<redacted>``

    Case (a) always masks the following token regardless of its shape, so a
    secret value can never slip through; over-masking a (rare) following flag is
    accepted as the safe trade-off.
    """
    redacted: List[str] = []
    expect_value = False
    for arg in args:
        if expect_value:
            redacted.append(_REDACTED)
            expect_value = False
            continue
        if arg.startswith("-") and "=" in arg:  # --flag=VALUE form
            flag, _, _value = arg.partition("=")
            if _flag_name_is_secret(flag):
                redacted.append("{0}={1}".format(flag, _REDACTED))
            else:
                redacted.append(arg)
            continue
        if arg.startswith("-"):  # bare flag; its value (if any) is the next arg
            redacted.append(arg)
            expect_value = _flag_name_is_secret(arg)
            continue
        redacted.append(_REDACTED if _looks_like_secret_value(arg) else arg)
    return redacted


def _redact_url(url: str) -> str:
    """Redact credentials and sensitive query parameters from URLs."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return _redact_message(url)

    hostname = parts.hostname or ""
    netloc = hostname
    if parts.port:
        netloc = "{0}:{1}".format(netloc, parts.port)
    if parts.username or parts.password:
        netloc = "{0}@{1}".format(_REDACTED, netloc)

    query_items = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if _flag_name_is_secret(key) or _looks_like_secret_value(value):
            query_items.append((key, _REDACTED))
        else:
            query_items.append((key, value))
    query = urlencode(query_items, doseq=True).replace("%3Credacted%3E", _REDACTED)
    fragment = _REDACTED if parts.fragment else ""
    return urlunsplit((parts.scheme, netloc, parts.path, query, fragment))


def _describe(server: ServerDef) -> str:
    """One-line human description of a server's transport.

    Secret-looking argument values are masked (see :func:`_redact_args`) so the
    inventory and ``explain`` transport line never echo a token passed on the
    command line.
    """
    if server.command:
        parts = [server.command] + _redact_args(server.args)
        return "command: {0}".format(" ".join(parts))
    if server.url:
        return "url: {0}".format(_redact_url(server.url))
    return "(no command or url)"


def _print_inventory(results: List[Tuple[str, List[ServerDef]]]) -> None:
    """Render the human-readable inventory to stdout."""
    if not results:
        print("No MCP config files found.")
        print("\nTotal: 0 servers across 0 config files")
        return
    total_servers = 0
    for config_path, servers in results:
        print(config_path)
        if not servers:
            print("  (no servers defined)")
        for server in servers:
            print("  • {0:<20} {1}".format(server.name, _describe(server)))
        total_servers += len(servers)
        print("")
    file_word = "file" if len(results) == 1 else "files"
    server_word = "server" if total_servers == 1 else "servers"
    print(
        "Total: {0} {1} across {2} config {3}".format(
            total_servers, server_word, len(results), file_word
        )
    )


_SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")


def _severity_counts(findings: List[Finding]) -> dict:
    """Tally findings per severity, with every severity present (zero-filled)."""
    counts = {severity: 0 for severity in _SEVERITIES}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _print_findings(findings: List[Finding]) -> None:
    """Render the human-readable FINDINGS section to stdout."""
    print("")
    print("Findings:")
    if not findings:
        print("  No findings.")
        return
    for finding in findings:
        print(
            "  [{0}] {1}  {2}".format(
                finding.severity, finding.rule_id, finding.server
            )
        )
        print("      {0}".format(finding.message))
        if finding.fix:
            print("      fix: {0}".format(finding.fix))
    counts = _severity_counts(findings)
    print("")
    print(
        "Summary: HIGH {0}  MEDIUM {1}  LOW {2}  INFO {3}".format(
            counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"]
        )
    )


def _redact_mapping(mapping: dict) -> dict:
    """Replace every value in a key/value mapping with the redaction marker."""
    return {key: _REDACTED for key in mapping}


def _build_report(
    results: List[Tuple[str, List[ServerDef]]], findings: List[Finding]
) -> dict:
    """Build the ``--json`` report payload.

    Server ``env``/``headers`` *values* are redacted (keys preserved) and
    secret-looking ``args`` values are masked with the same helper used by the
    human/``explain`` output, so the machine report never carries a secret
    pulled from a config.
    """
    configs = [
        {"path": config_path, "servers": len(servers)}
        for config_path, servers in results
    ]
    servers_json = []
    for _config_path, servers in results:
        for server in servers:
            entry = dataclasses.asdict(server)
            entry["args"] = _redact_args(server.args)
            entry["env"] = _redact_mapping(server.env)
            entry["headers"] = _redact_mapping(server.headers)
            servers_json.append(entry)
    return {
        "version": __version__,
        "configs": configs,
        "servers": servers_json,
        "findings": [dataclasses.asdict(finding) for finding in findings],
    }


# SARIF severity levels: HIGH maps to error, MEDIUM to warning, the rest to note.
_SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)


def _build_sarif(findings: List[Finding]) -> dict:
    """Build a SARIF 2.1.0 report payload from the findings."""
    descriptions = rule_descriptions()
    fired_ids = sorted({finding.rule_id for finding in findings})
    rules = [
        {
            "id": rule_id,
            "shortDescription": {"text": descriptions.get(rule_id, rule_id)},
        }
        for rule_id in fired_ids
    ]
    sarif_results = [
        {
            "ruleId": finding.rule_id,
            "level": _SARIF_LEVEL.get(finding.severity, "note"),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location or ""}
                    }
                }
            ],
        }
        for finding in findings
    ]
    return {
        "version": "2.1.0",
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpsec",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def cmd_scan(args: argparse.Namespace) -> int:
    """Discover (or read) MCP configs, inventory servers, and report findings."""
    if args.json and args.sarif:
        print("error: --json and --sarif are mutually exclusive", file=sys.stderr)
        return 2

    if args.path:
        if not os.path.exists(args.path):
            print("error: no such path: {0}".format(args.path), file=sys.stderr)
            return 1
        files = _collect_target_files(args.path)
    else:
        from mcpsec.discovery import discover_existing

        files = discover_existing()

    results, _skipped = _gather(files)
    servers = [server for _config_path, servers in results for server in servers]
    findings = run_rules(servers)

    if args.json:
        print(json.dumps(_build_report(results, findings), indent=2))
    elif args.sarif:
        print(json.dumps(_build_sarif(findings), indent=2))
    else:
        _print_inventory(results)
        _print_findings(findings)
    return 0


def _print_explain_findings(findings: List[Finding]) -> None:
    """Render one server's findings under the explain output."""
    if not findings:
        print("  No findings for this server.")
        return
    for finding in findings:
        print(
            "  [{0}] {1}: {2}".format(
                finding.severity, finding.rule_id, finding.message
            )
        )
        if finding.fix:
            print("      fix: {0}".format(finding.fix))


def cmd_explain(args: argparse.Namespace) -> int:
    """Explain a single named server: transport, secret-bearing keys, findings.

    Loads configs the same way ``scan`` does (an explicit ``path``, else
    discovery), finds every server whose name matches, and reports each match's
    transport and env/header *keys* (values are masked) followed by the rules it
    trips. Returns 1 if no server with that name exists.
    """
    if args.path:
        if not os.path.exists(args.path):
            print("error: no such path: {0}".format(args.path), file=sys.stderr)
            return 1
        files = _collect_target_files(args.path)
    else:
        from mcpsec.discovery import discover_existing

        files = discover_existing()

    results, _skipped = _gather(files)
    matches = [
        server
        for _config_path, servers in results
        for server in servers
        if server.name == args.server
    ]
    if not matches:
        print(
            "error: no server named {0} found".format(args.server),
            file=sys.stderr,
        )
        return 1

    for server in matches:
        print("{0}  ({1})".format(server.name, server.source_file))
        print("  transport: {0}".format(_describe(server)))
        # Show only key names; secret values are never printed.
        if server.env:
            print("  env keys: {0}".format(", ".join(sorted(server.env))))
        if server.headers:
            print("  header keys: {0}".format(", ".join(sorted(server.headers))))
        _print_explain_findings(run_rules([server]))
        print("")
    return 0


# Severity at which ``scan`` should fail by default, recorded in the template.
_POLICY_VERSION = 1
_POLICY_FAIL_ON = "HIGH"


def cmd_policy(args: argparse.Namespace) -> int:
    """Write a policy template (``policy init``).

    The template lists every rule (id and default severity, sourced from
    :data:`mcpsec.rules.RULE_METADATA`) so it can be hand-edited to disable rules
    or adjust severities. Refuses to clobber an existing file without ``--force``.
    """
    if args.action != "init":  # argparse's choices guard this; stay defensive.
        print(
            "error: unknown policy action: {0}".format(args.action),
            file=sys.stderr,
        )
        return 2

    path = args.output
    if os.path.exists(path) and not args.force:
        print(
            "error: {0} exists (use --force to overwrite)".format(path),
            file=sys.stderr,
        )
        return 1

    policy = {
        "version": _POLICY_VERSION,
        "fail_on": _POLICY_FAIL_ON,
        "rules": {
            rule_id: {"enabled": True, "severity": severity}
            for rule_id, severity in RULE_METADATA
        },
    }
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(policy, indent=2))
        handle.write("\n")
    print("wrote {0}".format(path))
    return 0


# Threshold ranking for ``check``. Reuses the engine's SEVERITY_ORDER (single
# source of truth) and extends it with CRITICAL above HIGH so a policy override
# or ``fail_on: CRITICAL`` works even though the engine emits only HIGH..INFO.
# Lower value == more severe.
SEVERITY_RANK = dict(SEVERITY_ORDER, CRITICAL=-1)

# Per-severity tally order for ``check`` output, most->least severe.
_CHECK_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


class _PolicyError(Exception):
    """Raised when a ``--policy`` file is missing, unparseable, or invalid."""


def _load_policy(path: str) -> Tuple[str, dict]:
    """Load a policy file, returning ``(fail_on, rules)``.

    ``fail_on`` is normalised to upper case and validated against the known
    severities; ``rules`` is the (possibly empty) ruleId -> config mapping.
    Raises :class:`_PolicyError` on a missing file, malformed JSON, a non-object
    document, or an unknown ``fail_on`` severity.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        raise _PolicyError("no such policy file: {0}".format(path))
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        raise _PolicyError("could not read policy {0}: {1}".format(path, exc))
    if not isinstance(data, dict):
        raise _PolicyError("policy must be a JSON object")
    fail_on = str(data.get("fail_on", _POLICY_FAIL_ON)).upper()
    if fail_on not in SEVERITY_RANK:
        raise _PolicyError(
            "unknown fail_on severity: {0}".format(data.get("fail_on"))
        )
    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        raise _PolicyError("policy 'rules' must be an object")
    for rule_id, rule_cfg in rules.items():
        if not isinstance(rule_cfg, dict):
            raise _PolicyError("policy rule {0} must be an object".format(rule_id))
        if "enabled" in rule_cfg and not isinstance(rule_cfg["enabled"], bool):
            raise _PolicyError(
                "policy rule {0} enabled must be boolean".format(rule_id)
            )
        if "severity" in rule_cfg:
            severity = str(rule_cfg["severity"]).upper()
            if severity not in SEVERITY_RANK:
                raise _PolicyError(
                    "policy rule {0} has unknown severity: {1}".format(
                        rule_id, rule_cfg["severity"]
                    )
                )
    return fail_on, rules


def _effective_severity(finding: Finding, policy_rules: dict) -> str:
    """Resolve a finding's severity after applying any policy override.

    A known severity override for the finding's rule id wins; otherwise the
    rule engine's emitted severity is used. Policy loading validates override
    severities before this helper is called.
    """
    rule_cfg = policy_rules.get(finding.rule_id)
    if isinstance(rule_cfg, dict) and rule_cfg.get("severity"):
        override = str(rule_cfg["severity"]).upper()
        if override in SEVERITY_RANK:
            return override
    return finding.severity


def _is_enabled(finding: Finding, policy_rules: dict) -> bool:
    """True unless the policy explicitly disables the finding's rule."""
    rule_cfg = policy_rules.get(finding.rule_id)
    if isinstance(rule_cfg, dict):
        return bool(rule_cfg.get("enabled", True))
    return True


def _redact_message(text: str) -> str:
    """Mask secret-looking tokens embedded in a rule message.

    Rule messages can include user-controlled command arguments (for example an
    unpinned ``npx`` package argument). ``check`` is meant for CI logs, so apply
    the same conservative secret-value detector used for args before printing or
    serialising finding messages.
    """
    parts = []
    for token in text.split():
        prefix = token[: len(token) - len(token.lstrip("'\"`([{"))]
        suffix = token[len(token.rstrip("'\"`.,;:)]}")) :]
        core = token[len(prefix) : len(token) - len(suffix) if suffix else len(token)]
        if core and _looks_like_secret_value(core):
            parts.append("{0}{1}{2}".format(prefix, _REDACTED, suffix))
        else:
            parts.append(token)
    return " ".join(parts)


def _evaluate_findings(findings: List[Finding], threshold: str, policy_rules: dict):
    """Apply the policy to each finding.

    Returns a list of ``(finding, effective_severity, blocking)`` tuples,
    preserving the input order (already severity-sorted by the rule engine).
    Policy-disabled rules are omitted entirely; the remaining finding is
    blocking when its effective severity ranks at or above the threshold.
    """
    limit = SEVERITY_RANK.get(threshold, 99)
    evaluated = []
    for finding in findings:
        if not _is_enabled(finding, policy_rules):
            continue
        effective = _effective_severity(finding, policy_rules)
        blocking = SEVERITY_RANK.get(effective, 99) <= limit
        evaluated.append((finding, effective, blocking))
    return evaluated


def _check_counts(evaluated) -> dict:
    """Build the counts block: total, blocking, and a per-(effective-)severity tally."""
    counts = {"total": len(evaluated), "blocking": 0}
    counts.update({severity: 0 for severity in _CHECK_SEVERITIES})
    for _finding, effective, blocking in evaluated:
        if blocking:
            counts["blocking"] += 1
        counts[effective] = counts.get(effective, 0) + 1
    return counts


def _check_finding_entry(finding: Finding, effective: str) -> dict:
    """Serialise a finding for ``--json``, reflecting its effective severity.

    Reuses :func:`dataclasses.asdict` (so the entry mirrors what ``scan`` already
    exposes: rule_id/severity/server/message/fix/location, none of which carry
    secret material) and overwrites ``severity`` with the policy-effective value.
    """
    entry = dataclasses.asdict(finding)
    entry["severity"] = effective
    entry["message"] = _redact_message(entry["message"])
    return entry


def _print_check_human(passed: bool, threshold: str, counts: dict, evaluated) -> None:
    """Render the short, CI-friendly human report to stdout."""
    print("PASS" if passed else "FAIL")
    print("threshold: {0}".format(threshold))
    print(
        "findings: {0} total, {1} blocking".format(
            counts["total"], counts["blocking"]
        )
    )
    tally = "  ".join(
        "{0} {1}".format(severity, counts[severity])
        for severity in _CHECK_SEVERITIES
        # CRITICAL is shown only when present; the engine never emits it.
        if severity != "CRITICAL" or counts.get("CRITICAL", 0)
    )
    print("severity: {0}".format(tally))

    blocking = [(f, eff) for f, eff, is_block in evaluated if is_block]
    if not blocking:
        print("No blocking findings.")
        return
    print("Blocking findings:")
    for finding, effective in blocking:
        print(
            "  [{0}] {1}  {2}".format(effective, finding.rule_id, finding.server)
        )
        print("      {0}".format(_redact_message(finding.message)))
        if finding.fix:
            print("      fix: {0}".format(finding.fix))


def cmd_check(args: argparse.Namespace) -> int:
    """Re-run the rules as a CI gate, exiting non-zero on a blocking finding.

    Scans the same inputs as ``scan`` (an explicit ``path``, else discovery),
    applies an optional ``--policy`` (severity threshold, per-rule enable flags
    and severity overrides), and reports PASS/FAIL. Exit codes: 0 = clean,
    1 = at least one blocking finding, 2 = invalid usage / policy error.
    """
    if args.policy is not None:
        try:
            threshold, policy_rules = _load_policy(args.policy)
        except _PolicyError as exc:
            print("error: {0}".format(exc), file=sys.stderr)
            return 2
    else:
        threshold, policy_rules = _POLICY_FAIL_ON, {}

    if args.path:
        if not os.path.exists(args.path):
            print("error: no such path: {0}".format(args.path), file=sys.stderr)
            return 2
        files = _collect_target_files(args.path)
    else:
        from mcpsec.discovery import discover_existing

        files = discover_existing()

    results, _skipped = _gather(files)
    servers = [server for _config_path, servers in results for server in servers]
    findings = run_rules(servers)

    evaluated = _evaluate_findings(findings, threshold, policy_rules)
    counts = _check_counts(evaluated)
    passed = counts["blocking"] == 0

    if args.json:
        report = {
            "pass": passed,
            "threshold": threshold,
            "counts": counts,
            "blocking_findings": [
                _check_finding_entry(finding, effective)
                for finding, effective, blocking in evaluated
                if blocking
            ],
            "findings": [
                _check_finding_entry(finding, effective)
                for finding, effective, _blocking in evaluated
            ],
        }
        print(json.dumps(report))
    else:
        _print_check_human(passed, threshold, counts, evaluated)

    return 0 if passed else 1


_REVIEW_PERMISSION_LABELS = {
    "MCPSEC001": "Inline secret exposure",
    "MCPSEC002": "Authentication header exposure",
    "MCPSEC003": "Unpinned package execution",
    "MCPSEC004": "Auto-install package execution",
    "MCPSEC005": "Filesystem-wide access",
    "MCPSEC006": "Shell execution",
    "MCPSEC007": "Plaintext remote endpoint",
    "MCPSEC008": "Remote HTTPS endpoint",
    "MCPSEC009": "Sampling / model-callback permission",
}


def _decision_for_severities(severities: List[str]) -> str:
    """Return the top-level permission decision for a set of severities."""
    if any(sev in ("CRITICAL", "HIGH") for sev in severities):
        return "DENY"
    if any(sev == "MEDIUM" for sev in severities):
        return "REVIEW"
    return "APPROVE"


def _highest_severity(findings: List[Finding]) -> str:
    """Return the most severe finding level, or INFO for clean servers."""
    if not findings:
        return "INFO"
    return min((finding.severity for finding in findings), key=lambda sev: SEVERITY_RANK.get(sev, 99))


def _server_review_entry(server: ServerDef, findings: List[Finding]) -> dict:
    """Build one server's permission-review entry with redacted transport data."""
    severities = [finding.severity for finding in findings]
    risk = _highest_severity(findings)
    return {
        "name": server.name,
        "source_file": server.source_file,
        "transport": _describe(server),
        "risk": risk if findings else "NONE",
        "recommendation": _decision_for_severities(severities),
        "permissions": sorted(
            {_REVIEW_PERMISSION_LABELS.get(finding.rule_id, finding.rule_id) for finding in findings}
        ),
        "env_keys": sorted(server.env),
        "header_keys": sorted(server.headers),
        "findings": [_check_finding_entry(finding, finding.severity) for finding in findings],
    }


def _build_review(results: List[Tuple[str, List[ServerDef]]], findings: List[Finding]) -> dict:
    """Build the permission-review payload used by markdown and JSON output."""
    findings_by_identity = {}
    findings_by_name = {}
    for finding in findings:
        if finding.location:
            findings_by_identity.setdefault((finding.server, finding.location), []).append(finding)
        else:
            findings_by_name.setdefault(finding.server, []).append(finding)
    servers = [server for _config_path, group in results for server in group]
    server_entries = [
        _server_review_entry(
            server,
            findings_by_identity.get((server.name, server.source_file), [])
            + findings_by_name.get(server.name, []),
        )
        for server in servers
    ]
    severities = [finding.severity for finding in findings]
    summary = {severity: 0 for severity in _SEVERITIES}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1
    summary.update(
        {
            "configs": len(results),
            "servers": len(servers),
            "findings": len(findings),
        }
    )
    return {
        "version": __version__,
        "decision": _decision_for_severities(severities),
        "summary": summary,
        "servers": server_entries,
    }


def _print_review_markdown(report: dict) -> None:
    """Render a human-readable permission review as Markdown."""
    summary = report["summary"]
    print("# MCP Permission Review")
    print("")
    print("Decision: {0}".format(report["decision"]))
    print("Servers reviewed: {0}".format(summary["servers"]))
    print(
        "Findings: {0} total — HIGH {1}, MEDIUM {2}, LOW {3}, INFO {4}".format(
            summary["findings"],
            summary.get("HIGH", 0),
            summary.get("MEDIUM", 0),
            summary.get("LOW", 0),
            summary.get("INFO", 0),
        )
    )
    print("")
    if report["decision"] == "APPROVE":
        print("No risky MCP permissions detected.")
        print("")
    buckets = [
        ("## High-risk servers", {"HIGH", "CRITICAL"}),
        ("## Needs review", {"MEDIUM", "LOW", "INFO"}),
    ]
    for title, severities in buckets:
        entries = [server for server in report["servers"] if server["risk"] in severities and server["findings"]]
        if not entries:
            continue
        print(title)
        print("")
        for server in entries:
            print("### {0}".format(server["name"]))
            print("- Source: `{0}`".format(server["source_file"]))
            print("- Transport: `{0}`".format(server["transport"]))
            print("- Risk: {0}".format(server["risk"]))
            print("- Recommended action: {0}".format(server["recommendation"]))
            if server["env_keys"]:
                print("- Env keys: {0}".format(", ".join("`{0}`".format(k) for k in server["env_keys"])))
            if server["header_keys"]:
                print("- Header keys: {0}".format(", ".join("`{0}`".format(k) for k in server["header_keys"])))
            print("- Permissions:")
            for permission in server["permissions"]:
                print("  - {0}".format(permission))
            print("- Findings:")
            for finding in server["findings"]:
                print("  - [{0}] {1}: {2}".format(finding["severity"], finding["rule_id"], finding["message"]))
                if finding.get("fix"):
                    print("    - Fix: {0}".format(finding["fix"]))
            print("")
    if report["decision"] == "DENY":
        print("Recommended action: DENY until HIGH findings are fixed or explicitly accepted in policy.")
    elif report["decision"] == "REVIEW":
        print("Recommended action: REVIEW before approval; no HIGH findings were detected.")
    else:
        print("Recommended action: APPROVE")


def cmd_review(args: argparse.Namespace) -> int:
    """Render a permission-oriented MCP security review."""
    if args.path:
        if not os.path.exists(args.path):
            print("error: no such path: {0}".format(args.path), file=sys.stderr)
            return 1
        files = _collect_target_files(args.path)
    else:
        from mcpsec.discovery import discover_existing

        files = discover_existing()
    results, _skipped = _gather(files)
    servers = [server for _config_path, group in results for server in group]
    findings = run_rules(servers)
    report = _build_review(results, findings)
    if args.json or args.format == "json":
        print(json.dumps(report))
    else:
        _print_review_markdown(report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser with the ``scan``/``explain``/``policy``/``check`` subcommands."""
    parser = argparse.ArgumentParser(
        prog="mcpsec",
        description="CLI-first security scanner for MCP configurations.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="mcpsec {0}".format(__version__),
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="Inventory MCP servers from a config file/dir, or via discovery.",
    )
    scan.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Config file or directory to scan. Omit to auto-discover.",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a human-readable inventory.",
    )
    scan.add_argument(
        "--sarif",
        action="store_true",
        help="Emit a SARIF 2.1.0 report (mutually exclusive with --json).",
    )
    scan.set_defaults(func=cmd_scan)

    explain = subparsers.add_parser(
        "explain",
        help="Explain a single named server: transport, keys, and findings.",
    )
    explain.add_argument(
        "server",
        help="Name of the MCP server to explain.",
    )
    explain.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Config file or directory to read. Omit to auto-discover.",
    )
    explain.set_defaults(func=cmd_explain)


    review = subparsers.add_parser(
        "review",
        help="Render a permission-oriented MCP security review.",
    )
    review.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Config file or directory to review. Omit to auto-discover.",
    )
    review.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format for the review (default markdown).",
    )
    review.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON review instead of Markdown (alias for --format json).",
    )
    review.set_defaults(func=cmd_review)

    policy = subparsers.add_parser(
        "policy", help="Manage policy templates."
    )
    policy.add_argument(
        "action",
        choices=["init"],
        help="Policy action to perform.",
    )
    policy.add_argument(
        "--output",
        default=os.path.join(".", "mcpsec.policy.json"),
        help="Path to write the policy template (default ./mcpsec.policy.json).",
    )
    policy.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )
    policy.set_defaults(func=cmd_policy)

    check = subparsers.add_parser(
        "check",
        help="CI gate: fail when a finding is at/above a severity threshold.",
    )
    check.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Config file or directory to check. Omit to auto-discover.",
    )
    check.add_argument(
        "--policy",
        default=None,
        help="Path to a policy JSON file (as written by 'policy init').",
    )
    check.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON result instead of a human report.",
    )
    check.set_defaults(func=cmd_check)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point for both the console script and ``python3 -m mcpsec``."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
