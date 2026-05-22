"""Command-line interface for mcpsec.

``scan`` discovers (or reads) MCP configs, inventories their servers, and runs
the risk-rule engine, reporting findings as a human-readable report (default),
``--json``, or ``--sarif`` (SARIF 2.1.0). ``explain`` focuses the same machinery
on a single named server, and ``policy init`` writes a policy template.
"""

import argparse
import dataclasses
import json
import os
import sys
from typing import List, Optional, Tuple

from mcpsec import __version__
from mcpsec.models import Finding, ServerDef
from mcpsec.parser import load_config, normalize
from mcpsec.rules import (
    RULE_METADATA,
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
        return "url: {0}".format(server.url)
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


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser with the ``scan``/``explain``/``policy`` subcommands."""
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
