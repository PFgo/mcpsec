"""Static risk-rule engine for mcpsec.

Each rule inspects a single :class:`~mcpsec.models.ServerDef` and yields zero or
more :class:`~mcpsec.models.Finding` objects. :func:`run_rules` runs every rule
over every server and returns the aggregated findings, sorted by severity then
rule id (then server name) for stable output.
"""

import os
import re
from typing import Dict, Iterator, List

from mcpsec.models import Finding, ServerDef

# Lower value == more severe; used as the primary sort key.
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


# --- MCPSEC001: inline secrets ------------------------------------------------

_SECRET_VALUE_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{12,}"),
    re.compile(r"gh[opsu]_[A-Za-z0-9]{16,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xoxb-[A-Za-z0-9\-]{8,}"),
]

_SECRET_NAME_FRAGMENTS = ("SECRET", "TOKEN", "PASSWORD", "APIKEY", "API_KEY")


def _looks_like_secret_value(value: str) -> bool:
    return bool(value) and any(p.search(value) for p in _SECRET_VALUE_PATTERNS)


def _name_implies_secret(key: str) -> bool:
    upper = key.upper()
    return any(frag in upper for frag in _SECRET_NAME_FRAGMENTS)


def rule_inline_secret(server: ServerDef) -> Iterator[Finding]:
    """MCPSEC001: a literal secret value, or a secret-named key with a value."""
    for source, mapping in (("env var", server.env), ("header", server.headers)):
        for key, raw in mapping.items():
            value = "" if raw is None else str(raw)
            if _looks_like_secret_value(value) or (
                _name_implies_secret(key) and value.strip()
            ):
                yield Finding(
                    rule_id="MCPSEC001",
                    severity="HIGH",
                    server=server.name,
                    message="{0} '{1}' appears to hold a hardcoded secret".format(
                        source, key
                    ),
                    fix="Move it to a secret manager / inject it from the environment at runtime.",
                    location=server.source_file,
                )


# --- MCPSEC002: auth headers --------------------------------------------------

_AUTH_HEADER_NAMES = {"authorization", "x-api-key", "api-key"}


def rule_auth_header(server: ServerDef) -> Iterator[Finding]:
    """MCPSEC002: a header carrying authentication credentials."""
    for key in server.headers:
        if key.lower() in _AUTH_HEADER_NAMES:
            yield Finding(
                rule_id="MCPSEC002",
                severity="MEDIUM",
                server=server.name,
                message="header '{0}' embeds authentication credentials".format(key),
                fix="Avoid embedding auth in config; inject credentials at runtime.",
                location=server.source_file,
            )


# --- npx/uvx helpers ----------------------------------------------------------

_NODE_RUNNERS = {"npx", "uvx"}

# Executable suffixes stripped before runner comparison so Windows launchers
# (npx.cmd, powershell.exe, bash.exe, ...) are detected like their bare names.
_RUNNER_SUFFIXES = (".exe", ".cmd", ".bat", ".com")


def _runner_basename(server: ServerDef):
    if not server.command:
        return None
    base = os.path.basename(server.command).lower()
    for suffix in _RUNNER_SUFFIXES:
        if base.endswith(suffix):
            return base[: -len(suffix)]
    return base


def _is_node_runner(server: ServerDef) -> bool:
    return _runner_basename(server) in _NODE_RUNNERS


def _package_arg(args: List[str]):
    """First non-flag argument (the package spec), ignoring leading flags."""
    for arg in args:
        if arg.startswith("-"):
            continue
        return arg
    return None


def _is_pinned(pkg: str) -> bool:
    """True if the package spec carries an exact version pin.

    Recognises both the npx ``pkg@1.2.3`` form and the PEP 508 exact pin
    ``pkg==1.2.3`` (so ``uvx ruff==0.6.9`` counts as pinned), each requiring a
    digit after the delimiter so a bare ``pkg@`` / ``pkg==`` is not mistaken for
    a pin.
    """
    eq = pkg.find("==")
    if eq > 0 and eq + 2 < len(pkg) and pkg[eq + 2].isdigit():
        return True
    at = pkg.rfind("@")
    return at > 0 and at + 1 < len(pkg) and pkg[at + 1].isdigit()


def rule_unpinned_npx(server: ServerDef) -> Iterator[Finding]:
    """MCPSEC003: an npx/uvx package run without a pinned version."""
    if not _is_node_runner(server):
        return
    pkg = _package_arg(server.args)
    if pkg and not _is_pinned(pkg):
        yield Finding(
            rule_id="MCPSEC003",
            severity="MEDIUM",
            server=server.name,
            message="package '{0}' is run via {1} without a pinned version".format(
                pkg, _runner_basename(server)
            ),
            fix="Pin an exact version, e.g. package@1.2.3.",
            location=server.source_file,
        )


def rule_npx_yes(server: ServerDef) -> Iterator[Finding]:
    """MCPSEC004: an npx/uvx invocation with auto-install (-y/--yes)."""
    if not _is_node_runner(server):
        return
    if any(arg in ("-y", "--yes") for arg in server.args):
        yield Finding(
            rule_id="MCPSEC004",
            severity="LOW",
            server=server.name,
            message="{0} is invoked with auto-install (-y/--yes)".format(
                _runner_basename(server)
            ),
            fix="Review the package before enabling auto-install.",
            location=server.source_file,
        )


# --- MCPSEC005: broad filesystem access ---------------------------------------

_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")


def _broad_paths():
    paths = {"/", "~", os.path.expanduser("~")}
    env_home = os.environ.get("HOME")
    if env_home:
        paths.add(env_home)
    return paths


def rule_broad_fs_path(server: ServerDef) -> Iterator[Finding]:
    """MCPSEC005: an argument that grants filesystem-wide access."""
    broad = _broad_paths()
    for arg in server.args:
        if arg in broad or _DRIVE_ROOT.match(arg):
            yield Finding(
                rule_id="MCPSEC005",
                severity="HIGH",
                server=server.name,
                message="argument '{0}' grants filesystem-wide access".format(arg),
                fix="Scope the path to a specific subdirectory.",
                location=server.source_file,
            )


# --- MCPSEC006: shell wrappers ------------------------------------------------

_SHELLS = {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"}
# Built from _SHELLS so a pipe into any known shell (incl. pwsh/powershell/cmd)
# is caught; sorted for a deterministic alternation.
_PIPE_TO_SHELL = re.compile(
    r"\|\s*(" + "|".join(sorted(_SHELLS)) + r")\b"
)


def rule_shell_wrapper(server: ServerDef) -> Iterator[Finding]:
    """MCPSEC006: a shell run with -c, or a command piped into a shell."""
    base = _runner_basename(server)
    if base in _SHELLS and any(arg == "-c" for arg in server.args):
        yield Finding(
            rule_id="MCPSEC006",
            severity="HIGH",
            server=server.name,
            message="command '{0}' runs a shell with -c".format(base),
            fix="Invoke the target binary directly instead of through a shell.",
            location=server.source_file,
        )
        return
    for arg in server.args:
        if _PIPE_TO_SHELL.search(arg):
            yield Finding(
                rule_id="MCPSEC006",
                severity="HIGH",
                server=server.name,
                message="argument pipes output into a shell interpreter",
                fix="Invoke the target binary directly instead of through a shell.",
                location=server.source_file,
            )
            return


# --- MCPSEC007 / MCPSEC008: remote transport ----------------------------------


def rule_insecure_remote_http(server: ServerDef) -> Iterator[Finding]:
    """MCPSEC007: a remote server reached over plaintext http://."""
    if server.url and server.url.lower().startswith("http://"):
        yield Finding(
            rule_id="MCPSEC007",
            severity="HIGH",
            server=server.name,
            message="remote server uses insecure http:// transport",
            fix="Use an https:// endpoint.",
            location=server.source_file,
        )


def rule_remote_endpoint_review(server: ServerDef) -> Iterator[Finding]:
    """MCPSEC008: a remote https:// endpoint worth reviewing for trust."""
    if server.url and server.url.lower().startswith("https://"):
        yield Finding(
            rule_id="MCPSEC008",
            severity="INFO",
            server=server.name,
            message="remote https:// endpoint should be reviewed for trust",
            fix="Confirm the endpoint is operated by a trusted party.",
            location=server.source_file,
        )


# --- MCPSEC009: sampling ------------------------------------------------------


def rule_sampling_enabled(server: ServerDef) -> Iterator[Finding]:
    """MCPSEC009: the server requests sampling (model-completion callbacks)."""
    if server.sampling:
        yield Finding(
            rule_id="MCPSEC009",
            severity="MEDIUM",
            server=server.name,
            message="server requests sampling (model completion callbacks)",
            fix="Confirm sampling/LLM-callback is intended; it lets the server request model completions.",
            location=server.source_file,
        )


RULES = [
    rule_inline_secret,
    rule_auth_header,
    rule_unpinned_npx,
    rule_npx_yes,
    rule_broad_fs_path,
    rule_shell_wrapper,
    rule_insecure_remote_http,
    rule_remote_endpoint_review,
    rule_sampling_enabled,
]

# (rule_id, default severity) for every rule, in id order. Single source of
# truth for tooling that needs the rule catalogue without running the engine
# (e.g. ``policy init``); kept beside RULES so the two stay in step.
RULE_METADATA = [
    ("MCPSEC001", "HIGH"),
    ("MCPSEC002", "MEDIUM"),
    ("MCPSEC003", "MEDIUM"),
    ("MCPSEC004", "LOW"),
    ("MCPSEC005", "HIGH"),
    ("MCPSEC006", "HIGH"),
    ("MCPSEC007", "HIGH"),
    ("MCPSEC008", "INFO"),
    ("MCPSEC009", "MEDIUM"),
]


def run_rules(servers: List[ServerDef]) -> List[Finding]:
    """Run every rule over every server, returning aggregated, sorted findings."""
    findings: List[Finding] = []
    for server in servers:
        for rule in RULES:
            findings.extend(rule(server))
    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule_id, f.server)
    )
    return findings


def rule_descriptions() -> Dict[str, str]:
    """Map each rule id to a short description, derived from the rule docstrings.

    Each rule's docstring opens with ``"MCPSEC0NN: <description>"``; this keeps a
    single source of truth so reports (e.g. SARIF ``tool.driver.rules``) need not
    duplicate the text.
    """
    descriptions: Dict[str, str] = {}
    for rule in RULES:
        first_line = (rule.__doc__ or "").strip().splitlines()[0]
        rule_id, _, text = first_line.partition(":")
        if text:
            descriptions[rule_id.strip()] = text.strip()
    return descriptions


def rule_catalog() -> List[Dict[str, str]]:
    """Join rule metadata with descriptions into a catalogue, sorted by id.

    Combines :data:`RULE_METADATA` (rule id, default severity) with
    :func:`rule_descriptions` (rule id -> short description) into a list of
    ``{"rule_id", "severity", "description"}`` dicts sorted by rule id. This is
    the single source of truth for consumers that need the rule catalogue without
    running the engine (e.g. the ``mcpsec rules`` command), so they need not
    re-list rule ids, severities, or descriptions.
    """
    descriptions = rule_descriptions()
    return [
        {
            "rule_id": rule_id,
            "severity": severity,
            "description": descriptions.get(rule_id, ""),
        }
        for rule_id, severity in sorted(RULE_METADATA)
    ]
