"""Locate MCP configuration files in well-known locations.

The ``home``/``env``/``cwd`` parameters are injectable so callers (and tests) can
point discovery at a sandbox instead of the real machine.
"""

import os
from typing import Dict, List, Optional


def _resolve_home(home: Optional[str], env: Optional[Dict[str, str]]) -> str:
    """Pick the home directory: explicit arg, then ``env['HOME']``, then ``~``."""
    if home is not None:
        return home
    if env is not None and env.get("HOME"):
        return env["HOME"]
    return os.path.expanduser("~")


def default_config_candidates(
    home: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> List[str]:
    """Return candidate MCP config paths, whether or not they exist.

    Home-anchored, well-known locations are absolute; the two generic project
    candidates (``./mcp.json`` and ``./.mcp.json``) are returned as paths
    relative to the current working directory and are resolved against an
    injectable ``cwd`` by :func:`discover_existing`.
    """
    home_dir = _resolve_home(home, env)
    return [
        # Claude Desktop (macOS).
        os.path.join(
            home_dir,
            "Library",
            "Application Support",
            "Claude",
            "claude_desktop_config.json",
        ),
        # Cursor.
        os.path.join(home_dir, ".cursor", "mcp.json"),
        # Hermes.
        os.path.join(home_dir, ".hermes", "mcp.json"),
        # Generic project-local configs (relative to CWD).
        os.path.join(".", "mcp.json"),
        os.path.join(".", ".mcp.json"),
    ]


def discover_existing(
    home: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> List[str]:
    """Return only the candidate paths that exist as files.

    Relative candidates are resolved against ``cwd`` (defaulting to the real
    current working directory) before the existence check.
    """
    base = cwd if cwd is not None else os.getcwd()
    existing: List[str] = []
    for candidate in default_config_candidates(home=home, env=env):
        full = candidate if os.path.isabs(candidate) else os.path.normpath(
            os.path.join(base, candidate)
        )
        if os.path.isfile(full):
            existing.append(full)
    return existing
