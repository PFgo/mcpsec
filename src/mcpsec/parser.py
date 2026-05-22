"""Load MCP config files and normalize them into :class:`ServerDef` objects.

JSON is always supported via the standard library. YAML is supported only when
PyYAML happens to be importable; otherwise YAML files are skipped with a warning
rather than crashing the scan.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

try:  # PyYAML is an optional, best-effort dependency.
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - exercised by environments without PyYAML
    yaml = None

from mcpsec.models import ServerDef

_YAML_EXTS = (".yaml", ".yml")


def load_config(path: str) -> Optional[Any]:
    """Parse a config file into raw Python data.

    Returns the decoded object (typically a ``dict``), or ``None`` when the file
    is a YAML file but PyYAML is unavailable (a warning is printed to stderr and
    the file is skipped). JSON decode errors are allowed to propagate so callers
    can decide how to surface them.
    """
    ext = os.path.splitext(path)[1].lower()
    if ext in _YAML_EXTS:
        if yaml is None:
            print(
                "warning: skipping {0} (YAML support requires PyYAML, "
                "which is not installed)".format(path),
                file=sys.stderr,
            )
            return None
        with open(path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _coerce_str_list(value: Any) -> List[str]:
    """Return a list of strings, tolerating missing or malformed input."""
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return []


def _coerce_str_dict(value: Any) -> Dict[str, str]:
    """Return a ``str -> str`` mapping, tolerating missing or malformed input."""
    if isinstance(value, dict):
        return {str(key): str(val) for key, val in value.items()}
    return {}


def normalize(path: str, data: Any) -> List[ServerDef]:
    """Convert raw config data into a list of :class:`ServerDef`.

    Supports both ``{"mcpServers": {...}}`` and ``{"servers": {...}}`` shapes
    (and a file containing both). Missing or malformed fields degrade to empty
    defaults rather than raising.
    """
    servers: List[ServerDef] = []
    if not isinstance(data, dict):
        return servers

    for section_key in ("mcpServers", "servers"):
        section = data.get(section_key)
        if not isinstance(section, dict):
            continue
        for name, entry in section.items():
            if not isinstance(entry, dict):
                # Record that the server exists even if its body is malformed.
                servers.append(ServerDef(name=str(name), source_file=path))
                continue
            servers.append(
                ServerDef(
                    name=str(name),
                    source_file=path,
                    command=entry.get("command"),
                    args=_coerce_str_list(entry.get("args")),
                    env=_coerce_str_dict(entry.get("env")),
                    url=entry.get("url"),
                    headers=_coerce_str_dict(entry.get("headers")),
                    sampling=entry.get("sampling"),
                )
            )
    return servers
