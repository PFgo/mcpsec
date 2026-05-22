"""Core data models for mcpsec.

These dataclasses are the shared vocabulary between discovery, parsing, the CLI,
and (in later stages) the risk-rule engine. They are intentionally plain data
holders with no behaviour beyond construction.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ServerDef:
    """A single MCP server entry extracted from a config file.

    Both stdio-style servers (``command`` + ``args``) and remote/HTTP servers
    (``url`` + ``headers``) are represented by this one shape; fields that do not
    apply to a given server are left at their empty/``None`` defaults.
    """

    name: str
    source_file: str
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    sampling: Optional[Any] = None


@dataclass
class Finding:
    """A single issue reported by a risk rule.

    Produced by the rule engine (:mod:`mcpsec.rules`) and rendered by ``scan`` in
    the human, ``--json``, and ``--sarif`` outputs.
    """

    rule_id: str
    severity: str
    server: str
    message: str
    fix: Optional[str] = None
    location: Optional[str] = None
