"""Tests for the user-facing ``audit`` entry point.

``audit`` is the customer-friendly command for reviewing real app configs such as
Hermes ``~/.hermes/config.yaml``. These tests cover behavior rather than argparse
internals: YAML Hermes-shaped config is accepted, output is a permission review,
and JSON mode is machine-readable.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from mcpsec import cli
from mcpsec.discovery import default_config_candidates


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class AuditCommandTest(unittest.TestCase):
    def test_audit_reviews_hermes_config_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.yaml")
            with open(config, "w", encoding="utf-8") as handle:
                handle.write(
                    "mcp:\n"
                    "  servers:\n"
                    "    filesystem-root:\n"
                    "      command: npx\n"
                    "      args:\n"
                    "        - -y\n"
                    "        - '@modelcontextprotocol/server-filesystem'\n"
                    "        - /\n"
                )

            code, stdout, stderr = _run(["audit", config])

        self.assertEqual(code, 0, stderr)
        self.assertIn("# MCP Permission Review", stdout)
        self.assertIn("filesystem-root", stdout)
        self.assertIn("Filesystem-wide access", stdout)
        self.assertEqual(stderr, "")

    def test_audit_json_is_machine_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.yaml")
            with open(config, "w", encoding="utf-8") as handle:
                handle.write(
                    "mcp:\n"
                    "  servers:\n"
                    "    safe-docs:\n"
                    "      command: uvx\n"
                    "      args:\n"
                    "        - docs-server\n"
                )

            code, stdout, stderr = _run(["audit", config, "--json"])

        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["summary"]["servers"], 1)
        self.assertEqual(report["servers"][0]["name"], "safe-docs")
        self.assertEqual(stderr, "")

    def test_discovery_includes_hermes_config_yaml(self):
        candidates = default_config_candidates(home="/fake/home")

        self.assertIn(os.path.join("/fake/home", ".hermes", "config.yaml"), candidates)


if __name__ == "__main__":
    unittest.main()
