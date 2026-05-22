"""Tests for the ``scan`` report output paths (human / JSON / SARIF).

These drive the CLI end-to-end against ``examples/sample.mcp.json`` by calling
:func:`mcpsec.cli.main` and capturing stdout/stderr, so they cover argument
parsing, the rule engine, and serialisation together.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from mcpsec import cli

_SAMPLE = os.path.join(
    os.path.dirname(__file__), os.pardir, "examples", "sample.mcp.json"
)


def _run(argv):
    """Run cli.main(argv), returning (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class JsonReportTest(unittest.TestCase):
    """``--json`` populates the findings list (no longer hardcoded empty)."""

    def test_findings_populated(self):
        code, stdout, _ = _run(["scan", _SAMPLE, "--json"])
        self.assertEqual(code, 0)
        report = json.loads(stdout)
        # Existing keys preserved.
        self.assertEqual(
            sorted(report.keys()), ["configs", "findings", "servers", "version"]
        )
        self.assertTrue(report["findings"], "expected at least one finding")
        first = report["findings"][0]
        for key in ("rule_id", "severity", "server", "message", "fix", "location"):
            self.assertIn(key, first)


class JsonRedactsServerSecretsTest(unittest.TestCase):
    """``--json`` masks env/header *values* but preserves their keys."""

    def test_env_and_header_values_redacted(self):
        code, stdout, _ = _run(["scan", _SAMPLE, "--json"])
        self.assertEqual(code, 0)
        report = json.loads(stdout)
        by_name = {server["name"]: server for server in report["servers"]}

        github = by_name["github"]
        # Key preserved, value masked.
        self.assertIn("GITHUB_PERSONAL_ACCESS_TOKEN", github["env"])
        self.assertEqual(
            github["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"], "<redacted>"
        )

        remote = by_name["remote-api"]
        self.assertIn("Authorization", remote["headers"])
        self.assertEqual(remote["headers"]["Authorization"], "<redacted>")

        # No env/header value escapes redaction, and the raw sample secret is
        # nowhere in the serialised output.
        for server in report["servers"]:
            for value in server["env"].values():
                self.assertEqual(value, "<redacted>")
            for value in server["headers"].values():
                self.assertEqual(value, "<redacted>")
        self.assertNotIn("ghp_example_placeholder_token", stdout)


class JsonRedactsArgSecretsTest(unittest.TestCase):
    """``--json`` masks secret *values* in command args, keeping benign args."""

    def test_arg_secret_values_redacted(self):
        # A standalone OpenAI-style token plus a value passed after --token; the
        # raw secrets must never reach the JSON, but benign args stay verbatim.
        flag_secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        standalone_secret = "sk-abcdefghijklmnopqrstuvwxyz0123"
        config = {
            "mcpServers": {
                "leaky": {
                    "command": "npx",
                    "args": [
                        "server",
                        "pkg@1.2.3",
                        "--token",
                        flag_secret,
                        standalone_secret,
                    ],
                }
            }
        }
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump(config, handle)
            path = handle.name
        try:
            code, stdout, _ = _run(["scan", path, "--json"])
        finally:
            os.unlink(path)

        self.assertEqual(code, 0)
        # Neither secret value appears anywhere in the serialised output.
        self.assertNotIn(flag_secret, stdout)
        self.assertNotIn(standalone_secret, stdout)

        report = json.loads(stdout)
        server = {s["name"]: s for s in report["servers"]}["leaky"]
        args = server["args"]
        self.assertIsInstance(args, list)
        self.assertTrue(all(isinstance(a, str) for a in args))
        # Benign args survive verbatim; the secret slots are masked.
        self.assertIn("server", args)
        self.assertIn("pkg@1.2.3", args)
        self.assertEqual(args, ["server", "pkg@1.2.3", "--token", "<redacted>", "<redacted>"])


class HumanReportTest(unittest.TestCase):
    """The default report prints inventory plus a FINDINGS section + summary."""

    def test_findings_section_and_summary(self):
        code, stdout, _ = _run(["scan", _SAMPLE])
        self.assertEqual(code, 0)
        self.assertIn("Findings:", stdout)
        self.assertIn("Summary:", stdout)
        # The sample trips the inline-secret rule.
        self.assertIn("MCPSEC001", stdout)


class SarifReportTest(unittest.TestCase):
    """``--sarif`` emits valid SARIF 2.1.0 JSON with at least one result."""

    def test_sarif_shape(self):
        code, stdout, _ = _run(["scan", _SAMPLE, "--sarif"])
        self.assertEqual(code, 0)
        report = json.loads(stdout)
        self.assertEqual(report["version"], "2.1.0")
        self.assertIn("$schema", report)
        run = report["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "mcpsec")
        self.assertTrue(run["tool"]["driver"]["rules"])
        results = run["results"]
        self.assertGreaterEqual(len(results), 1)
        first = results[0]
        self.assertIn(first["level"], ("error", "warning", "note"))
        self.assertIn("text", first["message"])
        uri = first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertTrue(uri)


class MutualExclusionTest(unittest.TestCase):
    """``--json`` and ``--sarif`` together is an error (exit 2)."""

    def test_json_and_sarif_returns_2(self):
        code, _, stderr = _run(["scan", _SAMPLE, "--json", "--sarif"])
        self.assertEqual(code, 2)
        self.assertIn("mutually exclusive", stderr)


if __name__ == "__main__":
    unittest.main()
