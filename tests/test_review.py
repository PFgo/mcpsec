"""Tests for the ``review`` permission-review command."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from mcpsec import cli

_EXAMPLES = os.path.join(os.path.dirname(__file__), os.pardir, "examples")
_INSECURE = os.path.join(_EXAMPLES, "insecure.mcp.json")
_CLEAN = os.path.join(_EXAMPLES, "clean.mcp.json")


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _write(tmp, name, obj):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle)
    return path


class ReviewMarkdownTest(unittest.TestCase):
    def test_insecure_review_is_denied_and_explains_permissions(self):
        code, stdout, stderr = _run(["review", _INSECURE])
        self.assertEqual(code, 0, stderr)
        self.assertIn("# MCP Permission Review", stdout)
        self.assertIn("Decision: DENY", stdout)
        self.assertIn("Servers reviewed: 4", stdout)
        self.assertIn("## High-risk servers", stdout)
        self.assertIn("filesystem-root", stdout)
        self.assertIn("Filesystem-wide access", stdout)
        self.assertIn("Shell execution", stdout)
        self.assertIn("Plaintext remote endpoint", stdout)
        self.assertIn("Recommended action: DENY", stdout)

    def test_clean_review_is_approved(self):
        code, stdout, stderr = _run(["review", _CLEAN])
        self.assertEqual(code, 0, stderr)
        self.assertIn("Decision: APPROVE", stdout)
        self.assertIn("No risky MCP permissions detected.", stdout)


    def test_explicit_markdown_format_is_supported(self):
        code, stdout, stderr = _run(["review", _CLEAN, "--format", "markdown"])
        self.assertEqual(code, 0, stderr)
        self.assertIn("# MCP Permission Review", stdout)
        self.assertIn("Decision: APPROVE", stdout)


class ReviewJsonTest(unittest.TestCase):
    def test_json_shape_contains_decision_counts_and_server_risks(self):
        code, stdout, stderr = _run(["review", _INSECURE, "--format", "json"])
        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["decision"], "DENY")
        self.assertEqual(report["summary"]["servers"], 4)
        self.assertEqual(report["summary"]["HIGH"], 3)
        self.assertIn("servers", report)
        by_name = {server["name"]: server for server in report["servers"]}
        self.assertEqual(by_name["filesystem-root"]["risk"], "HIGH")
        self.assertEqual(by_name["filesystem-root"]["recommendation"], "DENY")
        self.assertTrue(by_name["filesystem-root"]["permissions"])
        self.assertTrue(by_name["filesystem-root"]["findings"])

    def test_json_clean_review_is_approve(self):
        code, stdout, stderr = _run(["review", _CLEAN, "--json"])
        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["decision"], "APPROVE")
        self.assertEqual(report["summary"]["findings"], 0)
        self.assertEqual(report["servers"][0]["recommendation"], "APPROVE")


class ReviewSecretRedactionTest(unittest.TestCase):
    def test_review_does_not_echo_secret_args_or_env_values(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz0123"
        with tempfile.TemporaryDirectory() as tmp:
            config = _write(
                tmp,
                "leaky.mcp.json",
                {
                    "mcpServers": {
                        "leaky": {
                            "command": "npx",
                            "args": [secret],
                            "env": {"OPENAI_API_KEY": secret},
                        }
                    }
                },
            )
            code, stdout, stderr = _run(["review", config])
            self.assertEqual(code, 0, stderr)
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, stderr)
            self.assertIn("<redacted>", stdout)

    def test_review_does_not_echo_secret_url_credentials_or_query_values(self):
        secret = "URL_SECRET_VALUE_12345"
        with tempfile.TemporaryDirectory() as tmp:
            config = _write(
                tmp,
                "remote-secret.mcp.json",
                {
                    "mcpServers": {
                        "remote": {
                            "url": (
                                "https://user:"
                                + secret
                                + "@api.example.com/mcp?api_"
                                + "key="
                                + secret
                                + "&safe=ok#"
                                + secret
                            )
                        }
                    }
                },
            )
            code, stdout, stderr = _run(["review", config, "--json"])
            self.assertEqual(code, 0, stderr)
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, stderr)
            report = json.loads(stdout)
            self.assertIn("<redacted>", report["servers"][0]["transport"])
            self.assertIn("api_key=<redacted>", report["servers"][0]["transport"])
            self.assertIn("safe=ok", report["servers"][0]["transport"])


class ReviewDuplicateServerNameTest(unittest.TestCase):
    def test_findings_are_attributed_by_name_and_source_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            clean = _write(
                tmp,
                "a-clean.mcp.json",
                {"mcpServers": {"dup": {"command": "echo", "args": ["ok"]}}},
            )
            risky = _write(
                tmp,
                "b-risky.mcp.json",
                {"mcpServers": {"dup": {"command": "bash", "args": ["-c", "echo hi"]}}},
            )
            self.assertTrue(clean and risky)
            code, stdout, stderr = _run(["review", tmp, "--json"])
            self.assertEqual(code, 0, stderr)
            report = json.loads(stdout)
            entries = sorted(report["servers"], key=lambda item: item["source_file"])
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0]["name"], "dup")
            self.assertEqual(entries[0]["recommendation"], "APPROVE")
            self.assertEqual(entries[0]["findings"], [])
            self.assertEqual(entries[1]["name"], "dup")
            self.assertEqual(entries[1]["recommendation"], "DENY")
            self.assertEqual(entries[1]["findings"][0]["rule_id"], "MCPSEC006")


if __name__ == "__main__":
    unittest.main()
