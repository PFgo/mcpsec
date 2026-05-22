"""Tests for the ``check`` subcommand (policy-aware CI gate).

These drive the CLI by calling :func:`mcpsec.cli.main` and capturing
stdout/stderr/exit, mirroring the style of ``test_policy.py`` and
``test_report.py``. Policy files and synthetic configs are written into a
temporary directory.
"""

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
    """Run cli.main(argv), returning (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _write(tmp, name, obj):
    """Write ``obj`` as JSON into ``tmp/name`` and return the path."""
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle)
    return path


class CheckDefaultThresholdTest(unittest.TestCase):
    """With no policy the threshold is HIGH."""

    def test_insecure_example_fails(self):
        # (a) insecure example has HIGH findings -> blocking -> exit 1, FAIL.
        code, stdout, _ = _run(["check", _INSECURE])
        self.assertEqual(code, 1)
        self.assertTrue(stdout.startswith("FAIL"), stdout)

    def test_clean_example_passes(self):
        # (b) clean example has no findings -> exit 0, PASS.
        code, stdout, _ = _run(["check", _CLEAN])
        self.assertEqual(code, 0)
        self.assertTrue(stdout.startswith("PASS"), stdout)


class CheckJsonTest(unittest.TestCase):
    """``--json`` emits a structured, parseable result."""

    def test_json_shape_on_insecure(self):
        # (c)
        code, stdout, _ = _run(["check", _INSECURE, "--json"])
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["pass"], False)
        self.assertEqual(report["threshold"], "HIGH")
        self.assertIn("counts", report)
        self.assertEqual(report["counts"]["total"], 6)
        self.assertGreaterEqual(report["counts"]["blocking"], 1)
        # Per-severity tally present.
        for severity in ("HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertIn(severity, report["counts"])
        self.assertTrue(report["blocking_findings"], "expected blocking findings")
        self.assertTrue(report["findings"], "expected findings")
        # Each finding entry carries the documented fields.
        for entry in report["findings"]:
            for key in ("rule_id", "severity", "server", "message", "fix"):
                self.assertIn(key, entry)


class CheckDisableRuleTest(unittest.TestCase):
    """A disabled rule's findings never block."""

    def test_disabled_rule_unblocks(self):
        # (d) single HIGH finding (insecure http remote); disabling its rule
        # leaves nothing blocking -> PASS / exit 0.
        with tempfile.TemporaryDirectory() as tmp:
            config = _write(
                tmp,
                "single.mcp.json",
                {"mcpServers": {"remote": {"url": "http://insecure.example.com/x"}}},
            )
            policy = _write(
                tmp,
                "policy.json",
                {
                    "version": 1,
                    "fail_on": "HIGH",
                    "rules": {"MCPSEC007": {"enabled": False, "severity": "HIGH"}},
                },
            )
            code, stdout, _ = _run(["check", config, "--policy", policy])
            self.assertEqual(code, 0)
            self.assertTrue(stdout.startswith("PASS"), stdout)

            jcode, jout, _ = _run(["check", config, "--policy", policy, "--json"])
            self.assertEqual(jcode, 0)
            report = json.loads(jout)
            self.assertEqual(report["pass"], True)
            self.assertEqual(report["counts"]["blocking"], 0)
            # Disabled rules are fully dropped from check results.
            ids = {f["rule_id"] for f in report["findings"]}
            self.assertNotIn("MCPSEC007", ids)
            self.assertEqual(report["blocking_findings"], [])
            self.assertEqual(report["counts"]["total"], 0)


class CheckFailOnTest(unittest.TestCase):
    """A lower ``fail_on`` makes more findings block."""

    def test_fail_on_low_blocks_more(self):
        # (e)
        default_code, default_out, _ = _run(["check", _INSECURE, "--json"])
        default_blocking = json.loads(default_out)["counts"]["blocking"]

        with tempfile.TemporaryDirectory() as tmp:
            policy = _write(tmp, "low.json", {"version": 1, "fail_on": "LOW"})
            code, stdout, _ = _run(["check", _INSECURE, "--policy", policy, "--json"])
            self.assertEqual(code, 1)
            low_blocking = json.loads(stdout)["counts"]["blocking"]

        self.assertGreater(low_blocking, default_blocking)


class CheckSeverityOverrideTest(unittest.TestCase):
    """Per-rule severity overrides change the effective severity used."""

    def test_override_lowers_and_raises(self):
        # (f) Lower a HIGH rule (MCPSEC005) to LOW -> no longer blocking.
        #     Raise a MEDIUM rule (MCPSEC003) to HIGH -> becomes blocking.
        with tempfile.TemporaryDirectory() as tmp:
            policy = _write(
                tmp,
                "override.json",
                {
                    "version": 1,
                    "fail_on": "HIGH",
                    "rules": {
                        "MCPSEC005": {"enabled": True, "severity": "LOW"},
                        "MCPSEC003": {"enabled": True, "severity": "HIGH"},
                    },
                },
            )
            code, stdout, _ = _run(["check", _INSECURE, "--policy", policy, "--json"])
            self.assertEqual(code, 1)
            report = json.loads(stdout)
            blocking_ids = {f["rule_id"] for f in report["blocking_findings"]}
            self.assertNotIn("MCPSEC005", blocking_ids)
            self.assertIn("MCPSEC003", blocking_ids)

            # Effective severities are reflected in the findings list.
            by_id = {f["rule_id"]: f for f in report["findings"]}
            self.assertEqual(by_id["MCPSEC005"]["severity"], "LOW")
            self.assertEqual(by_id["MCPSEC003"]["severity"], "HIGH")


class CheckPolicyErrorTest(unittest.TestCase):
    """Bad ``--policy`` input is an invalid-usage error (exit 2)."""

    def test_missing_policy_file(self):
        # (g)
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.json")
            code, _, stderr = _run(["check", _INSECURE, "--policy", missing])
            self.assertEqual(code, 2)
            self.assertIn("error:", stderr)

    def test_malformed_policy_json(self):
        # (h)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{ this is not valid json")
            code, _, stderr = _run(["check", _INSECURE, "--policy", path])
            self.assertEqual(code, 2)
            self.assertIn("error:", stderr)

    def test_unknown_fail_on_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = _write(tmp, "bad-failon.json", {"fail_on": "BANANA"})
            code, _, stderr = _run(["check", _INSECURE, "--policy", policy])
            self.assertEqual(code, 2)
            self.assertIn("error:", stderr)

    def test_unknown_rule_severity_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = _write(
                tmp,
                "bad-rule-severity.json",
                {"rules": {"MCPSEC004": {"enabled": True, "severity": "HGIH"}}},
            )
            code, _, stderr = _run(["check", _INSECURE, "--policy", policy])
            self.assertEqual(code, 2)
            self.assertIn("unknown severity", stderr)

    def test_non_boolean_rule_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = _write(
                tmp,
                "bad-enabled.json",
                {"rules": {"MCPSEC007": {"enabled": "false", "severity": "HIGH"}}},
            )
            code, _, stderr = _run(["check", _INSECURE, "--policy", policy])
            self.assertEqual(code, 2)
            self.assertIn("enabled must be boolean", stderr)

    def test_missing_target_path_is_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "missing.mcp.json")
            code, _, stderr = _run(["check", missing])
            self.assertEqual(code, 2)
            self.assertIn("error:", stderr)


class CheckNoSecretLeakTest(unittest.TestCase):
    """``check`` output never echoes a secret value from a config."""

    def test_secret_value_absent_from_output(self):
        # (i)
        secret = "sk-abcdefghijklmnopqrstuvwxyz0123"
        with tempfile.TemporaryDirectory() as tmp:
            config = _write(
                tmp,
                "leaky.mcp.json",
                {"mcpServers": {"leaky": {"command": "foo", "env": {"CONFIG": secret}}}},
            )
            code, stdout, stderr = _run(["check", config, "--json"])
            # The inline-secret rule fires (HIGH) -> blocking -> exit 1.
            self.assertEqual(code, 1)
            report = json.loads(stdout)
            ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("MCPSEC001", ids)
            # The raw secret never appears in stdout or stderr.
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, stderr)

    def test_secret_arg_absent_from_finding_messages(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz0123"
        with tempfile.TemporaryDirectory() as tmp:
            config = _write(
                tmp,
                "leaky-arg.mcp.json",
                {"mcpServers": {"leaky": {"command": "npx", "args": [secret]}}},
            )
            policy = _write(tmp, "medium.json", {"version": 1, "fail_on": "MEDIUM"})
            code, stdout, stderr = _run(["check", config, "--policy", policy, "--json"])
            self.assertEqual(code, 1)
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, stderr)
            report = json.loads(stdout)
            messages = "\n".join(f["message"] for f in report["findings"])
            self.assertIn("<redacted>", messages)

            hcode, hout, herr = _run(["check", config, "--policy", policy])
            self.assertEqual(hcode, 1)
            self.assertNotIn(secret, hout)
            self.assertNotIn(secret, herr)


if __name__ == "__main__":
    unittest.main()
