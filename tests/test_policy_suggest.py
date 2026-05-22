"""Tests for the ``policy suggest`` command (Stage 1: contract only).

These pin the contract for ``mcpsec policy suggest [path]``, which reuses the
``review`` machinery (risk level + APPROVE/REVIEW/DENY recommendation + secret
redaction) to emit a conservative starting *policy* JSON document.

They drive the CLI via :func:`mcpsec.cli.main`, mirroring ``test_review.py``.
In Stage 1 the feature is unimplemented, so ``suggest`` is not yet a valid
``policy`` action; argparse rejects it with ``SystemExit``. The ``_run`` helper
below catches that so the assertions fail cleanly (red) instead of aborting.
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

# The three keys the policy document's "defaults" block must carry.
_DEFAULT_KEYS = {"unknown_servers", "dangerous_findings", "high_risk_findings"}

# Server names from examples/insecure.mcp.json that are HIGH risk (review's
# recommendation is DENY for each): shell exec, plaintext remote, fs-root.
_HIGH_SERVERS = ("shell-runner", "insecure-remote", "filesystem-root")


def _run(argv):
    """Run cli.main(argv), returning (exit_code, stdout, stderr).

    Robust to argparse's ``SystemExit``: in Stage 1 ``suggest`` is not a valid
    subcommand, so without this guard the run would abort the test instead of
    failing cleanly.
    """
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    return code, out.getvalue(), err.getvalue()


def _write(tmp, name, obj):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle)
    return path


class PolicySuggestJsonShapeTest(unittest.TestCase):
    """The emitted policy document matches the documented shape."""

    def test_clean_servers_are_allowed_with_no_denied_permissions(self):
        code, stdout, stderr = _run(["policy", "suggest", _CLEAN, "--json"])
        self.assertEqual(code, 0, stderr)
        policy = json.loads(stdout)

        self.assertEqual(policy["version"], 1)
        self.assertEqual(policy["generated_by"], "mcpsec policy suggest")
        self.assertTrue(policy["source"]["paths"])
        self.assertEqual(set(policy["defaults"]), _DEFAULT_KEYS)
        self.assertEqual(
            policy["defaults"],
            {
                "unknown_servers": "review",
                "dangerous_findings": "deny",
                "high_risk_findings": "deny",
            },
        )

        servers = policy["servers"]
        self.assertIsInstance(servers, dict)
        # Both clean example servers: APPROVE -> allow, nothing denied.
        for name in ("pinned-tool", "scoped-filesystem"):
            self.assertIn(name, servers)
            self.assertEqual(servers[name]["decision"], "allow")
            self.assertEqual(servers[name]["denied_permissions"], [])

    def test_high_risk_servers_are_denied_with_reasons_and_denied_permissions(self):
        code, stdout, stderr = _run(["policy", "suggest", _INSECURE, "--json"])
        self.assertEqual(code, 0, stderr)
        policy = json.loads(stdout)
        servers = policy["servers"]
        self.assertIsInstance(servers, dict)

        for name in _HIGH_SERVERS:
            self.assertIn(name, servers)
            entry = servers[name]
            self.assertEqual(entry["decision"], "deny", name)
            self.assertEqual(entry["risk"], "HIGH", name)
            self.assertTrue(entry["reasons"], name)
            self.assertTrue(entry["denied_permissions"], name)

        # No HIGH-risk server is ever 'allow'.
        for name in _HIGH_SERVERS:
            self.assertNotEqual(servers[name]["decision"], "allow", name)


class PolicySuggestOutputFormsTest(unittest.TestCase):
    """Default, --json, and --format json print the SAME policy document."""

    def test_default_and_flagged_forms_match(self):
        code_default, default_out, err_default = _run(["policy", "suggest", _CLEAN])
        code_json, json_out, err_json = _run(["policy", "suggest", _CLEAN, "--json"])
        code_fmt, fmt_out, err_fmt = _run(
            ["policy", "suggest", _CLEAN, "--format", "json"]
        )

        self.assertEqual(code_default, 0, err_default)
        self.assertEqual(code_json, 0, err_json)
        self.assertEqual(code_fmt, 0, err_fmt)

        default_doc = json.loads(default_out)
        json_doc = json.loads(json_out)
        fmt_doc = json.loads(fmt_out)
        self.assertEqual(default_doc, json_doc)
        self.assertEqual(default_doc, fmt_doc)


class PolicySuggestFileOutputTest(unittest.TestCase):
    """``--output`` writes the document to a file and prints only a confirmation."""

    def test_output_writes_file_and_prints_short_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mcpsec.policy.json")
            code, stdout, stderr = _run(
                ["policy", "suggest", _CLEAN, "--output", path]
            )
            self.assertEqual(code, 0, stderr)

            # Stdout is the short, safe confirmation -- not the full document.
            self.assertIn("wrote {0}".format(path), stdout)
            self.assertNotIn('"generated_by"', stdout)
            self.assertNotIn('"servers"', stdout)

            self.assertTrue(os.path.isfile(path))
            with open(path, "r", encoding="utf-8") as handle:
                policy = json.load(handle)
            self.assertEqual(policy["version"], 1)
            self.assertEqual(policy["generated_by"], "mcpsec policy suggest")
            self.assertEqual(set(policy["defaults"]), _DEFAULT_KEYS)
            self.assertIsInstance(policy["servers"], dict)


class PolicySuggestSecretRedactionTest(unittest.TestCase):
    """Secrets in args/env/URLs never reach stdout, stderr, or the output file."""

    def test_secrets_are_never_emitted(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz0123"
        url_secret = "URL_SECRET_VALUE_12345"
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
                        },
                        "remote": {
                            "url": (
                                "https://user:"
                                + url_secret
                                + "@api.example.com/mcp?api_"
                                + "key="
                                + url_secret
                                + "&safe=ok#"
                                + url_secret
                            )
                        },
                    }
                },
            )

            # JSON to stdout.
            code, stdout, stderr = _run(["policy", "suggest", config, "--json"])
            self.assertEqual(code, 0, stderr)
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, stderr)
            self.assertNotIn(url_secret, stdout)
            self.assertNotIn(url_secret, stderr)

            # Written file.
            out_path = os.path.join(tmp, "suggested.policy.json")
            code, stdout, stderr = _run(
                ["policy", "suggest", config, "--output", out_path]
            )
            self.assertEqual(code, 0, stderr)
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, stderr)
            self.assertNotIn(url_secret, stdout)
            self.assertNotIn(url_secret, stderr)

            self.assertTrue(os.path.isfile(out_path))
            with open(out_path, "r", encoding="utf-8") as handle:
                file_contents = handle.read()
            self.assertNotIn(secret, file_contents)
            self.assertNotIn(url_secret, file_contents)

    def test_secret_marker_tokens_are_redacted_from_policy_notes(self):
        marker_secret = "URL_SECRET_VALUE_12345"
        with tempfile.TemporaryDirectory() as tmp:
            config = _write(
                tmp,
                "marker.mcp.json",
                {"mcpServers": {"leaky": {"command": "npx", "args": [marker_secret]}}},
            )
            code, stdout, stderr = _run(["policy", "suggest", config, "--json"])
            self.assertEqual(code, 0, stderr)
            self.assertNotIn(marker_secret, stdout)
            policy = json.loads(stdout)
            notes = "\n".join(policy["servers"]["leaky"]["notes"])
            self.assertIn("<redacted>", notes)


class PolicySuggestErrorTest(unittest.TestCase):
    """A non-existent path is reported the same way as scan/check/review."""

    def test_missing_path_is_an_error(self):
        code, _stdout, stderr = _run(["policy", "suggest", "/no/such/path"])
        self.assertEqual(code, 1)
        self.assertIn("error: no such path:", stderr)


class PolicySuggestAsCheckPolicyTest(unittest.TestCase):
    """A suggested policy is directly consumable by ``mcpsec check --policy``."""

    def test_suggested_policy_makes_review_servers_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = _write(
                tmp,
                "sampling.mcp.json",
                {"mcpServers": {"sampler": {"command": "tool", "sampling": True}}},
            )
            policy_path = os.path.join(tmp, "mcpsec.policy.json")
            code, _stdout, stderr = _run(
                ["policy", "suggest", config, "--output", policy_path]
            )
            self.assertEqual(code, 0, stderr)

            check_code, check_stdout, check_stderr = _run(
                ["check", config, "--policy", policy_path, "--json"]
            )
            self.assertEqual(check_code, 1, check_stderr)
            report = json.loads(check_stdout)
            self.assertEqual(report["counts"]["blocking"], 1)
            self.assertEqual(report["blocking_findings"][0]["server"], "sampler")


class PolicySuggestDuplicateNameTest(unittest.TestCase):
    """Duplicate server keys are disambiguated without overwriting real names."""

    def test_duplicate_server_name_keys_do_not_overwrite_real_hash_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = _write(
                tmp,
                "first.mcp.json",
                {"mcpServers": {"dup": {"command": "tool"}, "dup#2": {"command": "tool"}}},
            )
            second = _write(
                tmp,
                "second.mcp.json",
                {"mcpServers": {"dup": {"command": "tool"}}},
            )
            code, stdout, stderr = _run(["policy", "suggest", tmp, "--json"])
            self.assertEqual(code, 0, stderr)
            policy = json.loads(stdout)
            servers = policy["servers"]
            self.assertIn("dup", servers)
            self.assertIn("dup#2", servers)
            self.assertIn("dup#3", servers)
            self.assertEqual(servers["dup#2"]["name"], "dup#2")
            self.assertEqual(servers["dup#3"]["name"], "dup")
            self.assertEqual(len(servers), 3)
            self.assertTrue(first)
            self.assertTrue(second)
    def test_check_policy_uses_source_file_identity_for_duplicate_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write(tmp, "first.mcp.json", {"mcpServers": {"dup": {"command": "tool"}}})
            _write(
                tmp,
                "second.mcp.json",
                {"mcpServers": {"dup": {"command": "tool", "sampling": True}}},
            )
            policy_path = os.path.join(tmp, "mcpsec.policy.json")
            code, _stdout, stderr = _run(["policy", "suggest", tmp, "--output", policy_path])
            self.assertEqual(code, 0, stderr)

            check_code, check_stdout, check_stderr = _run(
                ["check", tmp, "--policy", policy_path, "--json"]
            )
            self.assertEqual(check_code, 1, check_stderr)
            report = json.loads(check_stdout)
            self.assertEqual(report["counts"]["blocking"], 1)
            self.assertEqual(report["blocking_findings"][0]["server"], "dup")
            self.assertIn("second.mcp.json", report["blocking_findings"][0]["location"])


if __name__ == "__main__":
    unittest.main()
