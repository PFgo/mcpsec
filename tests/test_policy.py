"""Tests for the ``policy init`` subcommand.

These drive the CLI by calling :func:`mcpsec.cli.main` and writing into a
temporary directory, mirroring the style of ``test_report.py``.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout


from mcpsec import cli
from mcpsec.rules import RULE_METADATA


def _run(argv):
    """Run cli.main(argv), returning (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class PolicyInitTest(unittest.TestCase):
    """``policy init`` writes a well-formed template and honours --force."""

    def test_writes_valid_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mcpsec.policy.json")
            code, stdout, _ = _run(["policy", "init", "--output", path])
            self.assertEqual(code, 0)
            self.assertIn("wrote {0}".format(path), stdout)
            self.assertTrue(os.path.isfile(path))

            with open(path, "r", encoding="utf-8") as handle:
                policy = json.load(handle)
            self.assertIn("fail_on", policy)
            self.assertIn("version", policy)
            self.assertGreater(len(RULE_METADATA), 0)
            self.assertEqual(len(policy["rules"]), len(RULE_METADATA))
            # Every rule entry carries an enabled flag and a severity.
            for rule_id, body in policy["rules"].items():
                self.assertTrue(rule_id.startswith("MCPSEC00"))
                self.assertIn("enabled", body)
                self.assertIn("severity", body)

    def test_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "mcpsec.policy.json")
            first, _, _ = _run(["policy", "init", "--output", path])
            self.assertEqual(first, 0)

            # A second run without --force is an error (exit 1).
            second, _, stderr = _run(["policy", "init", "--output", path])
            self.assertEqual(second, 1)
            self.assertIn("use --force to overwrite", stderr)

            # With --force it overwrites and succeeds.
            third, _, _ = _run(["policy", "init", "--output", path, "--force"])
            self.assertEqual(third, 0)


if __name__ == "__main__":
    unittest.main()
