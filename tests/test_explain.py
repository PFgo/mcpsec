"""Tests for the ``explain`` subcommand.

These drive the CLI end-to-end against ``examples/sample.mcp.json`` by calling
:func:`mcpsec.cli.main` and capturing stdout/stderr, mirroring the style of
``test_report.py``.
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


class ExplainFoundServerTest(unittest.TestCase):
    """A matching server prints its name plus at least one finding."""

    def test_prints_name_and_findings(self):
        code, stdout, _ = _run(["explain", "github", _SAMPLE])
        self.assertEqual(code, 0)
        self.assertIn("github", stdout)
        # The github server holds a secret-named env var (MCPSEC001).
        self.assertIn("MCPSEC001", stdout)
        self.assertNotIn("No findings for this server.", stdout)


class ExplainUnknownServerTest(unittest.TestCase):
    """An unknown server name is an error (exit 1)."""

    def test_returns_1(self):
        code, _, stderr = _run(["explain", "does-not-exist", _SAMPLE])
        self.assertEqual(code, 1)
        self.assertIn("no server named does-not-exist found", stderr)


class ExplainMasksSecretValuesTest(unittest.TestCase):
    """Explain shows env/header key names but never their secret values."""

    def test_values_absent_from_stdout(self):
        code, stdout, _ = _run(["explain", "github", _SAMPLE])
        self.assertEqual(code, 0)
        # The key name is shown ...
        self.assertIn("GITHUB_PERSONAL_ACCESS_TOKEN", stdout)
        # ... but the secret value from the sample config is not.
        self.assertNotIn("ghp_example_placeholder_token", stdout)


class ExplainMasksSecretArgTest(unittest.TestCase):
    """A secret passed as a CLI arg (e.g. ``--token X``) is never printed."""

    def test_secret_arg_absent_from_stdout(self):
        secret = "ghp_realSecret123abcdef456"
        config = {
            "mcpServers": {
                "leaky": {
                    "command": "some-server",
                    "args": ["--token", secret],
                }
            }
        }
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as handle:
            json.dump(config, handle)
            path = handle.name
        try:
            code, stdout, _ = _run(["explain", "leaky", path])
            self.assertEqual(code, 0)
            # The secret value never reaches stdout ...
            self.assertNotIn(secret, stdout)
            # ... while the flag name and the redaction marker do.
            self.assertIn("--token", stdout)
            self.assertIn("<redacted>", stdout)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
