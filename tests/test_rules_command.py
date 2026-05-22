"""Tests for the ``rules`` rule-catalogue command."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from mcpsec import __version__, cli
from mcpsec.rules import RULE_METADATA

# Expected (rule_id, default severity) pairs, sourced from the single
# RULE_METADATA catalogue so this test never re-hardcodes the values.
_EXPECTED = sorted(RULE_METADATA)
_EXPECTED_IDS = [rule_id for rule_id, _severity in _EXPECTED]
_EXPECTED_SEVERITIES = {rule_id: severity for rule_id, severity in _EXPECTED}
# Derive the rule count from the catalogue so adding a rule never requires
# touching the assertions below.
_EXPECTED_COUNT = len(_EXPECTED)


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class RulesHumanTest(unittest.TestCase):
    def test_lists_all_rules_with_ids_and_severities(self):
        code, stdout, stderr = _run(["rules"])
        self.assertEqual(code, 0, stderr)
        # One line per rule that names its id, severity, and a description.
        rule_lines = [
            line for line in stdout.splitlines() if line.startswith("MCPSEC")
        ]
        self.assertEqual(len(rule_lines), _EXPECTED_COUNT)
        listed_ids = []
        for rule_id, line in zip(_EXPECTED_IDS, rule_lines):
            fields = line.split()
            self.assertEqual(fields[0], rule_id)
            self.assertEqual(fields[1], _EXPECTED_SEVERITIES[rule_id])
            # The remainder of the line is a non-empty description.
            self.assertTrue(line.split(fields[1], 1)[1].strip())
            listed_ids.append(fields[0])
        self.assertEqual(listed_ids, _EXPECTED_IDS)

    def test_is_sorted_by_rule_id(self):
        _code, stdout, _err = _run(["rules"])
        rule_ids = [
            line.split()[0]
            for line in stdout.splitlines()
            if line.startswith("MCPSEC")
        ]
        self.assertEqual(rule_ids, sorted(rule_ids))

    def test_trailing_summary_count(self):
        _code, stdout, _err = _run(["rules"])
        self.assertIn(f"Total: {_EXPECTED_COUNT} rules", stdout)


class RulesJsonTest(unittest.TestCase):
    def test_json_has_version_and_rules_keys(self):
        code, stdout, stderr = _run(["rules", "--json"])
        self.assertEqual(code, 0, stderr)
        payload = json.loads(stdout)
        self.assertIn("version", payload)
        self.assertIn("rules", payload)
        self.assertEqual(payload["version"], __version__)

    def test_json_lists_nine_rules_with_correct_severities(self):
        _code, stdout, _err = _run(["rules", "--json"])
        rules = json.loads(stdout)["rules"]
        self.assertEqual(len(rules), _EXPECTED_COUNT)
        for entry in rules:
            self.assertEqual(
                set(entry), {"rule_id", "severity", "description"}
            )
            self.assertEqual(
                entry["severity"], _EXPECTED_SEVERITIES[entry["rule_id"]]
            )
            self.assertTrue(entry["description"])

    def test_json_is_sorted_by_rule_id(self):
        _code, stdout, _err = _run(["rules", "--json"])
        rules = json.loads(stdout)["rules"]
        rule_ids = [entry["rule_id"] for entry in rules]
        self.assertEqual(rule_ids, sorted(rule_ids))
        self.assertEqual(rule_ids, _EXPECTED_IDS)


if __name__ == "__main__":
    unittest.main()
