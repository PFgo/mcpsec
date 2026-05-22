"""Tests for mcpsec.discovery.

These point discovery at a sandboxed home/cwd via tempfile so they never
touch the real machine's config locations.
"""

import os
import tempfile
import unittest

from mcpsec.discovery import discover_existing, default_config_candidates


class DiscoverExistingTest(unittest.TestCase):
    def test_returns_only_existing_files_including_cwd_mcp_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            mcp_json = os.path.join(tmp, "mcp.json")
            with open(mcp_json, "w", encoding="utf-8") as handle:
                handle.write('{"mcpServers": {}}')

            found = discover_existing(
                home=tmp,
                env={"HOME": tmp},
                cwd=tmp,
            )

            # The cwd-relative ./mcp.json should resolve under tmp and be found.
            self.assertIn(os.path.join(tmp, "mcp.json"), found)
            # Only existing files are returned; the home-anchored candidates
            # were never created, so nothing outside tmp leaks in.
            self.assertEqual(found, [os.path.join(tmp, "mcp.json")])
            for path in found:
                self.assertTrue(os.path.isfile(path))

    def test_returns_empty_when_nothing_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            found = discover_existing(home=tmp, env={"HOME": tmp}, cwd=tmp)
            self.assertEqual(found, [])


class DefaultConfigCandidatesTest(unittest.TestCase):
    def test_includes_known_application_paths(self):
        candidates = default_config_candidates(home="/fake/home")

        # Claude Desktop (macOS).
        self.assertIn(
            os.path.join(
                "/fake/home",
                "Library",
                "Application Support",
                "Claude",
                "claude_desktop_config.json",
            ),
            candidates,
        )
        # Cursor.
        self.assertIn(
            os.path.join("/fake/home", ".cursor", "mcp.json"),
            candidates,
        )
        # Hermes.
        self.assertIn(
            os.path.join("/fake/home", ".hermes", "mcp.json"),
            candidates,
        )


if __name__ == "__main__":
    unittest.main()
