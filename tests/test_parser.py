"""Tests for mcpsec.parser.normalize.

These build the raw config data as inline Python dicts (they do not read
examples/) and assert that both supported shapes are normalized into
ServerDef objects with the expected field values.
"""

import unittest

from mcpsec.parser import normalize
from mcpsec.models import ServerDef


class NormalizeMcpServersShapeTest(unittest.TestCase):
    """The {"mcpServers": {...}} shape (Claude Desktop / Cursor style)."""

    def test_extracts_stdio_and_remote_servers(self):
        data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {"FS_ALLOW_WRITE": "false"},
                },
                "remote-api": {
                    "url": "https://mcp.example.com/sse",
                    "headers": {"Authorization": "Bearer secret-token"},
                },
            }
        }

        servers = normalize("config.json", data)

        self.assertEqual(len(servers), 2)
        by_name = {s.name: s for s in servers}

        fs = by_name["filesystem"]
        self.assertIsInstance(fs, ServerDef)
        self.assertEqual(fs.source_file, "config.json")
        self.assertEqual(fs.command, "npx")
        self.assertEqual(
            fs.args,
            ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        self.assertIsInstance(fs.args, list)
        self.assertEqual(fs.env, {"FS_ALLOW_WRITE": "false"})
        self.assertIsInstance(fs.env, dict)
        # A stdio server has no remote fields.
        self.assertIsNone(fs.url)
        self.assertEqual(fs.headers, {})

        remote = by_name["remote-api"]
        self.assertEqual(remote.url, "https://mcp.example.com/sse")
        self.assertEqual(remote.headers, {"Authorization": "Bearer secret-token"})
        self.assertIsInstance(remote.headers, dict)
        # A remote server has no stdio fields.
        self.assertIsNone(remote.command)
        self.assertEqual(remote.args, [])


class NormalizeServersShapeTest(unittest.TestCase):
    """The {"servers": {...}} shape."""

    def test_extracts_command_args_env(self):
        data = {
            "servers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_example"},
                }
            }
        }

        servers = normalize("other.json", data)

        self.assertEqual(len(servers), 1)
        gh = servers[0]
        self.assertEqual(gh.name, "github")
        self.assertEqual(gh.source_file, "other.json")
        self.assertEqual(gh.command, "npx")
        self.assertEqual(gh.args, ["-y", "@modelcontextprotocol/server-github"])
        self.assertEqual(gh.env, {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_example"})


class NormalizeBothShapesTest(unittest.TestCase):
    """A single file containing both sections is fully extracted."""

    def test_both_sections_collected(self):
        data = {
            "mcpServers": {
                "alpha": {"command": "node", "args": ["alpha.js"]},
            },
            "servers": {
                "beta": {"url": "https://beta.example.com"},
            },
        }

        servers = normalize("combined.json", data)
        names = sorted(s.name for s in servers)
        self.assertEqual(names, ["alpha", "beta"])

        by_name = {s.name: s for s in servers}
        self.assertEqual(by_name["alpha"].command, "node")
        self.assertEqual(by_name["alpha"].args, ["alpha.js"])
        self.assertEqual(by_name["beta"].url, "https://beta.example.com")


if __name__ == "__main__":
    unittest.main()
