"""Boundary tests for scripts/dependabot_companion.py; fixtures are synthetic."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dependabot_companion import (
    COMPANION_FILES,
    decide_diff,
    derive_inventory,
    opencode_binary_pin_stale,
    parse_go_mod,
    serialize_inventory,
)


class GoModParsingTests(unittest.TestCase):
    def test_block_and_single_line_requires(self):
        text = """module example.com/esf

go 1.27.3

require (
    google.golang.org/grpc v1.85.0
    go.temporal.io/sdk v1.50.0 // indirect
)

require golang.org/x/net v0.53.0
"""
        modules = parse_go_mod(text)
        self.assertEqual(modules["google.golang.org/grpc"], "1.85.0")
        self.assertEqual(modules["go.temporal.io/sdk"], "1.50.0")
        self.assertEqual(modules["golang.org/x/net"], "0.53.0")


class DecideDiffTests(unittest.TestCase):
    def test_accepts_companion_only_diff_under_cap(self):
        self.assertIsNone(decide_diff({"release/inventory.json"}, 12, 500))

    def test_refuses_non_companion_file(self):
        reason = decide_diff({"go.mod"}, 3, 500)
        self.assertIn("non-companion", reason)

    def test_refuses_over_cap(self):
        reason = decide_diff({"release/inventory.json"}, 501, 500)
        self.assertIn("exceeds cap", reason)

    def test_companion_set_is_exactly_the_four_files(self):
        self.assertEqual(
            COMPANION_FILES,
            {
                "release/inventory.json",
                "internal/releaseinfo/inventory.json",
                "internal/controlplane/web/package-lock.json",
                "agents/opencode/package-lock.json",
            },
        )


class OpenCodePinStaleTests(unittest.TestCase):
    def _inventory(self, version, integrity):
        return {
            "dependencies": {
                "opencode": {
                    "version": version,
                    "linux_amd64_npm_integrity": integrity,
                }
            }
        }

    def test_unchanged_identity_is_not_stale(self):
        inv = self._inventory("2.0.29", "sha512-bin")
        self.assertFalse(opencode_binary_pin_stale(inv, inv))

    def test_version_change_is_stale(self):
        self.assertTrue(
            opencode_binary_pin_stale(
                self._inventory("2.0.29", "sha512-bin"),
                self._inventory("2.0.30", "sha512-bin"),
            )
        )

    def test_binary_integrity_change_is_stale(self):
        self.assertTrue(
            opencode_binary_pin_stale(
                self._inventory("2.0.29", "sha512-old"),
                self._inventory("2.0.29", "sha512-new"),
            )
        )


class DeriveInventoryTests(unittest.TestCase):
    def test_frontend_and_go_versions_rederived(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "release").mkdir(parents=True)
            (root / "internal/controlplane/web").mkdir(parents=True)
            (root / "agents/opencode").mkdir(parents=True)
            inventory = {
                "dependencies": {
                    "frontend": {"vite": "0.0.0"},
                    "grpc": "0.0.0",
                    "temporal": {"go_sdk": "0.0.0", "api": "0.0.0"},
                    "opencode": {
                        "linux_amd64_package": "@opencode/cli-linux-x64-baseline"
                    },
                    "cubesandbox": {},
                    "dspy": "0.0.0",
                }
            }
            (root / "release/inventory.json").write_text(json.dumps(inventory))
            (root / "go.mod").write_text(
                "module example.com/esf\n\nrequire (\n"
                "    google.golang.org/grpc v1.85.0\n"
                "    go.temporal.io/sdk v1.50.0\n"
                "    go.temporal.io/api v1.64.2\n)\n"
            )
            web_lock = {
                "packages": {"node_modules/vite": {"version": "8.3.5"}}
            }
            (root / "internal/controlplane/web/package-lock.json").write_text(
                json.dumps(web_lock)
            )
            agent_lock = {
                "packages": {
                    "node_modules/@opencode/cli": {
                        "version": "2.0.29",
                        "integrity": "sha512-cli",
                    },
                    "node_modules/@opencode/cli-linux-x64-baseline": {
                        "version": "2.0.29",
                        "integrity": "sha512-bin",
                    },
                }
            }
            (root / "agents/opencode/package-lock.json").write_text(
                json.dumps(agent_lock)
            )
            (root / "uv.lock").write_text(
                '[[package]]\nname = "dspy"\nversion = "3.4.1"\n'
            )
            derived = derive_inventory(root)
            deps = derived["dependencies"]
            self.assertEqual(deps["frontend"]["vite"], "8.3.5")
            self.assertEqual(deps["grpc"], "1.85.0")
            self.assertEqual(deps["temporal"]["go_sdk"], "1.50.0")
            self.assertEqual(deps["temporal"]["api"], "1.64.2")
            self.assertEqual(deps["opencode"]["version"], "2.0.29")
            self.assertEqual(deps["opencode"]["npm_integrity"], "sha512-cli")
            self.assertEqual(
                deps["opencode"]["linux_amd64_npm_integrity"], "sha512-bin"
            )
            self.assertEqual(deps["dspy"], "3.4.1")

    def test_serialization_is_byte_stable_for_current_inventory(self):
        repo_root = Path(__file__).resolve().parents[2]
        raw = (repo_root / "release/inventory.json").read_bytes()
        parsed = json.loads(raw)
        self.assertEqual(serialize_inventory(parsed).encode(), raw)


if __name__ == "__main__":
    unittest.main()
