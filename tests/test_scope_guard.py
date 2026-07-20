import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from scope_guard import ScopeError, authorize, normalize_target


class ScopeGuardTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.programs = Path(self.tempdir.name)
        (self.programs / "alpha.md").write_text(
            """# Alpha

## In Scope
- example.com
- *.example.org
- 192.0.2.0/24

## Out of Scope
- admin.example.org
""",
            encoding="utf-8",
        )
        (self.programs / "beta.md").write_text(
            """# Beta

## In Scope
- admin.example.org

## Out of Scope
- blocked.example.com
""",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def test_exact_host_and_url_are_authorized(self):
        self.assertEqual(authorize("https://example.com/path", self.programs)[0], "example.com")

    def test_substring_is_not_authorized(self):
        with self.assertRaises(ScopeError):
            authorize("not-example.com", self.programs)

    def test_wildcard_and_cidr_are_supported(self):
        self.assertEqual(authorize("api.example.org", self.programs)[0], "api.example.org")
        self.assertEqual(authorize("192.0.2.42", self.programs)[0], "192.0.2.42")

    def test_global_out_of_scope_wins(self):
        with self.assertRaises(ScopeError):
            authorize("admin.example.org", self.programs)
        with self.assertRaises(ScopeError):
            authorize("blocked.example.com", self.programs)

    def test_traversal_and_credentials_are_rejected(self):
        for target in ("../example.com", "https://user:pass@example.com"):
            with self.subTest(target=target), self.assertRaises(ScopeError):
                normalize_target(target)

    def test_force_environment_does_not_bypass_cli(self):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "scope_guard.py"),
                "unauthorized.example",
                "--programs-dir",
                str(self.programs),
            ],
            env={**os.environ, "FORCE": "1"},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_out_of_scope_entry_blocks_authorization(self):
        (self.programs / "broken.md").write_text(
            "# Broken\n\n## Out of Scope\n- https://example.net/admin\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ScopeError, "invalid scope entry"):
            authorize("example.com", self.programs)


if __name__ == "__main__":
    unittest.main()
