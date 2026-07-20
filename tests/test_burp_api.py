import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "auto-scanner" / "burp-integration"))

import burp_api


class BurpScopeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.programs = Path(self.tempdir.name)
        (self.programs / "program.md").write_text(
            "# Program\n\n## In Scope\n- example.com\n\n## Out of Scope\n- blocked.example.com\n",
            encoding="utf-8",
        )
        self.original_programs = burp_api.PROGRAMS_DIR
        burp_api.PROGRAMS_DIR = self.programs
        self.api = burp_api.BurpAPI()
        self.requests = []
        self.api.post = lambda path, data: self.requests.append((path, data)) or {"ok": True}

    def tearDown(self):
        burp_api.PROGRAMS_DIR = self.original_programs
        self.tempdir.cleanup()

    def test_target_url_is_parsed_before_sending_to_burp(self):
        self.api.add_to_target("https://example.com:8443/path")
        payload = self.requests[0][1]
        self.assertEqual(payload["host"], "example.com")
        self.assertEqual(payload["protocol"], "https")
        self.assertEqual(payload["port"], 8443)

    def test_active_scan_rejects_unauthorized_target(self):
        with self.assertRaises(burp_api.ScopeError):
            self.api.start_scan(["https://unauthorized.example"])
        self.assertEqual(self.requests, [])

    def test_intruder_rejects_unauthorized_target(self):
        with self.assertRaises(burp_api.ScopeError):
            self.api.send_to_intruder({"url": "https://unauthorized.example"})
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
