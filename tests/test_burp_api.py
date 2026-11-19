import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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

    def test_reads_api_key_from_env_and_passes_timeout_to_urlopen(self):
        with mock.patch.dict(os.environ, {"BURP_API_KEY": "env-secret-key", "BURP_PORT": "1338"}):
            api = burp_api.BurpAPI(timeout=12)
        self.assertEqual(api.api_key, "env-secret-key")
        self.assertEqual(api.headers.get("Burp-API-Key"), "env-secret-key")
        self.assertEqual(api.base_url, "http://localhost:1338")

        captured = {}

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"ok": true}'

        def fake_urlopen(req, **kwargs):
            captured["kwargs"] = kwargs
            return FakeResp()

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res = api.status()
        self.assertEqual(res, {"ok": True})
        self.assertEqual(captured["kwargs"].get("timeout"), 12)


if __name__ == "__main__":
    unittest.main()
