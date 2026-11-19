import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from scope_guard import (
    ScopeError,
    audit_programs,
    authorize,
    diff_scope_sources,
    explain_target,
    export_scope,
    filter_file,
    normalize_target,
    read_program_policy,
)


class ScopeGuardTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.programs = Path(self.tempdir.name)
        recent = datetime.now(timezone.utc).date().isoformat()
        (self.programs / "alpha.md").write_text(
            f"""# Alpha

| Field | Value |
|-------|-------|
| **Platform** | HackerOne |
| **H1 Handle** | alpha |
| **Status** | Active |
| **Last scope review** | {recent} |

## In Scope
- example.com
- *.example.org
- staging-*.example.net
- 192.0.2.0/24

## Out of Scope
- admin.example.org

## Special Rules
- Rate limit: max 15 requests/second
- Required header: `X-HackerOne-Research: tester`
""",
            encoding="utf-8",
        )
        (self.programs / "beta.md").write_text(
            f"""# Beta

| Field | Value |
|-------|-------|
| **Platform** | Bugcrowd |
| **Status** | Active |
| **Last scope review** | {recent} |

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
        self.assertEqual(authorize("staging-eu.example.net", self.programs)[0], "staging-eu.example.net")
        with self.assertRaises(ScopeError):
            authorize("sub.staging-eu.example.net", self.programs)

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
        for bad_entry in (
            "https://example.net/admin?debug=1",
            "ftp://example.net/files",
            "https://user:pass@example.net",
        ):
            with self.subTest(entry=bad_entry):
                broken = self.programs / "broken.md"
                broken.write_text(
                    f"# Broken\n\n## Out of Scope\n- {bad_entry}\n",
                    encoding="utf-8",
                )
                try:
                    with self.assertRaisesRegex(ScopeError, "invalid scope entry"):
                        authorize("example.com", self.programs)
                finally:
                    broken.unlink(missing_ok=True)

    def test_path_scoped_and_port_scoped_rules(self):
        (self.programs / "granular.md").write_text(
            """# Granular

| Field | Value |
|-------|-------|
| **Status** | Active |

## In Scope
- https://portal.scoped.example/admin
- https://api.scoped.example/v2/*
- svc.scoped.example:8443

## Out of Scope
- https://api.scoped.example/v2/logout*
- blocked.scoped.example:9000
""",
            encoding="utf-8",
        )
        self.assertEqual(authorize("https://portal.scoped.example/admin", self.programs)[0], "portal.scoped.example")
        self.assertEqual(authorize("https://portal.scoped.example/admin/users", self.programs)[0], "portal.scoped.example")
        with self.assertRaises(ScopeError):
            authorize("https://portal.scoped.example/administrator", self.programs)
        with self.assertRaises(ScopeError):
            authorize("portal.scoped.example", self.programs)

        self.assertEqual(authorize("https://api.scoped.example/v2/orders", self.programs)[0], "api.scoped.example")
        with self.assertRaises(ScopeError):
            authorize("https://api.scoped.example/v20/orders", self.programs)
        with self.assertRaises(ScopeError):
            authorize("https://api.scoped.example/v2/logout", self.programs)
        with self.assertRaises(ScopeError):
            authorize("https://api.scoped.example/v2/logout-all", self.programs)

        self.assertEqual(authorize("https://svc.scoped.example:8443/health", self.programs)[0], "svc.scoped.example")
        self.assertEqual(authorize("svc.scoped.example:8443", self.programs)[0], "svc.scoped.example")
        with self.assertRaises(ScopeError):
            authorize("https://svc.scoped.example/health", self.programs)
        with self.assertRaises(ScopeError):
            authorize("svc.scoped.example", self.programs)

    def test_paused_and_retired_programs_block_in_scope_but_keep_exclusions(self):
        (self.programs / "paused.md").write_text(
            """# PausedProg

| Field | Value |
|-------|-------|
| **Status** | Paused (maintenance) |

## In Scope
- paused-only.example

## Out of Scope
- legacy-excluded.example.org
""",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ScopeError, "non-active program"):
            authorize("paused-only.example", self.programs)
        with self.assertRaisesRegex(ScopeError, "explicitly out of scope"):
            authorize("legacy-excluded.example.org", self.programs)

    def test_stale_scope_emits_warning_and_policy_metadata_extracted(self):
        old_date = (datetime.now(timezone.utc).date() - timedelta(days=45)).isoformat()
        stale_file = self.programs / "stale.md"
        stale_file.write_text(
            f"""# StaleProg

| Field | Value |
|-------|-------|
| **Platform** | Intigriti |
| **Program Handle** | stale-prog |
| **Status** | Active |
| **Last scope review** | {old_date} |

## In Scope
- stale.example

## Special Rules
- Rate limit: automated scanners capped at **5 requests / sec**.
- Use `X-Security-Testing: dev101x` on every request.
""",
            encoding="utf-8",
        )
        policy = read_program_policy(stale_file)
        self.assertEqual(policy.rate_limit, 5)
        self.assertEqual(policy.research_headers, ["X-Security-Testing: dev101x"])
        self.assertTrue(policy.active)

        err_buf = io.StringIO()
        with mock.patch.dict(os.environ, {"BB_SCOPE_MAX_AGE_DAYS": "30"}), redirect_stderr(err_buf):
            host, _ = authorize("stale.example", self.programs)
        self.assertEqual(host, "stale.example")
        self.assertIn("last reviewed", err_buf.getvalue())

    def test_explain_policy_json_and_audit_conflict(self):
        verdict = explain_target("api.example.org", self.programs)
        self.assertTrue(verdict["authorized"])
        self.assertEqual(verdict["rate_limit"], 15)
        self.assertEqual(verdict["research_header"], "X-HackerOne-Research: tester")

        denied = explain_target("admin.example.org", self.programs)
        self.assertFalse(denied["authorized"])

        audit = audit_programs(self.programs)
        self.assertEqual(audit["parse_errors"], 0)
        self.assertGreaterEqual(audit["conflicts_found"], 1)
        beta_entry = next(p for p in audit["programs"] if p["file"] == "beta.md")
        self.assertTrue(any("admin.example.org" in c for c in beta_entry["conflicts"]))

        cli_pol = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "scope_guard.py"),
                "--programs-dir",
                str(self.programs),
                "--policy-json",
                "api.example.org",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        pol_data = json.loads(cli_pol.stdout)
        self.assertEqual(pol_data["rate_limit"], 15)
        self.assertEqual(pol_data["research_header"], "X-HackerOne-Research: tester")

    def test_export_burp_json_wildcards_cidrs(self):
        burp_json = json.loads(export_scope(self.programs, "burp", program_filter="alpha"))
        scope_obj = burp_json["target"]["scope"]
        self.assertTrue(scope_obj["advanced_mode"])
        hosts = [item["host"] for item in scope_obj["include"]]
        self.assertTrue(any(r"192\.0\.2\." in h for h in hosts))
        self.assertTrue(any("staging-[a-z0-9-]*" in h for h in hosts))
        exc_hosts = [item["host"] for item in scope_obj["exclude"]]
        self.assertTrue(any("blocked" in h for h in exc_hosts))

        self.assertEqual(
            export_scope(self.programs, "wildcards", program_filter="alpha").splitlines(),
            ["*.example.org", "staging-*.example.net"],
        )
        self.assertEqual(
            export_scope(self.programs, "cidrs", program_filter="alpha").splitlines(),
            ["192.0.2.0/24"],
        )

    def test_import_h1_csv_json_and_diff(self):
        work = Path(self.tempdir.name)
        csv_path = work / "h1.csv"
        csv_path.write_text(
            "identifier,asset_type,eligible_for_submission,eligible_for_bounty,instruction\n"
            "*.acme.example,WILDCARD,true,true,Main domain\n"
            "com.acme.android,GOOGLE_PLAY_APP_ID,true,true,Android APK\n"
            "out.acme.example,URL,false,false,Excluded host\n",
            encoding="utf-8",
        )
        md_out = work / "imported-csv.md"
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "scope_guard.py"),
                "--import-h1-csv",
                str(csv_path),
                "--program-name",
                "acme",
                "--output",
                str(md_out),
            ],
            check=True,
        )
        pol = read_program_policy(md_out)
        self.assertEqual(pol.in_scope, ["*.acme.example"])
        self.assertEqual(pol.out_scope, ["out.acme.example"])
        self.assertIn("GOOGLE_PLAY_APP_ID", md_out.read_text(encoding="utf-8"))

        json_path = work / "bt.json"
        json_path.write_text(
            json.dumps(
                {
                    "name": "Acme",
                    "handle": "acme",
                    "targets": {
                        "in_scope": [
                            {"asset_identifier": "*.acme.example", "asset_type": "WILDCARD"},
                            {"asset_identifier": "new.acme.example", "asset_type": "URL"},
                        ],
                        "out_of_scope": [{"asset_identifier": "out.acme.example", "asset_type": "URL"}],
                    },
                }
            ),
            encoding="utf-8",
        )
        diff = diff_scope_sources(md_out, json_path)
        self.assertEqual(diff["in_scope_added"], ["new.acme.example"])
        self.assertEqual(diff["in_scope_removed"], [])

    def test_batch_filter_file_partitions_and_dedups_candidates(self):
        inp = self.programs / "input.txt"
        auth = self.programs / "auth.txt"
        disc = self.programs / "disc.txt"
        cand = self.programs / "candidates-pending-scope.txt"
        cand.write_text("existing.unlisted.example\n", encoding="utf-8")
        inp.write_text(
            "\n".join(
                [
                    "https://example.com/a",
                    "api.example.org",
                    "admin.example.org",
                    "not-example.com",
                    "not-example.com",
                    "",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        filter_file(inp, self.programs, auth, disc, cand)
        self.assertEqual(auth.read_text(encoding="utf-8").splitlines(), ["https://example.com/a", "api.example.org"])
        self.assertEqual(
            disc.read_text(encoding="utf-8").splitlines(),
            ["admin.example.org", "not-example.com", "not-example.com"],
        )
        self.assertEqual(
            cand.read_text(encoding="utf-8").splitlines(),
            ["admin.example.org", "existing.unlisted.example", "not-example.com"],
        )

    def test_batch_filter_file_missing_input_creates_empty_outputs(self):
        auth = self.programs / "auth.txt"
        disc = self.programs / "disc.txt"
        filter_file(self.programs / "missing.txt", self.programs, auth, disc)
        self.assertEqual(auth.read_text(encoding="utf-8"), "")
        self.assertEqual(disc.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
