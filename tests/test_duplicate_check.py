import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import duplicate_check  # noqa: E402


class DuplicateCheckTests(unittest.TestCase):
    def test_tokenize_removes_stopwords(self):
        self.assertEqual(duplicate_check.tokenize("IDOR on the /api/booking endpoint"), {"idor", "/api/booking", "endpoint"})

    def test_parse_submitted_reports_skips_header_and_separator(self):
        md = """# Program

## In Scope
- example.com

## Submitted Reports
| Date | Title | Severity | Status | H1 URL |
|------|-------|----------|--------|--------|
| 2026-10-01 | IDOR on /api/booking | High | Triaged | https://hackerone.com/reports/1 |
| 2026-10-02 | SSRF in webhook | Medium | New | |

## Notes
- unrelated
"""
        rows = list(duplicate_check.parse_submitted_reports(md))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["title"], "IDOR on /api/booking")
        self.assertEqual(rows[1]["severity"], "Medium")

    def test_cli_detects_matching_report_and_filters_by_program(self):
        with tempfile.TemporaryDirectory() as tmp:
            prog_dir = Path(tmp)
            (prog_dir / "alpha.md").write_text(
                "## Submitted Reports\n| Date | Title |\n|---|---|\n| 2026-10-01 | IDOR on /api/booking |\n",
                encoding="utf-8",
            )
            (prog_dir / "beta.md").write_text(
                "## Submitted Reports\n| Date | Title |\n|---|---|\n| 2026-10-02 | Reflected XSS on search |\n",
                encoding="utf-8",
            )
            original_dir = duplicate_check.PROGRAMS_DIR
            duplicate_check.PROGRAMS_DIR = prog_dir
            try:
                files = duplicate_check.program_files("alpha")
                self.assertEqual([f.name for f in files], ["alpha.md"])
            finally:
                duplicate_check.PROGRAMS_DIR = original_dir

            res = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "duplicate_check.py"), "booking idor"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res.returncode, 0)
            self.assertIn("hackerone.com/hacktivity", res.stdout)

            bad = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "duplicate_check.py"), "the of and"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main()
