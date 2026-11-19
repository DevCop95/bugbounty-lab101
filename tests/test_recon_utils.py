import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from recon_utils import (
    build_report,
    clean_and_bucket_urls,
    diff_baseline,
    parse_httpx_outputs,
)


class ReconUtilsTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.work = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_parse_httpx_json_and_takeover_and_fallback(self):
        hjson = self.work / "httpx.json"
        hjson.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "url": "https://app.example.com",
                            "status_code": 200,
                            "tech": ["Next.js", "Cloudflare"],
                            "cname": "app.edge.example.net",
                        }
                    ),
                    json.dumps(
                        {
                            "url": "https://old.example.com",
                            "status-code": 404,
                            "technologies": ["GitHub Pages"],
                            "cname": ["old-org.github.io."],
                        }
                    ),
                    "{broken json",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        live = self.work / "live.txt"
        tech = self.work / "tech.txt"
        takeover = self.work / "takeover.txt"
        cnt_live, cnt_tech, cnt_to = parse_httpx_outputs(hjson, live, tech, takeover)
        self.assertEqual((cnt_live, cnt_tech, cnt_to), (2, 3, 1))
        self.assertEqual(live.read_text(encoding="utf-8").splitlines(), ["https://app.example.com", "https://old.example.com"])
        self.assertEqual(tech.read_text(encoding="utf-8").splitlines(), ["Cloudflare", "GitHub Pages", "Next.js"])
        self.assertEqual(
            takeover.read_text(encoding="utf-8").splitlines(),
            ["https://old.example.com\t404\told-org.github.io"],
        )

        # Fallback to httpx.txt when httpx.json is absent
        htxt = self.work / "httpx.txt"
        htxt.write_text("https://fallback.example.com [200]\n", encoding="utf-8")
        parse_httpx_outputs(self.work / "missing.json", live, tech, takeover, httpx_txt=htxt)
        self.assertEqual(live.read_text(encoding="utf-8").splitlines(), ["https://fallback.example.com"])

    def test_clean_and_bucket_urls_strips_noise_and_dedups(self):
        src1 = self.work / "wayback.txt"
        src2 = self.work / "js.txt"
        src1.write_text(
            "\n".join(
                [
                    "https://example.com/static/logo.png",
                    "https://example.com/styles/app.css?v=1",
                    "https://example.com/js/app.js",
                    "https://example.com/search?q=alpha&page=1",
                    "https://example.com/search?page=2&q=beta",
                    "https://example.com/redirect?next=https://example.com/home",
                    "https://example.com/download?file=report.csv",
                    "https://example.com/users/1045/profile",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        src2.write_text("https://example.com/js/app.js\n", encoding="utf-8")

        clean_out = self.work / "clean_urls.txt"
        params_out = self.work / "params.txt"
        buckets = self.work / "buckets"
        n_clean, n_params = clean_and_bucket_urls([src1, src2, self.work / "missing.txt"], clean_out, params_out, buckets)

        self.assertEqual(n_clean, 5)
        self.assertEqual(params_out.read_text(encoding="utf-8").splitlines(), ["file", "next", "page", "q"])
        clean_lines = clean_out.read_text(encoding="utf-8").splitlines()
        self.assertIn("https://example.com/js/app.js", clean_lines)
        self.assertFalse(any("logo.png" in u or "app.css" in u for u in clean_lines))
        self.assertEqual(len([u for u in clean_lines if "/search?" in u]), 1)

        self.assertTrue(any("/search?" in u for u in (buckets / "candidates_xss.txt").read_text(encoding="utf-8").splitlines()))
        self.assertTrue(any("/search?" in u for u in (buckets / "candidates_sqli.txt").read_text(encoding="utf-8").splitlines()))
        self.assertTrue(any("/redirect?" in u for u in (buckets / "candidates_ssrf_redirect.txt").read_text(encoding="utf-8").splitlines()))
        self.assertTrue(any("/download?" in u for u in (buckets / "candidates_lfi.txt").read_text(encoding="utf-8").splitlines()))
        self.assertTrue(any("/users/1045/" in u for u in (buckets / "candidates_idor.txt").read_text(encoding="utf-8").splitlines()))

    def test_diff_baseline_emits_only_newly_seen_items(self):
        cur = self.work / "cur.txt"
        base = self.work / ".baseline" / "subs.txt"
        new_out = self.work / "new.txt"

        cur.write_text("a.example.com\nb.example.com\n", encoding="utf-8")
        self.assertEqual(diff_baseline(cur, base, new_out), 2)
        self.assertEqual(new_out.read_text(encoding="utf-8").splitlines(), ["a.example.com", "b.example.com"])

        cur.write_text("a.example.com\nb.example.com\nc.example.com\n", encoding="utf-8")
        self.assertEqual(diff_baseline(cur, base, new_out), 1)
        self.assertEqual(new_out.read_text(encoding="utf-8").splitlines(), ["c.example.com"])
        self.assertEqual(base.read_text(encoding="utf-8").splitlines(), ["a.example.com", "b.example.com", "c.example.com"])

    def test_build_report_uses_template_and_appends_telemetry(self):
        rep_dir = self.work / "reports" / "target.example"
        (rep_dir / "recon").mkdir(parents=True)
        (rep_dir / "vulns").mkdir(parents=True)
        (rep_dir / "recon" / "authorized_subdomains.txt").write_text("target.example\napi.target.example\n", encoding="utf-8")
        (rep_dir / "vulns" / "nuclei.txt").write_text("[medium] test finding\n", encoding="utf-8")

        out_md = rep_dir / "report-20261119.md"
        build_report(
            ROOT / "bugbounty" / "templates" / "report-template.md",
            out_md,
            "target.example",
            rep_dir,
            "customhunter",
            program_name="Acme Program",
            platform="Intigriti",
        )
        rendered = out_md.read_text(encoding="utf-8")
        self.assertIn("| **Program** | Acme Program |", rendered)
        self.assertIn("| **Platform** | Intigriti |", rendered)
        self.assertIn("| **Target** | target.example |", rendered)
        self.assertIn("| **Researcher** | customhunter |", rendered)
        self.assertIn("## Recon & Scan Telemetry Summary", rendered)
        self.assertIn("| `recon/authorized_subdomains.txt` | 2 |", rendered)
        self.assertIn("| `vulns/nuclei.txt` | 1 |", rendered)


if __name__ == "__main__":
    unittest.main()
