#!/usr/bin/env python3
"""Reconnaissance parsing, URL normalization/bucketing, baseline diffing, and report telemetry."""

from __future__ import annotations

import argparse
import datetime
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


NOISE_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".css",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
    ".pdf",
    ".zip",
    ".gz",
    ".map",
)

TAKEOVER_PROVIDERS = (
    "s3.amazonaws.com",
    "github.io",
    "herokuapp.com",
    "azurewebsites.net",
    "cloudapp.net",
    "pantheonsite.io",
    "ghost.io",
    "surge.sh",
    "bitbucket.io",
    "zendesk.com",
    "myshopify.com",
    "fastly.net",
    "netlify.app",
    "vercel.app",
    "readthedocs.io",
    "wpengine.com",
    "helpscoutdocs.com",
    "statuspage.io",
    "readme.io",
    "unbouncepages.com",
)

BUCKET_PARAM_HINTS: dict[str, set[str]] = {
    "candidates_xss.txt": {
        "q", "s", "search", "query", "keyword", "lang", "msg", "message",
        "error", "err", "title", "name", "comment", "text", "body", "html",
        "callback", "jsonp", "input", "term", "tag", "email", "label",
    },
    "candidates_sqli.txt": {
        "id", "uid", "pid", "cid", "item", "item_id", "user_id", "order",
        "sort", "dir", "filter", "where", "category", "cat", "page", "limit",
        "offset", "row", "col", "column", "table", "year", "month", "search",
        "query",
    },
    "candidates_ssrf_redirect.txt": {
        "url", "uri", "next", "redirect", "redirect_uri", "redirect_url",
        "return", "return_to", "returnto", "dest", "destination", "target",
        "to", "out", "view", "callback", "webhook", "fetch", "proxy", "feed",
        "host", "domain", "link", "continue", "goto", "r", "u",
    },
    "candidates_lfi.txt": {
        "file", "filename", "path", "filepath", "doc", "document", "page",
        "template", "tpl", "include", "inc", "dir", "folder", "root", "pg",
        "load", "read", "download", "img", "src", "style", "lang", "locale",
    },
    "candidates_idor.txt": {
        "id", "uid", "user_id", "userid", "account", "account_id", "acct",
        "profile", "profile_id", "order_id", "invoice", "invoice_id",
        "booking", "booking_id", "doc_id", "file_id", "report_id", "org",
        "org_id", "tenant", "tenant_id", "project_id", "member_id", "uuid",
        "token",
    },
}

IDOR_PATH_RE = re.compile(
    r"/(?:[0-9]{2,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)",
    re.IGNORECASE,
)


def _write_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _matches_takeover_provider(cname: str) -> bool:
    norm = cname.strip().rstrip(".").lower()
    return any(norm == p or norm.endswith("." + p) for p in TAKEOVER_PROVIDERS)


def parse_httpx_outputs(
    httpx_json: Path,
    live_out: Path,
    tech_out: Path,
    takeover_out: Path,
    httpx_txt: Path | None = None,
) -> tuple[int, int, int]:
    """Parse httpx JSONL (with plain-text fallback) into live URLs, techs, and takeover leads."""
    live_urls: set[str] = set()
    technologies: set[str] = set()
    takeovers: set[str] = set()

    if httpx_json.is_file():
        for raw_line in httpx_json.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue

            url = str(record.get("url") or "").strip()
            if url:
                live_urls.add(url)

            raw_tech = record.get("tech") if "tech" in record else record.get("technologies")
            if isinstance(raw_tech, list):
                for item in raw_tech:
                    tok = str(item).strip()
                    if tok:
                        technologies.add(tok)
            elif isinstance(raw_tech, str):
                for item in raw_tech.split(","):
                    tok = item.strip()
                    if tok:
                        technologies.add(tok)

            raw_cname = record.get("cname") or record.get("cnames")
            cnames: list[str] = []
            if isinstance(raw_cname, str) and raw_cname.strip():
                cnames = [raw_cname.strip()]
            elif isinstance(raw_cname, list):
                cnames = [str(c).strip() for c in raw_cname if str(c).strip()]

            status = record.get("status_code")
            if status is None:
                status = record.get("status-code")
            status_str = str(status) if status is not None else ""

            if url and cnames:
                for cname in cnames:
                    if _matches_takeover_provider(cname):
                        takeovers.add(f"{url}\t{status_str}\t{cname.rstrip('.').lower()}")

    if not live_urls and httpx_txt is not None and httpx_txt.is_file():
        for raw_line in httpx_txt.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if line:
                live_urls.add(line.split()[0])

    for path, items in (
        (live_out, sorted(live_urls)),
        (tech_out, sorted(technologies, key=lambda s: s.lower())),
        (takeover_out, sorted(takeovers)),
    ):
        _write_lf(path, "\n".join(items) + ("\n" if items else ""))

    return len(live_urls), len(technologies), len(takeovers)


def clean_and_bucket_urls(
    input_files: list[Path],
    out_path: Path,
    params_out: Path,
    buckets_dir: Path,
) -> tuple[int, int]:
    """Filter static asset noise, deduplicate URLs by structure, extract params, and bucket leads."""
    seen_signatures: dict[tuple[str, str, str, tuple[str, ...]], str] = {}
    all_params: set[str] = set()
    buckets: dict[str, set[str]] = {name: set() for name in BUCKET_PARAM_HINTS}

    for src in input_files:
        if not src.is_file():
            continue
        for raw_line in src.read_text(encoding="utf-8", errors="replace").splitlines():
            candidate = raw_line.strip()
            if not candidate or "://" not in candidate:
                continue
            try:
                parsed = urlsplit(candidate)
            except ValueError:
                continue
            scheme = parsed.scheme.lower()
            if scheme not in {"http", "https"} or not parsed.hostname:
                continue

            lower_path = parsed.path.lower()
            if any(lower_path.endswith(ext) for ext in NOISE_EXTENSIONS):
                continue

            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            param_keys = sorted({k for k, _ in query_pairs if k})
            all_params.update(param_keys)

            signature = (scheme, parsed.netloc.lower(), parsed.path or "/", tuple(param_keys))
            if signature not in seen_signatures:
                seen_signatures[signature] = candidate

            rep_url = seen_signatures[signature]
            lower_keys = {k.lower() for k in param_keys}
            for bucket_name, hint_keys in BUCKET_PARAM_HINTS.items():
                if lower_keys & hint_keys:
                    buckets[bucket_name].add(rep_url)
            if IDOR_PATH_RE.search(parsed.path or ""):
                buckets["candidates_idor.txt"].add(rep_url)

    clean_urls = sorted(seen_signatures.values())
    sorted_params = sorted(all_params)

    _write_lf(out_path, "\n".join(clean_urls) + ("\n" if clean_urls else ""))
    _write_lf(params_out, "\n".join(sorted_params) + ("\n" if sorted_params else ""))

    buckets_dir.mkdir(parents=True, exist_ok=True)
    for bucket_name, urls in buckets.items():
        sorted_bucket = sorted(urls)
        _write_lf(buckets_dir / bucket_name, "\n".join(sorted_bucket) + ("\n" if sorted_bucket else ""))

    return len(clean_urls), len(sorted_params)


def diff_baseline(current_file: Path, baseline_file: Path, new_out: Path) -> int:
    """Emit newly seen lines relative to baseline and update the persisted baseline."""
    current: set[str] = set()
    if current_file.is_file():
        current = {line.strip() for line in current_file.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()}

    baseline: set[str] = set()
    if baseline_file.is_file():
        baseline = {line.strip() for line in baseline_file.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()}

    new_items = sorted(current - baseline)
    merged = sorted(baseline | current)

    _write_lf(new_out, "\n".join(new_items) + ("\n" if new_items else ""))
    _write_lf(baseline_file, "\n".join(merged) + ("\n" if merged else ""))
    return len(new_items)


def _count_nonempty_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())


def build_report(
    template_path: Path,
    output_path: Path,
    target: str,
    reports_dir: Path,
    researcher: str,
    program_name: str = "",
    platform: str = "HackerOne",
) -> None:
    """Render report-template.md with target/program metadata and recon/scan telemetry."""
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    if template_path.is_file():
        content = template_path.read_text(encoding="utf-8")
    else:
        content = (
            "# Bug Bounty Report\n\n"
            "| Field | Value |\n|-------|-------|\n"
            "| **Program** | [Program name] |\n"
            "| **Platform** | HackerOne |\n"
            "| **Target** | [Exact domain/URL/asset listed in scope] |\n"
            "| **Date** | [YYYY-MM-DD] |\n"
            "| **Researcher** | dev101x |\n"
        )

    resolved_program = program_name.strip() or "[Program name]"
    content = content.replace("[Program name]", resolved_program)
    content = content.replace("| **Platform** | HackerOne |", f"| **Platform** | {platform} |")
    content = content.replace("[Exact domain/URL/asset listed in scope]", target)
    content = content.replace("[YYYY-MM-DD]", today)
    content = content.replace("| **Researcher** | dev101x |", f"| **Researcher** | {researcher} |")
    content = content.replace("*dev101x — Bug Bounty Framework*", f"*{researcher} — Bug Bounty Framework*")

    tracked_artifacts = [
        "recon/authorized_subdomains.txt",
        "recon/new_subdomains.txt",
        "recon/live_urls.txt",
        "recon/technologies.txt",
        "recon/takeover_candidates.txt",
        "recon/clean_urls.txt",
        "recon/params.txt",
        "recon/api_specs.txt",
        "recon/browser_urls_in_scope.txt",
    ]

    rows: list[tuple[str, int]] = []
    for rel in tracked_artifacts:
        full = reports_dir / rel
        if full.is_file():
            rows.append((rel, _count_nonempty_lines(full)))

    for subdir in ("vulns", "secrets", "api"):
        folder = reports_dir / subdir
        if not folder.is_dir():
            continue
        for item in sorted(folder.iterdir()):
            if item.is_file() and item.suffix in {".txt", ".json", ".csv"}:
                cnt = _count_nonempty_lines(item)
                if cnt > 0:
                    rows.append((f"{subdir}/{item.name}", cnt))

    summary_lines = [
        "",
        "---",
        "",
        "## Recon & Scan Telemetry Summary",
        "",
        f"Generated: `{today}` for target `{target}`",
        "",
        "| Artifact | Non-empty entries |",
        "|----------|-------------------|",
    ]
    if rows:
        for rel, cnt in rows:
            summary_lines.append(f"| `{rel}` | {cnt} |")
    else:
        summary_lines.append("| _(no phase telemetry recorded yet)_ | 0 |")
    summary_lines.append("")

    _write_lf(output_path, content.rstrip() + "\n" + "\n".join(summary_lines))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_httpx = sub.add_parser("parse-httpx", help="parse httpx JSONL output")
    p_httpx.add_argument("httpx_json", type=Path)
    p_httpx.add_argument("--live-out", type=Path, required=True)
    p_httpx.add_argument("--tech-out", type=Path, required=True)
    p_httpx.add_argument("--takeover-out", type=Path, required=True)
    p_httpx.add_argument("--httpx-txt", type=Path, default=None)

    p_clean = sub.add_parser("clean-urls", help="deduplicate URLs and build vuln candidate lists")
    p_clean.add_argument("inputs", nargs="+", type=Path)
    p_clean.add_argument("--out", type=Path, required=True)
    p_clean.add_argument("--params-out", type=Path, required=True)
    p_clean.add_argument("--buckets-dir", type=Path, required=True)

    p_diff = sub.add_parser("diff-baseline", help="diff current items against a baseline file")
    p_diff.add_argument("current_file", type=Path)
    p_diff.add_argument("--baseline", type=Path, required=True)
    p_diff.add_argument("--new-out", type=Path, required=True)

    p_rep = sub.add_parser("build-report", help="render HackerOne report template with telemetry")
    p_rep.add_argument("--template", type=Path, required=True)
    p_rep.add_argument("--output", type=Path, required=True)
    p_rep.add_argument("--target", required=True)
    p_rep.add_argument("--reports-dir", type=Path, required=True)
    p_rep.add_argument("--researcher", required=True)
    p_rep.add_argument("--program", default="")
    p_rep.add_argument("--platform", default="HackerOne")

    args = parser.parse_args()
    if args.cmd == "parse-httpx":
        parse_httpx_outputs(args.httpx_json, args.live_out, args.tech_out, args.takeover_out, args.httpx_txt)
    elif args.cmd == "clean-urls":
        clean_and_bucket_urls(args.inputs, args.out, args.params_out, args.buckets_dir)
    elif args.cmd == "diff-baseline":
        diff_baseline(args.current_file, args.baseline, args.new_out)
    elif args.cmd == "build-report":
        build_report(
            args.template,
            args.output,
            args.target,
            args.reports_dir,
            args.researcher,
            args.program,
            args.platform,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
