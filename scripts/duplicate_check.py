#!/usr/bin/env python3
"""Pre-submission duplicate check.

Duplicates are the #1 reason reports get closed (see docs/hackerone-workflow.md).
Before writing a report, this does a cheap first-pass check against your OWN
previously-submitted reports recorded in the "Submitted Reports" tables of
programs/*.md, and prints a structured Hacktivity search template for the
second-pass manual check.

It does NOT touch the network. It is a reminder/triage aid, not a guarantee.

Usage:
    scripts/duplicate_check.py "idor on /api/booking setup"
    scripts/duplicate_check.py --program agoda "booking idor"
    scripts/duplicate_check.py --threshold 0.5 "ssrf webhook"
"""
from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROGRAMS_DIR = REPO_ROOT / "programs"

# Words too generic to help a similarity match.
STOPWORDS = {
    "the", "a", "an", "on", "in", "to", "of", "via", "and", "or", "with",
    "for", "is", "at", "by", "from",
}


def tokenize(text: str) -> set[str]:
    toks = re.findall(r"[a-z0-9_./-]+", text.lower())
    return {t for t in toks if t and t not in STOPWORDS}


def parse_submitted_reports(md: str):
    """Yield dicts for each non-empty row of a 'Submitted Reports' table."""
    lines = md.splitlines()
    in_section = False
    header_seen = False
    for line in lines:
        if line.strip().lower().startswith("## submitted reports"):
            in_section = True
            header_seen = False
            continue
        if in_section and line.startswith("## "):
            break  # next section
        if not in_section:
            continue
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        # Skip header row and the markdown separator row.
        if not header_seen:
            if cells and cells[0].lower() == "date":
                header_seen = True
            continue
        if all(set(c) <= {"-", ":", " "} for c in cells):
            continue
        # Expect: Date | Title | Severity | Status | H1 URL
        if len(cells) >= 2 and any(cells):
            yield {
                "date": cells[0],
                "title": cells[1],
                "severity": cells[2] if len(cells) > 2 else "",
                "status": cells[3] if len(cells) > 3 else "",
                "url": cells[4] if len(cells) > 4 else "",
            }


def score(query_tokens: set[str], title: str) -> float:
    title_tokens = tokenize(title)
    if not title_tokens or not query_tokens:
        return 0.0
    overlap = len(query_tokens & title_tokens) / len(query_tokens)
    ratio = difflib.SequenceMatcher(
        None, " ".join(sorted(query_tokens)), " ".join(sorted(title_tokens))
    ).ratio()
    return max(overlap, ratio)


def program_files(program: str | None):
    if not PROGRAMS_DIR.is_dir():
        return []
    files = sorted(PROGRAMS_DIR.glob("*.md"))
    files = [f for f in files if f.name not in ("_template.md", "README.md")]
    if program:
        p = program.lower()
        files = [f for f in files if p in f.stem.lower()]
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("query", help="title keywords / endpoint / CWE of the bug you are about to report")
    ap.add_argument("--program", help="limit to programs/<name>*.md")
    ap.add_argument("--threshold", type=float, default=0.4,
                    help="similarity threshold 0..1 (default 0.4)")
    args = ap.parse_args()

    qtokens = tokenize(args.query)
    if not qtokens:
        print("Query has no searchable terms.", file=sys.stderr)
        return 2

    files = program_files(args.program)
    hits = []
    for f in files:
        try:
            md = f.read_text(encoding="utf-8")
        except OSError:
            continue
        for row in parse_submitted_reports(md):
            s = score(qtokens, row["title"])
            if s >= args.threshold:
                hits.append((s, f.stem, row))

    hits.sort(key=lambda x: x[0], reverse=True)

    print(f"== Local check: your own submitted reports (threshold {args.threshold}) ==")
    if hits:
        print("Possible overlap with reports you already filed:\n")
        for s, prog, row in hits:
            print(f"  [{s:.0%}] ({prog}) {row['title']}")
            meta = " | ".join(x for x in (row["status"], row["severity"], row["date"], row["url"]) if x)
            if meta:
                print(f"         {meta}")
        print("\n  -> Review these before submitting; a same-endpoint+same-class match is likely a self-duplicate.")
    else:
        print("No similar title found in your local programs/*.md report tables.")
        print("(This only covers YOUR recorded reports - still do the Hacktivity check below.)")

    # Second pass: structured Hacktivity query template (manual, no network here).
    terms = "+".join(sorted(qtokens))
    print("\n== Manual check: search public reports before submitting ==")
    print("  Hacktivity (all public):")
    print(f"    https://hackerone.com/hacktivity?querystring={terms}")
    if args.program:
        print("  Program-scoped (replace <handle> with the program's H1 handle):")
        print(f"    https://hackerone.com/<handle>/hacktivity?querystring={terms}")
    print("  Also grep the program's disclosed reports and changelog/known-issues page.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
