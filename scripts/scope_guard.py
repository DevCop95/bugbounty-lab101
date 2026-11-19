#!/usr/bin/env python3
"""Validate targets against the Markdown scope files in programs/."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """Raised when a target is malformed or not authorized."""


def normalize_target(value: str) -> str:
    value = value.strip()
    if not value or any(char.isspace() or ord(char) < 32 for char in value):
        raise ScopeError("target is empty or contains whitespace/control characters")

    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ScopeError("only valid http/https URLs are accepted")
        if parsed.username or parsed.password:
            raise ScopeError("URL credentials are not accepted")
        try:
            parsed.port
        except ValueError as exc:
            raise ScopeError("URL port is invalid") from exc
        host = parsed.hostname
    else:
        if any(char in value for char in "/\\?#@") or value in {".", ".."}:
            raise ScopeError("plain targets must be a host or IP address")
        host = value.strip("[]")

    host = host.rstrip(".").lower()
    if not host or ".." in host:
        raise ScopeError("target host is invalid")

    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    labels = host.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ScopeError("target host is invalid")
    return host


def normalize_scope_entry(value: str) -> str:
    value = value.strip().strip("`<>")
    value = re.split(r"\s+", value, maxsplit=1)[0]
    if value.startswith("*."):
        return "*." + normalize_target(value[2:])
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.port:
            raise ScopeError("scope URLs cannot contain ports, paths, queries, or fragments")
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return normalize_target(value)


def entry_matches(host: str, entry: str) -> bool:
    if entry.startswith("*."):
        suffix = entry[2:]
        return host.endswith("." + suffix) and host != suffix
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return host == entry


def read_sections(path: Path) -> tuple[list[str], list[str]]:
    sections: dict[str, list[str]] = {"in": [], "out": []}
    current = ""
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        heading = line.strip().lower()
        if heading == "## in scope":
            current = "in"
            continue
        if heading == "## out of scope":
            current = "out"
            continue
        if heading.startswith("## "):
            current = ""
            continue
        match = re.match(r"^\s*[-*]\s+(.+?)\s*$", line)
        if current and match:
            try:
                sections[current].append(normalize_scope_entry(match.group(1)))
            except (ScopeError, ValueError) as exc:
                raise ScopeError(f"invalid scope entry at {path}:{line_number}: {exc}") from exc
    return sections["in"], sections["out"]


def load_programs(programs_dir: Path) -> list[tuple[Path, list[str], list[str]]]:
    programs: list[tuple[Path, list[str], list[str]]] = []
    for path in sorted(programs_dir.glob("*.md")):
        if path.name in {"_template.md", "README.md"}:
            continue
        in_scope, out_scope = read_sections(path)
        programs.append((path, in_scope, out_scope))
    return programs


def is_authorized(
    target: str,
    programs: list[tuple[Path, list[str], list[str]]],
    programs_dir: Path,
) -> tuple[str, Path]:
    host = normalize_target(target)
    for path, _, out_scope in programs:
        if any(entry_matches(host, entry) for entry in out_scope):
            raise ScopeError(f"{host} is explicitly out of scope in {path.name}")

    for path, in_scope, _ in programs:
        if any(entry_matches(host, entry) for entry in in_scope):
            return host, path

    raise ScopeError(f"{host} is not listed in scope under {programs_dir}")


def authorize(target: str, programs_dir: Path) -> tuple[str, Path]:
    programs = load_programs(programs_dir)
    return is_authorized(target, programs, programs_dir)


def filter_file(
    input_path: Path,
    programs_dir: Path,
    authorized_out: Path,
    discarded_out: Path,
    candidates_out: Path | None = None,
) -> None:
    """Filter candidate targets in batch, loading scope definitions once."""
    authorized_out.parent.mkdir(parents=True, exist_ok=True)
    discarded_out.parent.mkdir(parents=True, exist_ok=True)
    authorized_out.write_text("", encoding="utf-8")
    discarded_out.write_text("", encoding="utf-8")

    programs = load_programs(programs_dir)
    if not input_path.is_file():
        return

    authorized_lines: list[str] = []
    discarded_lines: list[str] = []
    for line in input_path.read_text(encoding="utf-8", errors="replace").splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            is_authorized(candidate, programs, programs_dir)
            authorized_lines.append(candidate)
        except ScopeError:
            discarded_lines.append(candidate)

    if authorized_lines:
        authorized_out.write_text("\n".join(authorized_lines) + "\n", encoding="utf-8")
    if discarded_lines:
        discarded_out.write_text("\n".join(discarded_lines) + "\n", encoding="utf-8")
        if candidates_out is not None:
            candidates_out.parent.mkdir(parents=True, exist_ok=True)
            existing: set[str] = set()
            if candidates_out.is_file():
                existing = {
                    item.strip()
                    for item in candidates_out.read_text(encoding="utf-8", errors="replace").splitlines()
                    if item.strip()
                }
            merged = sorted(existing | set(discarded_lines))
            candidates_out.write_text("\n".join(merged) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?")
    parser.add_argument(
        "--programs-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "programs",
    )
    parser.add_argument("--normalize", action="store_true", help="validate and print only the normalized host")
    parser.add_argument("--filter-file", type=Path, help="filter a file of candidate targets in batch")
    parser.add_argument("--authorized-out", type=Path, help="output path for authorized targets")
    parser.add_argument("--discarded-out", type=Path, help="output path for discarded targets")
    parser.add_argument("--candidates-out", type=Path, help="sorted deduplicated file for pending candidates")
    args = parser.parse_args()

    try:
        if args.filter_file is not None:
            if args.authorized_out is None or args.discarded_out is None:
                parser.error("--filter-file requires --authorized-out and --discarded-out")
            filter_file(
                args.filter_file,
                args.programs_dir,
                args.authorized_out,
                args.discarded_out,
                args.candidates_out,
            )
            return 0
        if not args.target:
            parser.error("target is required unless --filter-file is used")
        if args.normalize:
            print(normalize_target(args.target))
        else:
            host, program = authorize(args.target, args.programs_dir)
            print(f"{host}\t{program}")
    except ScopeError as exc:
        print(f"Scope denied: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
