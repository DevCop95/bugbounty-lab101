#!/usr/bin/env python3
"""Scope validator, policy parser, audit/diff/import/export engine for programs/*.md."""

from __future__ import annotations

import argparse
import csv
import datetime
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit


INACTIVE_STATUSES = {"paused", "retired", "closed", "inactive", "archived"}
NON_NETWORK_ASSET_TYPES = {
    "GOOGLE_PLAY_APP_ID",
    "APPLE_STORE_APP_ID",
    "WINDOWS_APP_STORE_APP_ID",
    "SOURCE_CODE",
    "DOWNLOADABLE_EXECUTABLES",
    "EXECUTABLE",
    "HARDWARE",
    "SMART_CONTRACT",
    "AI_MODEL",
    "TESTFLIGHT",
    "MOBILE",
    "ANDROID",
    "IOS",
    "OTHER",
}

HEADER_RE = re.compile(
    r"`((?:[A-Za-z0-9-]*(?:Research|Security[-_]?Testing|Bug[-_]?Bounty|HackerOne|Bugcrowd|Intigriti|YesWeHack)[A-Za-z0-9-]*)|User-Agent):\s*([^`\r\n]+)`",
    re.IGNORECASE,
)
TABLE_ROW_RE = re.compile(r"^\|\s*\*{0,2}([^|*]+?)\*{0,2}\s*\|\s*(.*?)\s*\|\s*$")
LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
WILDCARD_LABEL_RE = re.compile(r"[a-z0-9*-]+")

RATE_PATTERNS = [
    re.compile(r"BB_RATE_LIMIT\s*[=:]\s*([0-9]+)", re.IGNORECASE),
    re.compile(
        r"(?:rate[\s_-]*limit|max(?:imum)?|ceiling(?:\s+of)?)\D{0,30}?\*{0,2}([0-9]+)\*{0,2}\s*(?:req(?:uests?)?\s*/\s*s(?:ec(?:ond)?)?|rps|requests?\s+per\s+second)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\*{0,2}([0-9]+)\*{0,2}\s*(?:req(?:uests?)?\s*/\s*s(?:ec(?:ond)?)?|rps|requests?\s+per\s+second)",
        re.IGNORECASE,
    ),
]


class ScopeError(ValueError):
    """Raised when a target or scope rule is malformed or not authorized."""


@dataclass(frozen=True)
class TargetInfo:
    raw: str
    host: str
    scheme: str | None
    port: int | None
    path: str
    is_url: bool

    @property
    def effective_port(self) -> int | None:
        if self.port is not None:
            return self.port
        if self.scheme == "https":
            return 443
        if self.scheme == "http":
            return 80
        return None


@dataclass(frozen=True)
class ScopeRule:
    raw: str
    canonical: str
    kind: str  # "domain", "wildcard", "cidr", "url"
    host_pattern: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    port: int | None = None
    scheme: str | None = None
    path_prefix: str | None = None
    path_match_mode: str | None = None  # "boundary" or "prefix"
    leading_wildcard: bool = False
    label_regexes: tuple[re.Pattern[str], ...] = ()

    @property
    def asset_class(self) -> str:
        if self.network is not None:
            return "cidrs"
        if self.leading_wildcard or "*" in self.host_pattern:
            return "wildcards"
        return "domains"


@dataclass
class ProgramPolicy:
    path: Path
    name: str
    platform: str = "HackerOne"
    handle: str = ""
    status: str = "Active"
    last_review: str | None = None
    in_scope: list[str] = field(default_factory=list)
    out_scope: list[str] = field(default_factory=list)
    in_rules: list[ScopeRule] = field(default_factory=list)
    out_rules: list[ScopeRule] = field(default_factory=list)
    research_headers: list[str] = field(default_factory=list)
    rate_limit: int | None = None
    active: bool = True
    stale_days: int | None = None
    parse_error: str | None = None


def _validate_host_or_ip(host: str) -> str:
    host = host.strip("[]").rstrip(".").lower()
    if not host or ".." in host:
        raise ScopeError("target host is invalid")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    labels = host.split(".")
    if any(not LABEL_RE.fullmatch(label) for label in labels):
        raise ScopeError("target host is invalid")
    return host


def _validate_port(port_val: int | str) -> int:
    try:
        port = int(port_val)
    except (TypeError, ValueError) as exc:
        raise ScopeError("port is invalid") from exc
    if port < 1 or port > 65535:
        raise ScopeError("port must be between 1 and 65535")
    return port


def parse_target(value: str) -> TargetInfo:
    """Validate a target URL, host:port, bare host, or IP and return TargetInfo."""
    raw = value.strip()
    if not raw or any(char.isspace() or ord(char) < 32 for char in raw):
        raise ScopeError("target is empty or contains whitespace/control characters")

    if "://" in raw:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ScopeError("only valid http/https URLs are accepted")
        if parsed.username or parsed.password:
            raise ScopeError("URL credentials are not accepted")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ScopeError("URL port is invalid") from exc
        if port is not None:
            port = _validate_port(port)
        host = _validate_host_or_ip(parsed.hostname)
        path = parsed.path or "/"
        return TargetInfo(
            raw=raw,
            host=host,
            scheme=parsed.scheme.lower(),
            port=port,
            path=path,
            is_url=True,
        )

    if any(char in raw for char in "/\\?#@") or raw in {".", ".."}:
        raise ScopeError("plain targets must be a host or IP address")

    stripped = raw.strip("[]")
    try:
        ip_str = str(ipaddress.ip_address(stripped))
        return TargetInfo(raw=raw, host=ip_str, scheme=None, port=None, path="/", is_url=False)
    except ValueError:
        pass

    port: int | None = None
    host_candidate = raw
    if raw.startswith("[") and "]:" in raw:
        host_part, port_part = raw[1:].split("]:", 1)
        if not port_part.isdigit():
            raise ScopeError("target port is invalid")
        port = _validate_port(port_part)
        host_candidate = host_part
    elif raw.count(":") == 1:
        host_part, port_part = raw.split(":", 1)
        if not port_part.isdigit():
            raise ScopeError("target port is invalid")
        port = _validate_port(port_part)
        host_candidate = host_part
    elif ":" in raw:
        raise ScopeError("target host is invalid")

    host = _validate_host_or_ip(host_candidate)
    return TargetInfo(raw=raw, host=host, scheme=None, port=port, path="/", is_url=False)


def normalize_target(value: str) -> str:
    """Validate and return only the normalized hostname or IP string."""
    return parse_target(value).host


def _compile_wildcard_host(host_expr: str) -> tuple[str, bool, tuple[re.Pattern[str], ...]]:
    host_expr = host_expr.rstrip(".").lower()
    if not host_expr or ".." in host_expr:
        raise ScopeError("wildcard host is invalid")

    leading_wildcard = False
    raw_labels = host_expr.split(".")
    if raw_labels[0] == "*":
        leading_wildcard = True
        tail_labels = raw_labels[1:]
        if not tail_labels:
            raise ScopeError("bare wildcard '*' is not allowed")
    else:
        tail_labels = raw_labels

    if len(tail_labels) < 1 or "*" in tail_labels[-1]:
        raise ScopeError("wildcard TLD is not allowed")

    compiled: list[re.Pattern[str]] = []
    for label in tail_labels:
        if not label or not WILDCARD_LABEL_RE.fullmatch(label):
            raise ScopeError(f"invalid wildcard label: {label}")
        if "*" not in label:
            if not LABEL_RE.fullmatch(label):
                raise ScopeError(f"invalid domain label in wildcard: {label}")
            compiled.append(re.compile("^" + re.escape(label) + "$"))
        else:
            if label == "*":
                raise ScopeError("intermediate '*' label is not supported")
            parts = [re.escape(part) for part in label.split("*")]
            compiled.append(re.compile("^" + "[a-z0-9-]*".join(parts) + "$"))

    canonical = ("*." if leading_wildcard else "") + ".".join(tail_labels)
    return canonical, leading_wildcard, tuple(compiled)


def _parse_path_rule(raw_path: str) -> tuple[str, str, str]:
    """Return (canonical_path, path_prefix, path_match_mode)."""
    if any(seg == ".." for seg in raw_path.split("/")):
        raise ScopeError("scope path cannot contain traversal segments")
    if raw_path.endswith("/*"):
        prefix = raw_path[:-2] or "/"
        canonical = (prefix if prefix != "/" else "") + "/*"
        return canonical, prefix, "boundary"
    if raw_path.endswith("*"):
        prefix = raw_path[:-1]
        if "*" in prefix:
            raise ScopeError("wildcard '*' is only allowed at the end of a scope path")
        return raw_path, prefix, "prefix"
    if "*" in raw_path:
        raise ScopeError("wildcard '*' is only allowed at the end of a scope path")
    trimmed = raw_path.rstrip("/") or "/"
    return trimmed, trimmed, "boundary"


def _split_host_and_port(token: str) -> tuple[str, int | None]:
    if token.startswith("["):
        if "]:" in token:
            host_part, port_part = token[1:].split("]:", 1)
            return host_part, _validate_port(port_part)
        return token.strip("[]"), None
    if token.count(":") == 1 and "/" not in token:
        host_part, port_part = token.split(":", 1)
        if not port_part.isdigit():
            raise ScopeError("scope port is invalid")
        return host_part, _validate_port(port_part)
    if ":" in token:
        # Plain IPv6 or CIDR with IPv6 (e.g. 2001:db8::/32)
        return token, None
    return token, None


def parse_scope_rule(value: str) -> ScopeRule:
    """Parse a scope definition line into a structured ScopeRule."""
    cleaned = value.strip().strip("`<>")
    token = re.split(r"\s+", cleaned, maxsplit=1)[0]
    if not token:
        raise ScopeError("scope entry is empty")

    if "://" in token:
        parsed = urlsplit(token)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise ScopeError("only valid http/https URLs are accepted")
        if parsed.username or parsed.password:
            raise ScopeError("URL credentials are not accepted")
        if parsed.query or parsed.fragment:
            raise ScopeError("scope URLs cannot contain queries or fragments")
        try:
            raw_port = parsed.port
        except ValueError as exc:
            raise ScopeError("URL port is invalid") from exc
        port = _validate_port(raw_port) if raw_port is not None else None
        raw_host = parsed.hostname.lower().rstrip(".")
        raw_path = parsed.path or ""

        if "*" in raw_host:
            host_canon, leading_wc, label_regexes = _compile_wildcard_host(raw_host)
            host_kind = "wildcard"
            net = None
        else:
            host_canon = _validate_host_or_ip(raw_host)
            host_kind = "domain"
            leading_wc = False
            label_regexes = ()
            try:
                ipaddress.ip_address(host_canon)
                net = ipaddress.ip_network(host_canon, strict=False)
            except ValueError:
                net = None

        if raw_path in {"", "/"} and port is None:
            kind = "cidr" if net is not None else host_kind
            canonical = str(net) if net is not None else host_canon
            return ScopeRule(
                raw=token,
                canonical=canonical,
                kind=kind,
                host_pattern=host_canon,
                network=net,
                port=None,
                scheme=None,
                leading_wildcard=leading_wc,
                label_regexes=label_regexes,
            )

        if raw_path in {"", "/"} and port is not None:
            canonical = f"{host_canon}:{port}"
            kind = "url"
            return ScopeRule(
                raw=token,
                canonical=canonical,
                kind=kind,
                host_pattern=host_canon,
                network=net,
                port=port,
                scheme=scheme,
                leading_wildcard=leading_wc,
                label_regexes=label_regexes,
            )

        path_canon, path_prefix, path_mode = _parse_path_rule(raw_path)
        port_suffix = f":{port}" if port is not None else ""
        canonical = f"{scheme}://{host_canon}{port_suffix}{path_canon}"
        return ScopeRule(
            raw=token,
            canonical=canonical,
            kind="url",
            host_pattern=host_canon,
            network=net,
            port=port,
            scheme=scheme,
            path_prefix=path_prefix,
            path_match_mode=path_mode,
            leading_wildcard=leading_wc,
            label_regexes=label_regexes,
        )

    if any(char in token for char in "\\?#@") or token in {".", ".."}:
        raise ScopeError("plain scope entries must be a host, wildcard, or CIDR")

    # Reject un-schemed paths like example.com/admin (require http(s):// for path rules)
    try:
        net = ipaddress.ip_network(token, strict=False)
        return ScopeRule(
            raw=token,
            canonical=str(net),
            kind="cidr",
            host_pattern=str(net),
            network=net,
        )
    except ValueError:
        pass

    if "/" in token:
        raise ScopeError("path-scoped entries must be full http(s) URLs")

    host_part, port = _split_host_and_port(token)
    if "*" in host_part:
        host_canon, leading_wc, label_regexes = _compile_wildcard_host(host_part)
        canonical = f"{host_canon}:{port}" if port is not None else host_canon
        return ScopeRule(
            raw=token,
            canonical=canonical,
            kind="wildcard",
            host_pattern=host_canon,
            port=port,
            leading_wildcard=leading_wc,
            label_regexes=label_regexes,
        )

    try:
        net = ipaddress.ip_network(host_part, strict=False)
        canonical = f"{net}:{port}" if port is not None else str(net)
        return ScopeRule(
            raw=token,
            canonical=canonical,
            kind="cidr" if port is None else "url",
            host_pattern=str(net.network_address),
            network=net,
            port=port,
        )
    except ValueError:
        host_canon = _validate_host_or_ip(host_part)
        canonical = f"{host_canon}:{port}" if port is not None else host_canon
        return ScopeRule(
            raw=token,
            canonical=canonical,
            kind="domain" if port is None else "url",
            host_pattern=host_canon,
            port=port,
        )


def normalize_scope_entry(value: str) -> str:
    """Validate and normalize a scope entry into canonical string form."""
    return parse_scope_rule(value).canonical


def _host_matches_rule(host: str, rule: ScopeRule) -> bool:
    if rule.network is not None:
        try:
            return ipaddress.ip_address(host) in rule.network
        except ValueError:
            return False

    if rule.label_regexes:
        target_labels = host.split(".")
        need = len(rule.label_regexes)
        if rule.leading_wildcard:
            if len(target_labels) <= need:
                return False
            slice_labels = target_labels[-need:]
        else:
            if len(target_labels) != need:
                return False
            slice_labels = target_labels
        return all(pattern.fullmatch(lbl) is not None for pattern, lbl in zip(rule.label_regexes, slice_labels))

    return host == rule.host_pattern


def _path_matches_rule(target_path: str, rule: ScopeRule) -> bool:
    assert rule.path_prefix is not None
    if rule.path_match_mode == "prefix":
        return target_path.startswith(rule.path_prefix)
    # Boundary-safe match: /admin matches /admin and /admin/... never /administrator
    if rule.path_prefix == "/":
        return target_path.startswith("/")
    return target_path == rule.path_prefix or target_path.startswith(rule.path_prefix + "/")


def rule_matches(target: TargetInfo, rule: ScopeRule) -> bool:
    """Return True if TargetInfo matches ScopeRule (host/CIDR + optional port & path)."""
    if not _host_matches_rule(target.host, rule):
        return False
    if rule.port is not None:
        if target.effective_port != rule.port:
            return False
    if rule.path_prefix is not None:
        if not target.is_url:
            return False
        if not _path_matches_rule(target.path, rule):
            return False
    return True


def entry_matches(target: str | TargetInfo, entry: str | ScopeRule) -> bool:
    """Check whether a normalized host or URL target matches a scope rule."""
    target_info = target if isinstance(target, TargetInfo) else parse_target(target)
    rule = entry if isinstance(entry, ScopeRule) else parse_scope_rule(entry)
    return rule_matches(target_info, rule)


def _extract_markdown_metadata(text: str, path: Path) -> tuple[str, str, str, str, str | None]:
    name = path.stem
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            heading_name = stripped[2:].strip()
            if heading_name and heading_name != "[Program Name]":
                name = heading_name
            break

    meta: dict[str, str] = {}
    for line in text.splitlines():
        match = TABLE_ROW_RE.match(line.strip())
        if match:
            key = match.group(1).strip().lower()
            val = match.group(2).strip()
            meta[key] = val

    platform = meta.get("platform", "HackerOne") or "HackerOne"
    handle = meta.get("h1 handle") or meta.get("program handle") or meta.get("handle") or ""
    status = meta.get("status", "Active") or "Active"
    last_review_raw = meta.get("last scope review", "")
    last_review = last_review_raw if re.fullmatch(r"\d{4}-\d{2}-\d{2}", last_review_raw) else None
    return name, platform, handle, status, last_review


def _is_status_active(status: str) -> bool:
    cleaned = status.strip().lower()
    if not cleaned:
        return True
    first_word = re.split(r"[\s(:;,/]+", cleaned, maxsplit=1)[0]
    return first_word not in INACTIVE_STATUSES


def _compute_stale_days(last_review: str | None) -> int | None:
    if not last_review:
        return None
    try:
        reviewed = datetime.date.fromisoformat(last_review)
    except ValueError:
        return None
    today = datetime.datetime.now(datetime.timezone.utc).date()
    return (today - reviewed).days


def _extract_research_headers_and_rate(text: str) -> tuple[list[str], int | None]:
    headers: list[str] = []
    seen_headers: set[str] = set()
    rate_candidates: list[int] = []

    current_section = ""
    relevant_lines: list[str] = []
    header_search_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("## "):
            current_section = lower[3:].strip()
            continue
        if current_section in {"in scope", "special rules"} or stripped.startswith("|"):
            header_search_lines.append(line)
        if current_section == "special rules" or stripped.startswith("|"):
            relevant_lines.append(line)

    for line in header_search_lines:
        for match in HEADER_RE.finditer(line):
            hname = match.group(1).strip()
            hval = match.group(2).strip()
            if not hname or not hval:
                continue
            formatted = f"{hname}: {hval}"
            key = formatted.lower()
            if key not in seen_headers:
                seen_headers.add(key)
                headers.append(formatted)

    special_blob = "\n".join(relevant_lines)
    for pattern in RATE_PATTERNS:
        for match in pattern.finditer(special_blob):
            val = int(match.group(1))
            if val > 0:
                rate_candidates.append(val)

    rate_limit = min(rate_candidates) if rate_candidates else None
    return headers, rate_limit


def read_sections(path: Path) -> tuple[list[str], list[str]]:
    """Read normalized canonical In Scope and Out of Scope entry strings."""
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


def read_program_policy(path: Path) -> ProgramPolicy:
    """Parse full scope rules and policy metadata from a program Markdown file."""
    text = path.read_text(encoding="utf-8")
    name, platform, handle, status, last_review = _extract_markdown_metadata(text, path)
    headers, rate_limit = _extract_research_headers_and_rate(text)
    stale_days = _compute_stale_days(last_review)
    active = _is_status_active(status)

    in_canon: list[str] = []
    out_canon: list[str] = []
    in_rules: list[ScopeRule] = []
    out_rules: list[ScopeRule] = []

    current = ""
    for line_number, line in enumerate(text.splitlines(), start=1):
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
                rule = parse_scope_rule(match.group(1))
            except (ScopeError, ValueError) as exc:
                raise ScopeError(f"invalid scope entry at {path}:{line_number}: {exc}") from exc
            if current == "in":
                in_canon.append(rule.canonical)
                in_rules.append(rule)
            else:
                out_canon.append(rule.canonical)
                out_rules.append(rule)

    return ProgramPolicy(
        path=path,
        name=name,
        platform=platform,
        handle=handle,
        status=status,
        last_review=last_review,
        in_scope=in_canon,
        out_scope=out_canon,
        in_rules=in_rules,
        out_rules=out_rules,
        research_headers=headers,
        rate_limit=rate_limit,
        active=active,
        stale_days=stale_days,
    )


def load_programs(programs_dir: Path) -> list[tuple[Path, list[str], list[str]]]:
    """Legacy loader returning (path, in_scope_list, out_scope_list)."""
    programs: list[tuple[Path, list[str], list[str]]] = []
    if not programs_dir.is_dir():
        return programs
    for path in sorted(programs_dir.glob("*.md")):
        if path.name in {"_template.md", "README.md"}:
            continue
        in_scope, out_scope = read_sections(path)
        programs.append((path, in_scope, out_scope))
    return programs


def load_program_policies(programs_dir: Path, lenient: bool = False) -> list[ProgramPolicy]:
    """Load structured ProgramPolicy objects from programs/*.md."""
    policies: list[ProgramPolicy] = []
    if not programs_dir.is_dir():
        return policies
    for path in sorted(programs_dir.glob("*.md")):
        if path.name in {"_template.md", "README.md"}:
            continue
        try:
            policies.append(read_program_policy(path))
        except ScopeError as exc:
            if not lenient:
                raise
            text = path.read_text(encoding="utf-8", errors="replace")
            name, platform, handle, status, last_review = _extract_markdown_metadata(text, path)
            policies.append(
                ProgramPolicy(
                    path=path,
                    name=name,
                    platform=platform,
                    handle=handle,
                    status=status,
                    last_review=last_review,
                    active=_is_status_active(status),
                    stale_days=_compute_stale_days(last_review),
                    parse_error=str(exc),
                )
            )
    return policies


def _emit_stale_warning_if_needed(policy: ProgramPolicy) -> None:
    try:
        max_age = int(os.environ.get("BB_SCOPE_MAX_AGE_DAYS", "30"))
    except ValueError:
        max_age = 30
    if max_age > 0 and policy.stale_days is not None and policy.stale_days > max_age:
        print(
            f"Scope warning: {policy.path.name} was last reviewed {policy.last_review} "
            f"({policy.stale_days}d ago > {max_age}d); re-verify policy before testing.",
            file=sys.stderr,
        )


def _evaluate_target(
    target_info: TargetInfo,
    policies: list[ProgramPolicy],
    programs_dir: Path,
) -> tuple[ProgramPolicy, ScopeRule]:
    for policy in policies:
        for rule in policy.out_rules:
            if rule_matches(target_info, rule):
                raise ScopeError(f"{target_info.host} is explicitly out of scope in {policy.path.name} ({rule.canonical})")

    for policy in policies:
        if not policy.active:
            continue
        for rule in policy.in_rules:
            if rule_matches(target_info, rule):
                return policy, rule

    for policy in policies:
        if policy.active:
            continue
        for rule in policy.in_rules:
            if rule_matches(target_info, rule):
                raise ScopeError(
                    f"{target_info.host} is covered only by non-active program {policy.path.name} (status: {policy.status})"
                )

    raise ScopeError(f"{target_info.host} is not listed in scope under {programs_dir}")


def is_authorized(
    target: str,
    programs: list[tuple[Path, list[str], list[str]]] | list[ProgramPolicy],
    programs_dir: Path,
) -> tuple[str, Path]:
    """Validate target against pre-loaded program tuples or ProgramPolicy objects."""
    target_info = parse_target(target)
    if programs and isinstance(programs[0], ProgramPolicy):
        policy, _ = _evaluate_target(target_info, programs, programs_dir)  # type: ignore[arg-type]
        return target_info.host, policy.path

    for path, _, out_scope in programs:  # type: ignore[misc]
        if any(entry_matches(target_info, entry) for entry in out_scope):
            raise ScopeError(f"{target_info.host} is explicitly out of scope in {path.name}")

    for path, in_scope, _ in programs:  # type: ignore[misc]
        if any(entry_matches(target_info, entry) for entry in in_scope):
            return target_info.host, path

    raise ScopeError(f"{target_info.host} is not listed in scope under {programs_dir}")


def authorize(target: str, programs_dir: Path, warn_stale: bool = True) -> tuple[str, Path]:
    """Authorize a single target against programs_dir and return (host, program_path)."""
    target_info = parse_target(target)
    policies = load_program_policies(programs_dir)
    policy, _ = _evaluate_target(target_info, policies, programs_dir)
    if warn_stale:
        _emit_stale_warning_if_needed(policy)
    return target_info.host, policy.path


def explain_target(target: str, programs_dir: Path) -> dict[str, object]:
    """Return a structured verdict explaining why target is authorized or denied."""
    try:
        target_info = parse_target(target)
    except ScopeError as exc:
        return {
            "target": target,
            "authorized": False,
            "reason": str(exc),
            "program_file": None,
            "matched_rule": None,
        }

    try:
        policies = load_program_policies(programs_dir)
    except ScopeError as exc:
        return {
            "target": target,
            "host": target_info.host,
            "authorized": False,
            "reason": str(exc),
            "program_file": None,
            "matched_rule": None,
        }

    try:
        policy, rule = _evaluate_target(target_info, policies, programs_dir)
        return {
            "target": target,
            "host": target_info.host,
            "effective_port": target_info.effective_port,
            "path": target_info.path if target_info.is_url else None,
            "authorized": True,
            "reason": f"Matched active in-scope rule '{rule.canonical}' in {policy.path.name}",
            "program_file": str(policy.path),
            "program_name": policy.name,
            "platform": policy.platform,
            "handle": policy.handle,
            "status": policy.status,
            "last_review": policy.last_review,
            "stale_days": policy.stale_days,
            "matched_rule": rule.canonical,
            "rule_kind": rule.kind,
            "research_header": policy.research_headers[0] if policy.research_headers else "",
            "research_headers": policy.research_headers,
            "rate_limit": policy.rate_limit,
        }
    except ScopeError as exc:
        return {
            "target": target,
            "host": target_info.host,
            "effective_port": target_info.effective_port,
            "path": target_info.path if target_info.is_url else None,
            "authorized": False,
            "reason": str(exc),
            "program_file": None,
            "matched_rule": None,
        }


def _write_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def filter_file(
    input_path: Path,
    programs_dir: Path,
    authorized_out: Path,
    discarded_out: Path,
    candidates_out: Path | None = None,
) -> None:
    """Filter candidate targets in batch, loading scope definitions once."""
    _write_lf(authorized_out, "")
    _write_lf(discarded_out, "")

    policies = load_program_policies(programs_dir)
    if not input_path.is_file():
        return

    authorized_lines: list[str] = []
    discarded_lines: list[str] = []
    for line in input_path.read_text(encoding="utf-8", errors="replace").splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            target_info = parse_target(candidate)
            _evaluate_target(target_info, policies, programs_dir)
            authorized_lines.append(candidate)
        except ScopeError:
            discarded_lines.append(candidate)

    if authorized_lines:
        _write_lf(authorized_out, "\n".join(authorized_lines) + "\n")
    if discarded_lines:
        _write_lf(discarded_out, "\n".join(discarded_lines) + "\n")
        if candidates_out is not None:
            existing: set[str] = set()
            if candidates_out.is_file():
                existing = {
                    item.strip()
                    for item in candidates_out.read_text(encoding="utf-8", errors="replace").splitlines()
                    if item.strip()
                }
            merged = sorted(existing | set(discarded_lines))
            _write_lf(candidates_out, "\n".join(merged) + "\n")


def _select_policies(policies: list[ProgramPolicy], program_filter: str | None) -> list[ProgramPolicy]:
    active = [p for p in policies if p.active]
    if not program_filter:
        return active
    wanted = program_filter.strip().lower()
    matched = [
        p
        for p in active
        if wanted in {p.path.stem.lower(), p.path.name.lower(), p.name.lower()}
    ]
    if not matched:
        raise ScopeError(f"no active program matching '{program_filter}'")
    return matched


def _rule_to_burp_host_regex(rule: ScopeRule) -> str:
    if rule.network is not None:
        net = rule.network
        if net.num_addresses == 1:
            return f"^{re.escape(str(net.network_address))}$"
        if net.version == 4:
            if net.prefixlen == 24:
                a, b, c, _ = str(net.network_address).split(".")
                return rf"^{a}\.{b}\.{c}\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$"
            if net.prefixlen == 16:
                a, b, _, _ = str(net.network_address).split(".")
                return rf"^{a}\.{b}\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$"
            if net.num_addresses <= 256:
                hosts = "|".join(re.escape(str(ip)) for ip in net)
                return f"^(?:{hosts})$"
        # Safe fallback for large IPv4/IPv6 blocks: escape network prefix up to last non-zero group
        return f"^{re.escape(str(net.network_address).split('/')[0])}"

    labels = rule.host_pattern.split(".")
    regex_parts: list[str] = []
    if labels[0] == "*":
        regex_parts.append(r"(?:[a-z0-9-]+\.)+")
        tail = labels[1:]
    else:
        tail = labels

    tail_regexes: list[str] = []
    for label in tail:
        if "*" in label:
            tail_regexes.append("[a-z0-9-]*".join(label.split("*")))
        else:
            tail_regexes.append(label)
    return "^" + "".join(regex_parts) + r"\.".join(tail_regexes) + "$"


def _rule_to_burp_item(rule: ScopeRule) -> dict[str, object]:
    protocol = "any"
    if rule.port == 443 and rule.scheme == "https":
        protocol = "https"
    elif rule.port == 80 and rule.scheme == "http":
        protocol = "http"

    item: dict[str, object] = {
        "enabled": True,
        "protocol": protocol,
        "host": _rule_to_burp_host_regex(rule),
    }
    if rule.port is not None:
        item["port"] = str(rule.port)
    if rule.path_prefix is not None:
        if rule.path_match_mode == "prefix":
            item["file"] = f"^{re.escape(rule.path_prefix)}.*"
        elif rule.path_prefix == "/":
            item["file"] = "^/.*"
        else:
            item["file"] = f"^{re.escape(rule.path_prefix)}(?:/.*)?$"
    return item


def export_burp_scope(policies: list[ProgramPolicy], program_filter: str | None = None) -> dict[str, object]:
    """Export active program rules in Burp Suite advanced_mode Target Scope JSON."""
    selected = _select_policies(policies, program_filter)
    include: list[dict[str, object]] = []
    exclude: list[dict[str, object]] = []
    seen_inc: set[str] = set()
    seen_exc: set[str] = set()

    for policy in selected:
        for rule in policy.in_rules:
            item = _rule_to_burp_item(rule)
            sig = json.dumps(item, sort_keys=True)
            if sig not in seen_inc:
                seen_inc.add(sig)
                include.append(item)

    # Always include exclusions from all programs so global Out-of-Scope safety holds.
    for policy in policies:
        for rule in policy.out_rules:
            item = _rule_to_burp_item(rule)
            sig = json.dumps(item, sort_keys=True)
            if sig not in seen_exc:
                seen_exc.add(sig)
                exclude.append(item)

    return {
        "target": {
            "scope": {
                "advanced_mode": True,
                "include": include,
                "exclude": exclude,
            }
        }
    }


def export_scope(
    programs_dir: Path,
    fmt: str,
    program_filter: str | None = None,
) -> str:
    """Export authorized program scope in burp, json, txt, domains, wildcards, or cidrs."""
    policies = load_program_policies(programs_dir)
    if fmt == "burp":
        return json.dumps(export_burp_scope(policies, program_filter), indent=2) + "\n"

    selected = _select_policies(policies, program_filter)
    if fmt == "json":
        payload = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
            "programs": [
                {
                    "name": p.name,
                    "file": p.path.name,
                    "platform": p.platform,
                    "handle": p.handle,
                    "status": p.status,
                    "last_review": p.last_review,
                    "research_headers": p.research_headers,
                    "rate_limit": p.rate_limit,
                    "in_scope": p.in_scope,
                    "out_scope": p.out_scope,
                }
                for p in selected
            ],
        }
        return json.dumps(payload, indent=2) + "\n"

    items: set[str] = set()
    for p in selected:
        for rule in p.in_rules:
            if fmt == "txt":
                items.add(rule.canonical)
            elif fmt == "domains" and rule.asset_class == "domains":
                items.add(rule.host_pattern)
            elif fmt == "wildcards" and rule.asset_class == "wildcards":
                items.add(rule.host_pattern)
            elif fmt == "cidrs" and rule.asset_class == "cidrs":
                items.add(rule.canonical)
    if not items:
        return ""
    return "\n".join(sorted(items)) + "\n"


def audit_programs(programs_dir: Path, max_age_days: int = 30) -> dict[str, object]:
    """Audit all programs/*.md for parse errors, staleness, metadata, and conflicts."""
    policies = load_program_policies(programs_dir, lenient=True)

    # Map active In-Scope rules vs all Out-of-Scope rules for cross-program conflict check
    all_out_rules: list[tuple[str, ScopeRule]] = []
    for p in policies:
        if p.parse_error is None:
            for r in p.out_rules:
                all_out_rules.append((p.path.name, r))

    results: list[dict[str, object]] = []
    parse_errors = 0
    stale_count = 0
    conflict_count = 0

    for p in policies:
        if p.parse_error:
            parse_errors += 1

        is_stale = bool(max_age_days > 0 and p.stale_days is not None and p.stale_days > max_age_days)
        missing_review = p.last_review is None
        if is_stale or missing_review:
            stale_count += 1

        counts = {"domains": 0, "wildcards": 0, "cidrs": 0}
        for r in p.in_rules:
            counts[r.asset_class] += 1

        conflicts: list[str] = []
        if p.active and p.parse_error is None:
            for r in p.in_rules:
                # Direct canonical or same-host collision against any Out-of-Scope rule
                for out_prog, out_r in all_out_rules:
                    if r.canonical == out_r.canonical or (
                        not r.leading_wildcard
                        and "*" not in r.host_pattern
                        and r.network is None
                        and _host_matches_rule(r.host_pattern, out_r)
                    ):
                        conflicts.append(f"{r.canonical} shadowed by out-of-scope '{out_r.canonical}' in {out_prog}")
        conflict_count += len(conflicts)

        results.append(
            {
                "file": p.path.name,
                "name": p.name,
                "platform": p.platform,
                "status": p.status,
                "active": p.active,
                "last_review": p.last_review,
                "stale_days": p.stale_days,
                "stale": is_stale,
                "missing_review": missing_review,
                "parse_error": p.parse_error,
                "in_scope_total": len(p.in_rules),
                "out_scope_total": len(p.out_rules),
                "counts": counts,
                "research_headers": p.research_headers,
                "rate_limit": p.rate_limit,
                "conflicts": conflicts,
            }
        )

    return {
        "programs_dir": str(programs_dir),
        "total_programs": len(policies),
        "active_programs": sum(1 for p in policies if p.active),
        "parse_errors": parse_errors,
        "stale_or_missing_review": stale_count,
        "conflicts_found": conflict_count,
        "programs": results,
    }


def _classify_import_items(
    raw_items: Iterable[tuple[str, str, bool, str]],
) -> tuple[list[str], list[str], list[str]]:
    """Split (identifier, asset_type, in_scope_flag, note) into in_lines, out_lines, notes."""
    in_lines: list[str] = []
    out_lines: list[str] = []
    notes: list[str] = []
    seen_in: set[str] = set()
    seen_out: set[str] = set()

    for ident, asset_type, is_in, note in raw_items:
        ident_clean = ident.strip()
        if not ident_clean:
            continue
        atype_upper = asset_type.strip().upper()
        if atype_upper in NON_NETWORK_ASSET_TYPES:
            notes.append(f"- [{atype_upper or 'NON_NET'}] `{ident_clean}`" + (f" — {note}" if note else ""))
            continue
        try:
            rule = parse_scope_rule(ident_clean)
        except ScopeError:
            notes.append(f"- [{atype_upper or 'MANUAL'}] `{ident_clean}`" + (f" — {note}" if note else ""))
            continue

        suffix = f" ({note})" if note else ""
        line = f"- {rule.canonical}{suffix}"
        if is_in:
            if rule.canonical not in seen_in:
                seen_in.add(rule.canonical)
                in_lines.append(line)
        else:
            if rule.canonical not in seen_out:
                seen_out.add(rule.canonical)
                out_lines.append(line)

    return in_lines, out_lines, notes


def _render_program_markdown(
    program_name: str,
    platform: str,
    handle: str,
    researcher: str,
    in_lines: list[str],
    out_lines: list[str],
    notes: list[str],
) -> str:
    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    in_block = "\n".join(in_lines) if in_lines else "- [None parsed — review policy manually]"
    out_block = "\n".join(out_lines) if out_lines else "- [None listed]"
    notes_block = "\n".join(notes) if notes else "Imported automatically; verify Special Rules and Excluded Vulnerability Types."

    return (
        f"# {program_name}\n\n"
        f"| Field | Value |\n"
        f"|-------|-------|\n"
        f"| **Platform** | {platform} |\n"
        f"| **H1 Handle** | {handle or program_name} |\n"
        f"| **Researcher** | {researcher} |\n"
        f"| **Status** | Active |\n"
        f"| **Type** | Public |\n"
        f"| **Last scope review** | {today} |\n\n"
        f"## In Scope\n\n"
        f"{in_block}\n\n"
        f"## Out of Scope\n\n"
        f"{out_block}\n\n"
        f"## Excluded Vulnerability Types\n\n"
        f"- [Verify program exclusions from policy page]\n\n"
        f"## Special Rules\n\n"
        f"- [Verify rate limits, required research headers, and test account rules]\n\n"
        f"## Submitted Reports\n\n"
        f"| Date | Title | Severity | Status | H1 URL |\n"
        f"|------|-------|----------|--------|--------|\n"
        f"|      |       |          |        |        |\n\n"
        f"## Notes\n\n"
        f"{notes_block}\n"
    )


def _parse_h1_csv_items(csv_path: Path) -> list[tuple[str, str, bool, str]]:
    items: list[tuple[str, str, bool, str]] = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            norm_row = {str(k).strip().lower(): (v or "").strip() for k, v in row.items() if k is not None}
            ident = (
                norm_row.get("identifier")
                or norm_row.get("asset_identifier")
                or norm_row.get("asset")
                or norm_row.get("target")
                or ""
            )
            atype = norm_row.get("asset_type") or norm_row.get("type") or ""
            sub_raw = norm_row.get("eligible_for_submission")
            if sub_raw is None:
                is_in = True
            else:
                is_in = sub_raw.lower() in {"true", "yes", "1"}
            bounty = norm_row.get("eligible_for_bounty", "")
            note_parts = []
            if bounty.lower() in {"false", "no", "0"} and is_in:
                note_parts.append("no-bounty / VDP asset")
            instr = norm_row.get("instruction", "").replace("\n", " ").strip()
            if instr:
                note_parts.append(instr[:120])
            items.append((ident, atype, is_in, "; ".join(note_parts)))
    return items


def _parse_json_scope_items(json_path: Path, program_hint: str | None) -> tuple[str, str, str, list[tuple[str, str, bool, str]]]:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    platform = "HackerOne"
    handle = program_hint or json_path.stem
    prog_name = program_hint or json_path.stem

    if isinstance(data, list):
        chosen = None
        if program_hint:
            hint_low = program_hint.lower()
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                if hint_low in {
                    str(entry.get("handle", "")).lower(),
                    str(entry.get("name", "")).lower(),
                    str(entry.get("id", "")).lower(),
                }:
                    chosen = entry
                    break
        elif len(data) == 1 and isinstance(data[0], dict):
            chosen = data[0]
        if chosen is None:
            raise ScopeError("JSON list contains multiple programs; specify --program-name matching handle or name")
        data = chosen

    if not isinstance(data, dict):
        raise ScopeError("unsupported JSON scope structure")

    prog_name = str(data.get("name") or data.get("program") or prog_name)
    handle = str(data.get("handle") or data.get("url") or handle)
    if "url" in data and isinstance(data["url"], str):
        u = data["url"].lower()
        if "bugcrowd" in u:
            platform = "Bugcrowd"
        elif "intigriti" in u:
            platform = "Intigriti"
        elif "yeswehack" in u:
            platform = "YesWeHack"
    elif "platform" in data:
        platform = str(data["platform"])

    targets_root = data.get("targets") if isinstance(data.get("targets"), dict) else data
    in_raw = targets_root.get("in_scope", [])
    out_raw = targets_root.get("out_of_scope", [])

    items: list[tuple[str, str, bool, str]] = []
    for is_in, entries in ((True, in_raw), (False, out_raw)):
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, str):
                items.append((entry, "", is_in, ""))
            elif isinstance(entry, dict):
                ident = str(
                    entry.get("asset_identifier")
                    or entry.get("target")
                    or entry.get("endpoint")
                    or entry.get("asset")
                    or entry.get("value")
                    or entry.get("id")
                    or ""
                )
                atype = str(entry.get("asset_type") or entry.get("type") or entry.get("category") or "")
                note_parts = []
                if is_in and entry.get("eligible_for_bounty") is False:
                    note_parts.append("no-bounty")
                if entry.get("reason"):
                    note_parts.append(str(entry["reason"]))
                items.append((ident, atype, is_in, "; ".join(note_parts)))
    return prog_name, platform, handle, items


def _parse_txt_scope_items(in_txt: Path, out_txt: Path | None) -> list[tuple[str, str, bool, str]]:
    items: list[tuple[str, str, bool, str]] = []
    for line in in_txt.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            items.append((s, "", True, ""))
    if out_txt is not None and out_txt.is_file():
        for line in out_txt.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                items.append((s, "", False, ""))
    return items


def _load_source_sets(source: Path) -> tuple[set[str], set[str]]:
    suffix = source.suffix.lower()
    if suffix == ".md":
        in_list, out_list = read_sections(source)
        return set(in_list), set(out_list)
    if suffix == ".csv":
        raw_items = _parse_h1_csv_items(source)
    elif suffix == ".json":
        _, _, _, raw_items = _parse_json_scope_items(source, None)
    else:
        raw_items = _parse_txt_scope_items(source, None)

    in_set: set[str] = set()
    out_set: set[str] = set()
    for ident, atype, is_in, _ in raw_items:
        if atype.strip().upper() in NON_NETWORK_ASSET_TYPES:
            continue
        try:
            canon = parse_scope_rule(ident).canonical
        except ScopeError:
            continue
        (in_set if is_in else out_set).add(canon)
    return in_set, out_set


def diff_scope_sources(old_path: Path, new_path: Path) -> dict[str, list[str]]:
    """Compute ADDED/REMOVED rules between two scope sources (.md/.csv/.json/.txt)."""
    old_in, old_out = _load_source_sets(old_path)
    new_in, new_out = _load_source_sets(new_path)
    return {
        "in_scope_added": sorted(new_in - old_in),
        "in_scope_removed": sorted(old_in - new_in),
        "out_of_scope_added": sorted(new_out - old_out),
        "out_of_scope_removed": sorted(old_out - new_out),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?")
    parser.add_argument("target_extra", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument(
        "--programs-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "programs",
    )
    parser.add_argument("--normalize", action="store_true", help="validate and print only the normalized host")
    parser.add_argument("--explain", action="store_true", help="explain scope verdict for a target")
    parser.add_argument("--policy-json", action="store_true", help="authorize target and print program policy JSON")
    parser.add_argument("--audit", action="store_true", help="audit all programs/*.md files")
    parser.add_argument("--max-age-days", type=int, default=30, help="review age threshold for --audit")
    parser.add_argument("--json", action="store_true", help="output JSON for --explain, --audit, or --diff")

    parser.add_argument(
        "--export",
        choices=["burp", "json", "txt", "domains", "wildcards", "cidrs"],
        help="export active scope in the requested format",
    )
    parser.add_argument("--program", help="filter --export to one program file/name")
    parser.add_argument("--output", type=Path, help="output file path for --export or --import-*")

    parser.add_argument("--import-h1-csv", type=Path, help="convert HackerOne CSV export to program Markdown")
    parser.add_argument("--import-json", type=Path, help="convert bounty-targets/JSON scope to program Markdown")
    parser.add_argument("--import-txt", type=Path, help="convert line-delimited in-scope file to program Markdown")
    parser.add_argument("--out-txt", type=Path, help="optional out-of-scope file used with --import-txt")
    parser.add_argument("--program-name", help="program name/handle override for imports")
    parser.add_argument("--platform", default="HackerOne", help="platform name for imports")
    parser.add_argument("--researcher", default=os.environ.get("BB_RESEARCHER", "dev101x"))

    parser.add_argument("--diff", nargs=2, metavar=("OLD_FILE", "NEW_FILE"), help="diff two scope files")

    parser.add_argument("--filter-file", type=Path, help="filter a file of candidate targets in batch")
    parser.add_argument("--authorized-out", type=Path, help="output path for authorized targets")
    parser.add_argument("--discarded-out", type=Path, help="output path for discarded targets")
    parser.add_argument("--candidates-out", type=Path, help="sorted deduplicated file for pending candidates")
    args = parser.parse_args()

    try:
        if args.audit:
            report = audit_programs(args.programs_dir, max_age_days=args.max_age_days)
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print(
                    f"Scope audit: {report['total_programs']} program(s) "
                    f"({report['active_programs']} active), "
                    f"{report['parse_errors']} parse error(s), "
                    f"{report['stale_or_missing_review']} stale/unreviewed, "
                    f"{report['conflicts_found']} conflict(s)"
                )
                for p in report["programs"]:
                    counts = p["counts"]
                    status_tag = "ACTIVE" if p["active"] else f"INACTIVE:{p['status']}"
                    review_tag = p["last_review"] or "missing"
                    if p["stale"]:
                        review_tag += f" (stale {p['stale_days']}d)"
                    print(
                        f"  - {p['file']} [{status_tag}] review={review_tag} "
                        f"in={p['in_scope_total']} (dom={counts['domains']}, wc={counts['wildcards']}, cidr={counts['cidrs']}) "
                        f"out={p['out_scope_total']} "
                        f"hdr={'yes' if p['research_headers'] else 'no'} "
                        f"rl={p['rate_limit'] if p['rate_limit'] is not None else 'default'}"
                    )
                    if p["parse_error"]:
                        print(f"      PARSE ERROR: {p['parse_error']}")
                    for c in p["conflicts"]:
                        print(f"      CONFLICT: {c}")
            return 1 if report["parse_errors"] > 0 else 0

        if args.export is not None:
            rendered = export_scope(args.programs_dir, args.export, args.program)
            if args.output is not None:
                _write_lf(args.output, rendered)
            else:
                sys.stdout.write(rendered)
            return 0

        if args.import_h1_csv or args.import_json or args.import_txt:
            if args.import_h1_csv:
                raw_items = _parse_h1_csv_items(args.import_h1_csv)
                prog_name = args.program_name or args.import_h1_csv.stem
                platform = args.platform
                handle = prog_name
            elif args.import_json:
                prog_name, platform, handle, raw_items = _parse_json_scope_items(args.import_json, args.program_name)
                if args.platform != "HackerOne":
                    platform = args.platform
            else:
                assert args.import_txt is not None
                raw_items = _parse_txt_scope_items(args.import_txt, args.out_txt)
                prog_name = args.program_name or args.import_txt.stem
                platform = args.platform
                handle = prog_name

            in_lines, out_lines, notes = _classify_import_items(raw_items)
            md = _render_program_markdown(prog_name, platform, handle, args.researcher, in_lines, out_lines, notes)
            if args.output is not None:
                _write_lf(args.output, md)
            else:
                sys.stdout.write(md)
            return 0

        if args.diff is not None:
            diff = diff_scope_sources(Path(args.diff[0]), Path(args.diff[1]))
            if args.json:
                print(json.dumps(diff, indent=2))
            else:
                print("== In Scope Diff ==")
                for item in diff["in_scope_added"]:
                    print(f"  + {item}")
                for item in diff["in_scope_removed"]:
                    print(f"  - {item}")
                if not diff["in_scope_added"] and not diff["in_scope_removed"]:
                    print("  (no changes)")
                print("== Out of Scope Diff ==")
                for item in diff["out_of_scope_added"]:
                    print(f"  + {item}")
                for item in diff["out_of_scope_removed"]:
                    print(f"  - {item}")
                if not diff["out_of_scope_added"] and not diff["out_of_scope_removed"]:
                    print("  (no changes)")
            return 0

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
            parser.error("target is required unless --audit, --export, --import-*, --diff, or --filter-file is used")

        if args.explain:
            verdict = explain_target(args.target, args.programs_dir)
            if args.json:
                print(json.dumps(verdict, indent=2))
            else:
                status_word = "AUTHORIZED" if verdict["authorized"] else "DENIED"
                print(f"Verdict : {status_word}")
                print(f"Target  : {verdict['target']}")
                if verdict.get("host"):
                    print(f"Host    : {verdict['host']}")
                print(f"Reason  : {verdict['reason']}")
                if verdict["authorized"]:
                    print(f"Program : {verdict['program_name']} ({Path(str(verdict['program_file'])).name})")
                    print(f"Platform: {verdict['platform']} | Status: {verdict['status']} | Review: {verdict['last_review'] or 'unknown'}")
                    print(f"Headers : {', '.join(verdict['research_headers']) or 'none'}")
                    print(f"RateLim : {verdict['rate_limit'] if verdict['rate_limit'] is not None else 'default'} req/s")
            return 0 if verdict["authorized"] else 1

        if args.policy_json:
            target_info = parse_target(args.target)
            policies = load_program_policies(args.programs_dir)
            policy, rule = _evaluate_target(target_info, policies, args.programs_dir)
            _emit_stale_warning_if_needed(policy)
            payload = {
                "host": target_info.host,
                "program_file": str(policy.path),
                "program_name": policy.name,
                "platform": policy.platform,
                "status": policy.status,
                "last_review": policy.last_review,
                "matched_rule": rule.canonical,
                "research_header": policy.research_headers[0] if policy.research_headers else "",
                "research_headers": policy.research_headers,
                "rate_limit": policy.rate_limit,
            }
            print(json.dumps(payload, separators=(",", ":")))
            return 0

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
