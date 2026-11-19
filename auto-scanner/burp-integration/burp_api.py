#!/usr/bin/env python3
"""
Burp Suite API Integration
==========================
Wrapper to interact with Burp Suite through its REST API.

Requirements:
- Burp Suite Professional or Community
- API enabled: Burp -> Settings -> Burp API -> Enable
- Default port: 1337

Usage:
    python3 burp_api.py <command> [options]

Commands:
    status          - Burp status
    proxy           - Enable/disable proxy
    target <url>    - Add URL to target scope
    scan <url>      - Active scan
    spider <url>    - Spider site
    sitemap         - View sitemap
    issues          - View findings
    export          - Export findings
    intruder        - Configure Intruder
    repeater        - Send to Repeater
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from scope_guard import ScopeError, authorize  # noqa: E402

BURP_HOST = os.environ.get("BURP_HOST", "localhost")
BURP_PORT = int(os.environ.get("BURP_PORT", "1337"))
BURP_API_KEY = os.environ.get("BURP_API_KEY", "")
DEFAULT_TIMEOUT = 30
PROGRAMS_DIR = REPO_ROOT / "programs"


def require_authorized(url: str) -> str:
    host, _ = authorize(url, PROGRAMS_DIR)
    return host


class BurpAPI:
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        api_key: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        resolved_host = host if host is not None else os.environ.get("BURP_HOST", BURP_HOST)
        resolved_port = port if port is not None else int(os.environ.get("BURP_PORT", str(BURP_PORT)))
        resolved_key = api_key if api_key is not None else os.environ.get("BURP_API_KEY", BURP_API_KEY)
        self.base_url = f"http://{resolved_host}:{resolved_port}"
        self.api_key = resolved_key
        self.timeout = timeout
        self.headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            self.headers["Burp-API-Key"] = self.api_key

    def _request(self, method: str, path: str, data: Optional[Dict] = None) -> Dict:
        """Send an HTTP request to the Burp Suite REST API."""
        url = f"{self.base_url}{path}"

        try:
            req = urllib.request.Request(url, method=method, headers=self.headers)
            if data:
                req.data = json.dumps(data).encode("utf-8")

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def get(self, path: str) -> Dict:
        return self._request("GET", path)

    def post(self, path: str, data: Dict) -> Dict:
        return self._request("POST", path, data)

    def put(self, path: str, data: Dict) -> Dict:
        return self._request("PUT", path, data)

    def delete(self, path: str) -> Dict:
        return self._request("DELETE", path)

    # ============================================
    # API METHODS
    # ============================================

    def status(self) -> Dict:
        """Get Burp API status."""
        return self.get("/burp/api")

    def get_version(self) -> Dict:
        """Get Burp version."""
        return self.get("/burp/api/version")

    def get_project_options(self) -> Dict:
        """Get current project options."""
        return self.get("/burp/api/project-options")

    def get_proxy_listeners(self) -> Dict:
        """Get proxy listeners."""
        return self.get("/burp/api/proxy/listeners")

    def set_proxy_enabled(self, enabled: bool) -> Dict:
        """Enable or disable the proxy listener."""
        return self.put(
            "/burp/api/proxy/listeners/http",
            {
                "requestEnabled": enabled,
                "responseEnabled": enabled,
            },
        )

    def get_proxy_history(self) -> Dict:
        """Get HTTP proxy history."""
        return self.get("/burp/api/proxy/http")

    def add_to_target(self, url: str) -> Dict:
        """Add an authorized URL to target scope."""
        host = require_authorized(url)
        parsed = urllib.parse.urlsplit(url if "://" in url else f"https://{url}")
        return self.post(
            "/burp/api/target/scope",
            {
                "include": True,
                "protocol": parsed.scheme,
                "host": host,
                "port": parsed.port or -1,
                "file": ".*",
            },
        )

    def get_target_scope(self) -> Dict:
        """Get target scope configuration."""
        return self.get("/burp/api/target/scope")

    def start_spider(self, url: str) -> Dict:
        """Start spidering an authorized URL."""
        require_authorized(url)
        return self.post(
            "/burp/api/spider",
            {
                "url": url,
                "maxDepth": 0,
                "maxPostDepth": 0,
                "threadCount": 10,
            },
        )

    def get_spider_status(self) -> Dict:
        """Get spider status."""
        return self.get("/burp/api/spider")

    def get_spider_urls(self) -> Dict:
        """Get spidered URLs."""
        return self.get("/burp/api/spider/web-pages")

    def start_scan(self, urls: list) -> Dict:
        """Start an active scan against authorized URLs."""
        for url in urls:
            require_authorized(url)
        return self.post(
            "/burp/api/scans",
            {
                "scanConfiguration": ["active"],
                "targets": [{"url": url, "type": "baseUrl"} for url in urls],
            },
        )

    def get_scan_status(self) -> Dict:
        """Get active scan status."""
        return self.get("/burp/api/scans")

    def get_scan_results(self, scan_id: str) -> Dict:
        """Get active scan results."""
        return self.get(f"/burp/api/scans/{scan_id}")

    def get_issues(self) -> Dict:
        """Get detected issues."""
        return self.get("/burp/api/project/issues")

    def get_issue_details(self, issue_id: str) -> Dict:
        """Get issue details."""
        return self.get(f"/burp/api/project/issues/{issue_id}")

    def export_issues(self, format: str = "json") -> Dict:
        """Export detected issues."""
        return self.post("/burp/api/project/export", {"format": format})

    def send_to_repeater(self, request: Dict) -> Dict:
        """Send an authorized request to Repeater."""
        require_authorized(str(request.get("url", "")))
        return self.post("/burp/api/repeater", request)

    def get_repeater_tabs(self) -> Dict:
        """Get Repeater tabs."""
        return self.get("/burp/api/repeater")

    def send_to_intruder(self, request: Dict) -> Dict:
        """Send an authorized request to Intruder."""
        require_authorized(str(request.get("url", "")))
        return self.post("/burp/api/intruder", request)


def main() -> None:
    parser = argparse.ArgumentParser(description="Burp Suite API Client")
    parser.add_argument("--host", default=os.environ.get("BURP_HOST", BURP_HOST), help="Burp host")
    parser.add_argument("--port", type=int, default=int(os.environ.get("BURP_PORT", str(BURP_PORT))), help="Burp API port")
    parser.add_argument("--api-key", default=os.environ.get("BURP_API_KEY", BURP_API_KEY), help="API key")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP request timeout in seconds")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("status", help="Burp status")
    subparsers.add_parser("version", help="Burp version")

    proxy_parser = subparsers.add_parser("proxy", help="Configure proxy")
    proxy_parser.add_argument("--enable", action="store_true", help="Enable proxy")
    proxy_parser.add_argument("--disable", action="store_true", help="Disable proxy")
    proxy_parser.add_argument("--history", action="store_true", help="View proxy history")

    target_parser = subparsers.add_parser("target", help="Manage target scope")
    target_parser.add_argument("action", choices=["add", "scope", "list"])
    target_parser.add_argument("url", nargs="?", help="URL to add")

    spider_parser = subparsers.add_parser("spider", help="Manage spider")
    spider_parser.add_argument("action", choices=["start", "status", "urls"])
    spider_parser.add_argument("url", nargs="?", help="URL to crawl")

    scan_parser = subparsers.add_parser("scan", help="Run active scan")
    scan_parser.add_argument("action", choices=["start", "status", "results"])
    scan_parser.add_argument("target", nargs="?", help="Target URL or scan ID")

    issues_parser = subparsers.add_parser("issues", help="Manage findings")
    issues_parser.add_argument("action", choices=["list", "details", "export"])
    issues_parser.add_argument("id", nargs="?", help="Issue ID")

    repeater_parser = subparsers.add_parser("repeater", help="Send request to Repeater")
    repeater_parser.add_argument("--url", required=True)
    repeater_parser.add_argument("--method", default="GET")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    api = BurpAPI(args.host, args.port, args.api_key, timeout=args.timeout)

    print(f"\n{'='*50}")
    print(f"Burp Suite API - {args.command.upper()}")
    print(f"{'='*50}\n")

    try:
        if args.command == "status":
            result = api.status()
        elif args.command == "version":
            result = api.get_version()
        elif args.command == "proxy":
            if args.enable:
                result = api.set_proxy_enabled(True)
            elif args.disable:
                result = api.set_proxy_enabled(False)
            elif args.history:
                result = api.get_proxy_history()
            else:
                result = api.get_proxy_listeners()
        elif args.command == "target":
            if args.action == "add" and args.url:
                result = api.add_to_target(args.url)
            else:
                result = api.get_target_scope()
        elif args.command == "spider":
            if args.action == "start" and args.url:
                result = api.start_spider(args.url)
            elif args.action == "urls":
                result = api.get_spider_urls()
            else:
                result = api.get_spider_status()
        elif args.command == "scan":
            if args.action == "start" and args.target:
                result = api.start_scan([args.target])
            elif args.action == "results" and args.target:
                result = api.get_scan_results(args.target)
            else:
                result = api.get_scan_status()
        elif args.command == "issues":
            if args.action == "details" and args.id:
                result = api.get_issue_details(args.id)
            elif args.action == "export":
                result = api.export_issues()
            else:
                result = api.get_issues()
        elif args.command == "repeater":
            result = api.send_to_repeater(
                {
                    "url": args.url,
                    "method": args.method,
                    "headers": "",
                    "body": "",
                }
            )

        print(json.dumps(result, indent=2))

    except ScopeError as e:
        print(f"\nScope denied: {e}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
