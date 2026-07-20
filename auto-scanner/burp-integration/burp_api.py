#!/usr/bin/env python3
"""
Burp Suite API Integration
==========================
Wrapper para interactuar con Burp Suite a través de su API REST.

Requisitos:
- Burp Suite Professional o Community
- API habilitada: Burp → Settings → Burp API → Enable
- Puerto por defecto: 1337

Uso:
    python3 burp_api.py <comando> [opciones]

Comandos:
    status          - Estado de Burp
    proxy           - Habilitar/deshabilitar proxy
    target <url>    - Agregar URL al target
    scan <url>      - Escaneo activo
    spider <url>    - Spider del sitio
    sitemap         - Ver sitemap
    issues          - Ver hallazgos
    export          - Exportar hallazgos
    intruder        - Configurar Intruder
    repeater        - Enviar a Repeater
"""

import sys
import json
import urllib.request
import urllib.error
import urllib.parse
import argparse
from pathlib import Path
from typing import Optional, Dict, Any

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from scope_guard import ScopeError, authorize  # noqa: E402

# Configuración por defecto
BURP_HOST = "localhost"
BURP_PORT = 1337
BURP_API_KEY = ""  # Configurar si es necesario
PROGRAMS_DIR = REPO_ROOT / "programs"


def require_authorized(url: str) -> str:
    host, _ = authorize(url, PROGRAMS_DIR)
    return host

class BurpAPI:
    def __init__(self, host: str = BURP_HOST, port: int = BURP_PORT, api_key: str = ""):
        self.base_url = f"http://{host}:{port}"
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json",
        }
        if api_key:
            self.headers["Burp-API-Key"] = api_key
    
    def _request(self, method: str, path: str, data: Optional[Dict] = None) -> Dict:
        """Realizar petición a la API de Burp"""
        url = f"{self.base_url}{path}"
        
        try:
            req = urllib.request.Request(url, method=method, headers=self.headers)
            if data:
                req.data = json.dumps(data).encode('utf-8')
            
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode('utf-8'))
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
    # MÉTODOS DE LA API
    # ============================================
    
    def status(self) -> Dict:
        """Obtener estado de Burp"""
        return self.get("/burp/api")
    
    def get_version(self) -> Dict:
        """Obtener versión de Burp"""
        return self.get("/burp/api/version")
    
    def get_project_options(self) -> Dict:
        """Obtener opciones del proyecto"""
        return self.get("/burp/api/project-options")
    
    def get_proxy_listeners(self) -> Dict:
        """Obtener listeners del proxy"""
        return self.get("/burp/api/proxy/listeners")
    
    def set_proxy_enabled(self, enabled: bool) -> Dict:
        """Habilitar/deshabilitar proxy"""
        return self.put("/burp/api/proxy/listeners/http", {
            "requestEnabled": enabled,
            "responseEnabled": enabled
        })
    
    def get_proxy_history(self) -> Dict:
        """Obtener historial del proxy"""
        return self.get("/burp/api/proxy/http")
    
    def add_to_target(self, url: str) -> Dict:
        """Agregar URL al target scope"""
        host = require_authorized(url)
        parsed = urllib.parse.urlsplit(url if "://" in url else f"https://{url}")
        return self.post("/burp/api/target/scope", {
            "include": True,
            "protocol": parsed.scheme,
            "host": host,
            "port": parsed.port or -1,
            "file": ".*"
        })
    
    def get_target_scope(self) -> Dict:
        """Obtener scope del target"""
        return self.get("/burp/api/target/scope")
    
    def start_spider(self, url: str) -> Dict:
        """Iniciar spider"""
        require_authorized(url)
        return self.post("/burp/api/spider", {
            "url": url,
            "maxDepth": 0,
            "maxPostDepth": 0,
            "threadCount": 10
        })
    
    def get_spider_status(self) -> Dict:
        """Obtener estado del spider"""
        return self.get("/burp/api/spider")
    
    def get_spider_urls(self) -> Dict:
        """Obtener URLs del spider"""
        return self.get("/burp/api/spider/web-pages")
    
    def start_scan(self, urls: list) -> Dict:
        """Iniciar escaneo activo"""
        for url in urls:
            require_authorized(url)
        return self.post("/burp/api/scans", {
            "scanConfiguration": ["active"],
            "targets": [{"url": url, "type": "baseUrl"} for url in urls]
        })
    
    def get_scan_status(self) -> Dict:
        """Obtener estado del escaneo"""
        return self.get("/burp/api/scans")
    
    def get_scan_results(self, scan_id: str) -> Dict:
        """Obtener resultados del escaneo"""
        return self.get(f"/burp/api/scans/{scan_id}")
    
    def get_issues(self) -> Dict:
        """Obtener hallazgos"""
        return self.get("/burp/api/project/issues")
    
    def get_issue_details(self, issue_id: str) -> Dict:
        """Obtener detalles de un hallazgo"""
        return self.get(f"/burp/api/project/issues/{issue_id}")
    
    def export_issues(self, format: str = "json") -> Dict:
        """Exportar hallazgos"""
        return self.post("/burp/api/project/export", {
            "format": format
        })
    
    def send_to_repeater(self, request: Dict) -> Dict:
        """Enviar petición a Repeater"""
        require_authorized(str(request.get("url", "")))
        return self.post("/burp/api/repeater", request)
    
    def get_repeater_tabs(self) -> Dict:
        """Obtener tabs de Repeater"""
        return self.get("/burp/api/repeater")
    
    def send_to_intruder(self, request: Dict) -> Dict:
        """Enviar petición a Intruder"""
        require_authorized(str(request.get("url", "")))
        return self.post("/burp/api/intruder", request)

def main():
    parser = argparse.ArgumentParser(description="Burp Suite API Client")
    parser.add_argument("--host", default=BURP_HOST, help="Burp host")
    parser.add_argument("--port", type=int, default=BURP_PORT, help="Burp API port")
    parser.add_argument("--api-key", default=BURP_API_KEY, help="API key")
    
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponibles")
    
    # Status
    subparsers.add_parser("status", help="Estado de Burp")
    subparsers.add_parser("version", help="Versión de Burp")
    
    # Proxy
    proxy_parser = subparsers.add_parser("proxy", help="Configurar proxy")
    proxy_parser.add_argument("--enable", action="store_true", help="Habilitar proxy")
    proxy_parser.add_argument("--disable", action="store_true", help="Deshabilitar proxy")
    proxy_parser.add_argument("--history", action="store_true", help="Ver historial")
    
    # Target
    target_parser = subparsers.add_parser("target", help="Gestionar target")
    target_parser.add_argument("action", choices=["add", "scope", "list"])
    target_parser.add_argument("url", nargs="?", help="URL a agregar")
    
    # Spider
    spider_parser = subparsers.add_parser("spider", help="Gestionar spider")
    spider_parser.add_argument("action", choices=["start", "status", "urls"])
    spider_parser.add_argument("url", nargs="?", help="URL a crawlear")
    
    # Scan
    scan_parser = subparsers.add_parser("scan", help="Escanear")
    scan_parser.add_argument("action", choices=["start", "status", "results"])
    scan_parser.add_argument("target", nargs="?", help="URL o scan ID")
    
    # Issues
    issues_parser = subparsers.add_parser("issues", help="Gestionar hallazgos")
    issues_parser.add_argument("action", choices=["list", "details", "export"])
    issues_parser.add_argument("id", nargs="?", help="Issue ID")
    
    # Repeater
    repeater_parser = subparsers.add_parser("repeater", help="Enviar a Repeater")
    repeater_parser.add_argument("--url", required=True)
    repeater_parser.add_argument("--method", default="GET")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    api = BurpAPI(args.host, args.port, args.api_key)
    
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
            elif args.action == "scope":
                result = api.get_target_scope()
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
            result = api.send_to_repeater({
                "url": args.url,
                "method": args.method,
                "headers": "",
                "body": ""
            })
        
        print(json.dumps(result, indent=2))
        
    except ScopeError as e:
        print(f"\nScope denied: {e}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        raise SystemExit(1)

if __name__ == "__main__":
    main()
