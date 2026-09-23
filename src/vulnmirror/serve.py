"""`vulnmirror serve`: a read-only JSON API over the mirror, on the standard library HTTP server.

Each request opens its own read-only connection, so a concurrent `update` or `build` is picked
up by the next request without restarting. Bind to loopback (the default) or put the server
behind a reverse proxy for TLS and rate limiting when exposing it.
"""

import hmac
import ipaddress
import json
import re
import sqlite3
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import parse_qs, urlsplit

from vulnmirror import api
from vulnmirror.config import Paths


def _version() -> str:
    try:
        return version("vulnmirror")
    except PackageNotFoundError:
        return "unknown"


@dataclass(frozen=True)
class Settings:
    paths: Paths
    token: str | None = None
    cors_origin: str | None = None
    max_limit: int = 1000
    timeout_s: float = 30.0


ROUTES = [
    (re.compile(r"^/healthz$"), "healthz"),
    (re.compile(r"^/$"), "index"),
    (re.compile(r"^/openapi\.json$"), "openapi"),
    (re.compile(r"^/v1/status$"), "status"),
    (re.compile(r"^/v1/cve/(?P<id>[^/]{1,64})$"), "cve"),
    (re.compile(r"^/v1/ghsa/(?P<id>[^/]{1,64})$"), "ghsa"),
    (re.compile(r"^/v1/search/cves$"), "search"),
]
PUBLIC = {"healthz"}  # reachable without a token


def route(path: str):
    """(route name, match) for a URL path, or (None, None)."""
    for pattern, name in ROUTES:
        m = pattern.match(path)
        if m:
            return name, m
    return None, None


def openapi() -> dict:
    def op(summary, params=(), path_id=None):
        parameters = [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}] if path_id else []
        parameters += [{"name": n, "in": "query", "schema": s, "description": d} for n, s, d in params]
        return {
            "get": {
                "summary": summary,
                "parameters": parameters,
                "responses": {
                    "200": {"description": "OK"},
                    "400": {"description": "invalid request"},
                    "404": {"description": "not found"},
                    "504": {"description": "query timeout"},
                },
            }
        }

    text = {"type": "string"}
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "vulnmirror",
            "version": _version(),
            "description": "Read-only API over a local mirror of CVE, NVD, KEV and GHSA metadata. "
            "Every response carries the snapshot it was read from.",
        },
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/healthz": op("liveness check (no token needed)"),
            "/v1/status": op("sync markers and row counts"),
            "/v1/cve/{id}": op("everything the mirror holds about one CVE", path_id=True),
            "/v1/ghsa/{id}": op("one GitHub advisory with aliases, packages, references and CWEs", path_id=True),
            "/v1/search/cves": op(
                "CVEs by vendor / product / CPE part / publication window, paginated",
                [
                    ("vendor", text, "case-insensitive substring; repeatable"),
                    ("product_like", text, "SQL LIKE pattern on the product name"),
                    ("cpe_part", {"enum": ["a", "o", "h"]}, "restrict to NVD CPE matches of this part"),
                    ("cpe_scope", {"enum": ["vulnerable", "any"]}, "'any' also matches non-vulnerable platform CPEs"),
                    ("from", {"type": "string", "format": "date"}, "earliest publication date"),
                    ("to", {"type": "string", "format": "date"}, "latest publication date"),
                    ("state", {"enum": ["PUBLISHED", "REJECTED"]}, "default PUBLISHED"),
                    ("limit", {"type": "integer"}, "page size, default 100"),
                    ("offset", {"type": "integer"}, "default 0"),
                ],
            ),
        },
    }


def make_handler(settings: Settings):
    token = settings.token.encode() if settings.token else None

    class Handler(BaseHTTPRequestHandler):
        server_version = f"vulnmirror/{_version()}"
        sys_version = ""

        def do_GET(self):
            self._handle(body=True)

        def do_HEAD(self):
            self._handle(body=False)

        def do_OPTIONS(self):
            self.send_response(204)
            self._common_headers()
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _refuse(self):
            self._send(
                405,
                {"error": "the API is read-only: only GET and HEAD are allowed"},
                True,
                extra={"Allow": "GET, HEAD, OPTIONS"},
            )

        do_POST = do_PUT = do_PATCH = do_DELETE = _refuse

        def _common_headers(self):
            if settings.cors_origin:
                self.send_header("Access-Control-Allow-Origin", settings.cors_origin)
            self.send_header("X-Content-Type-Options", "nosniff")

        def _send(self, status: int, payload: dict, body: bool, extra: dict | None = None):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self._common_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(data)

        def _authorized(self) -> bool:
            if token is None:
                return True
            header = self.headers.get("Authorization", "")
            scheme, _, given = header.partition(" ")
            return scheme.lower() == "bearer" and hmac.compare_digest(given.strip().encode(), token)

        def _handle(self, body: bool):
            url = urlsplit(self.path)
            name, m = route(url.path)
            if name is None:
                return self._send(404, {"error": f"no such endpoint: {url.path[:100]}"}, body)
            if name not in PUBLIC and not self._authorized():
                return self._send(
                    401, {"error": "missing or wrong bearer token"}, body, extra={"WWW-Authenticate": "Bearer"}
                )
            try:
                self._send(200, self._dispatch(name, m, parse_qs(url.query, keep_blank_values=True)), body)
            except api.ApiError as e:
                self._send(e.status, {"error": e.message}, body)
            except sqlite3.OperationalError as e:
                if "interrupted" in str(e):
                    self._send(504, {"error": f"query exceeded the {settings.timeout_s:g} s limit; narrow it"}, body)
                else:
                    self.log_error("database error: %s", e)
                    self._send(500, {"error": "database error"}, body)
            except Exception as e:  # never drop the connection without an answer; details stay in the log
                self.log_error("internal error: %r", e)
                self._send(500, {"error": "internal error"}, body)

        def _dispatch(self, name: str, m, params: dict) -> dict:
            if name == "healthz":
                return {"ok": True}
            if name == "openapi":
                return openapi()
            if name == "index":
                return {
                    "name": "vulnmirror",
                    "version": _version(),
                    "openapi": "/openapi.json",
                    "endpoints": [p for p in openapi()["paths"]],
                }
            if params and name != "search":
                raise api.ApiError(400, f"{url_name(name)} takes no query parameters")
            db = api.connect(settings.paths.db, settings.timeout_s)
            try:
                if name == "status":
                    return api.status(db)
                if name == "cve":
                    return api.cve(db, m["id"])
                if name == "ghsa":
                    return api.ghsa(db, m["id"])
                return api.search_cves(db, params, settings.max_limit)
            finally:
                db.close()

        def log_message(self, fmt, *args):
            sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")

    return Handler


def url_name(route: str) -> str:
    return {"status": "/v1/status", "cve": "/v1/cve/{id}", "ghsa": "/v1/ghsa/{id}"}.get(route, route)


def is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return host == "localhost"
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_server(settings: Settings, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(settings))
    server.daemon_threads = True
    return server
