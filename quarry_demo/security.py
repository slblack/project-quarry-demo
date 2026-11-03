"""Request hardening for a single-user localhost demo."""

from __future__ import annotations

import hmac
import ipaddress
import secrets
from typing import Iterable

from flask import Flask, Response, jsonify, request

LOOPBACK_HOSTNAMES = {"localhost", "127.0.0.1", "[::1]", "::1"}

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


def _hostname(host_header: str) -> str:
    host = host_header.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        return host[: end + 1] if end != -1 else host
    return host.rsplit(":", 1)[0] if ":" in host else host


def _valid_port(host_header: str) -> bool:
    host = host_header.strip()
    if host.startswith("["):
        rest = host[host.find("]") + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    else:
        port = host.rsplit(":", 1)[1] if ":" in host else ""
    return port == "" or (port.isdigit() and 0 < int(port) < 65536)


def host_allowed(host_header: str | None, extra_hosts: Iterable[str]) -> bool:
    """Defends against DNS rebinding: only loopback names (any port) plus explicit extras."""
    if not host_header or len(host_header) > 255 or not _valid_port(host_header):
        return False
    name = _hostname(host_header)
    return name in LOOPBACK_HOSTNAMES or name in {h.strip().lower() for h in extra_hosts if h.strip()}


def is_loopback_bind(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def install(app: Flask, extra_hosts: Iterable[str] = ()) -> str:
    """Install guards; returns the per-process CSRF token embedded in the page."""
    token = secrets.token_urlsafe(32)
    extra = tuple(extra_hosts)

    def error(status: int, message: str) -> Response:
        resp = jsonify({"ok": False, "error": {"code": "request_rejected", "message": message}})
        resp.status_code = status
        return resp

    @app.before_request
    def _guard():
        if not host_allowed(request.headers.get("Host"), extra):
            return error(400, "Invalid Host header.")
        if request.method == "OPTIONS":
            # No CORS: preflights are refused, so cross-origin custom-header requests never proceed.
            return error(403, "Cross-origin requests are not permitted.")
        path = request.path
        if not path.startswith("/api/"):
            return None
        fetch_site = request.headers.get("Sec-Fetch-Site")
        if fetch_site and fetch_site not in ("same-origin", "none"):
            return error(403, "Cross-origin requests are not permitted.")
        origin = request.headers.get("Origin")
        if origin is not None and origin != f"{request.scheme}://{request.host}":
            return error(403, "Cross-origin requests are not permitted.")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(supplied.encode(), token.encode()):
            return error(403, "Missing or invalid CSRF token. Reload the page.")
        if request.method == "POST":
            ctype = (request.mimetype or "").lower()
            if ctype != "application/json":
                return error(415, "Requests must be JSON.")
        return None

    @app.after_request
    def _headers(resp: Response) -> Response:
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers.pop("Access-Control-Allow-Origin", None)
        if request.path.startswith("/api/") or request.path == "/":
            resp.headers["Cache-Control"] = "no-store"
            resp.headers["Pragma"] = "no-cache"
        return resp

    return token
