"""Request context: request ID, security headers, one log line per request, last-resort errors.

Written as plain ASGI middleware (not BaseHTTPMiddleware) so it wraps every response, including
the 500 it produces itself for an unhandled exception, with the same headers and request ID.
"""

import json
import logging
import re
import time
import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.client_ip import Network, resolve_client_ip
from app.core.logging import client_ip_var, request_id_var

logger = logging.getLogger("sentinelx.http")

# Only accept a caller-supplied request ID if it is short and boring; otherwise a client could
# inject newlines or huge strings into our logs.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9-]{8,64}$")
_DOCS_PREFIX = "/api/docs"
# Health checks run every few seconds; logging each one at INFO would bury real traffic.
_QUIET_PATHS = frozenset({"/api/health", "/api/ready"})


def _security_headers(path: str) -> dict[str, str]:
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
    }
    if path.startswith("/api") and not path.startswith(_DOCS_PREFIX):
        # API responses are data, never pages: nothing may be cached, framed or executed.
        headers["Cache-Control"] = "no-store"
        headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return headers


def client_ip(request: Request) -> str:
    """The client address worked out by RequestContextMiddleware (see core/client_ip.py)."""
    resolved = getattr(request.state, "client_ip", None)
    if isinstance(resolved, str):
        return resolved
    return request.client.host if request.client else "unknown"


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp, trusted_networks: tuple[Network, ...] = ()) -> None:
        self.app = app
        self.trusted_networks = trusted_networks

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        supplied = headers.get("x-request-id", "")
        request_id = supplied if _SAFE_REQUEST_ID.match(supplied) else str(uuid.uuid4())
        peer = scope["client"][0] if scope.get("client") else None
        ip = resolve_client_ip(peer, headers, self.trusted_networks)
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        state["client_ip"] = ip
        token = request_id_var.set(request_id)
        ip_token = client_ip_var.set(ip)
        path: str = scope["path"]
        extra_headers = {**_security_headers(path), "X-Request-ID": request_id}
        started = time.perf_counter()
        status = 500
        response_started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal status, response_started
            if message["type"] == "http.response.start":
                status = message["status"]
                response_started = True
                headers = MutableHeaders(scope=message)
                for name, value in extra_headers.items():
                    headers[name] = value
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception:
            # Full details go to the server log only; the client gets a generic message.
            logger.exception("http.unhandled_error", extra={"fields": {"path": path}})
            if not response_started:
                await self._send_internal_error(send_with_headers, request_id)
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 1)
            logger.log(
                logging.DEBUG if path in _QUIET_PATHS else logging.INFO,
                "http.request",
                extra={
                    "fields": {
                        "method": scope["method"],
                        "path": path,  # no query string: it can carry search values
                        "status": status,
                        "duration_ms": duration_ms,
                        "client_ip": ip,
                    }
                },
            )
            request_id_var.reset(token)
            client_ip_var.reset(ip_token)

    @staticmethod
    async def _send_internal_error(send: Send, request_id: str) -> None:
        body = json.dumps(
            {
                "error": {
                    "code": "internal_error",
                    "message": "Internal server error",
                    "request_id": request_id,
                }
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 500,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class BodyLimitMiddleware:
    """Refuses request bodies over a limit, whatever proxy is (or is not) in front: nginx caps
    bodies too, but the backend must not depend on it (Phase 13). The declared Content-Length
    is checked first; a body without one (chunked) is counted as it streams in, so it is
    never read whole. When the count passes the limit, the 413 is sent from here and the app
    is told the client went away (it stops reading; anything it still sends is dropped).
    Raising instead would not work: FastAPI turns errors while reading a body into a 400.
    Ingest paths use the ingest limit, every other path `default_limit`."""

    def __init__(
        self,
        app: ASGIApp,
        default_limit: int,
        ingest_limit: int,
        ingest_prefix: str = "/api/ingest/",
    ) -> None:
        self.app = app
        self.default_limit = default_limit
        self.ingest_limit = ingest_limit
        self.ingest_prefix = ingest_prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]
        limit = self.ingest_limit if path.startswith(self.ingest_prefix) else self.default_limit
        declared = Headers(scope=scope).get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            await self._too_large(scope, send, limit)
            return
        received = 0
        refused = False
        started = False

        async def counting_receive() -> Message:
            nonlocal received, refused, started
            if refused:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    refused = True
                    if not started:
                        started = True
                        await self._too_large(scope, send, limit)
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if refused:
                return  # the 413 has been sent; the app's own answer is dropped
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        await self.app(scope, counting_receive, guarded_send)

    @staticmethod
    async def _too_large(scope: Scope, send: Send, limit: int) -> None:
        state = scope.get("state", {})
        body = json.dumps(
            {
                "error": {
                    "code": "payload_too_large",
                    "message": f"The request body can be at most {limit} bytes",
                    "request_id": state.get("request_id"),
                }
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
