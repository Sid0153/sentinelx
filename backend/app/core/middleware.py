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
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import request_id_var

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


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        supplied = Headers(scope=scope).get("x-request-id", "")
        request_id = supplied if _SAFE_REQUEST_ID.match(supplied) else str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id
        token = request_id_var.set(request_id)
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
                    }
                },
            )
            request_id_var.reset(token)

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
