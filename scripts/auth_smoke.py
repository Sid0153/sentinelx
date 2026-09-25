"""End-to-end check of sign-in, roles, sessions and the audit trail against a running stack.

    python3 scripts/auth_smoke.py http://127.0.0.1:8081 admin@example.com ADMIN_PASSWORD

Standard library only, so CI can run it without installing anything. Every check prints one
line; the first failure stops the script with a non-zero exit code.
"""

import json
import secrets
import sys
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from typing import Any


class Client:
    def __init__(self, base: str) -> None:
        if not base.startswith(("http://", "https://")):
            sys.exit("The base URL must start with http:// or https://")
        self.base = base.rstrip("/")
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.token: str | None = None

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any, dict[str, str]]:
        data = json.dumps(body).encode() if body is not None else None
        # The scheme was checked in __init__ (http/https only), so no file: or custom URLs.
        request = urllib.request.Request(self.base + path, data=data, method=method)  # noqa: S310
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with self.opener.open(request, timeout=15) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None, dict(response.headers)
        except urllib.error.HTTPError as error:
            raw = error.read()
            return error.code, json.loads(raw) if raw else None, dict(error.headers)

    def login(self, email: str, password: str) -> dict[str, Any]:
        status, body, headers = self.call(
            "POST", "/api/auth/login", {"email": email, "password": password}
        )
        check(status == 200, f"login as {email}", status)
        cookie = headers.get("set-cookie", "").lower()
        check("httponly" in cookie and "samesite=strict" in cookie, "refresh cookie is locked down")
        self.token = body["access_token"]
        return dict(body["user"])


def check(condition: bool, label: str, detail: object = "") -> None:
    print(f"{'ok  ' if condition else 'FAIL'} {label}" + (f" ({detail})" if detail else ""))
    if not condition:
        sys.exit(1)


def main(base: str, admin_email: str, admin_password: str) -> None:
    admin = Client(base)
    me = admin.login(admin_email, admin_password)
    check(me["role"] == "ADMIN", "admin has the ADMIN role")

    viewer_email = f"viewer-{secrets.token_hex(4)}@ci.example"
    viewer_password = secrets.token_urlsafe(18)
    status, _, _ = admin.call(
        "POST", "/api/users", {"email": viewer_email, "password": viewer_password, "role": "VIEWER"}
    )
    check(status == 201, "admin creates a viewer", status)

    viewer = Client(base)
    viewer.login(viewer_email, viewer_password)
    check(viewer.call("GET", "/api/auth/me")[0] == 200, "viewer reads their own profile")
    status, body, _ = viewer.call("GET", "/api/users")
    check(status == 403 and body["error"]["code"] == "forbidden", "viewer is refused admin data")
    check(Client(base).call("GET", "/api/users")[0] == 401, "anonymous request is refused")

    status, _, _ = viewer.call("POST", "/api/auth/refresh")
    check(status == 200, "refresh cookie renews the session", status)
    check(viewer.call("POST", "/api/auth/logout")[0] == 204, "viewer signs out")
    check(viewer.call("POST", "/api/auth/refresh")[0] == 401, "session is gone after sign-out")

    status, page, _ = admin.call("GET", "/api/audit?limit=50")
    check(status == 200, "admin reads the audit log", status)
    actions = {entry["action"] for entry in page["items"]}
    for expected in ("LOGIN_SUCCEEDED", "USER_CREATED", "ACCESS_DENIED", "LOGOUT"):
        check(expected in actions, f"audit log records {expected}")
    # Entries from the CLI (create-admin) have no request, and so no client IP.
    from_requests = [entry for entry in page["items"] if entry["request_id"]]
    check(
        all(entry["client_ip"] for entry in from_requests),
        "audit entries from requests carry the client IP",
    )
    check(viewer_password not in json.dumps(page), "no password in the audit log")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
