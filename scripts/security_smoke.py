"""End-to-end check of the Phase 13 account protections against a running stack.

    python3 scripts/security_smoke.py http://127.0.0.1:8081 admin@example.com ADMIN_PASSWORD

Two-factor sign-in (TOTP computed here like an authenticator app would), replay refusal,
recovery codes, an admin password reset with forced change, the admin two-factor reset and the
audit hash chain. Creates one throwaway ANALYST user. Standard library only; every check
prints one line and the first failure exits non-zero.
"""

import base64
import hashlib
import hmac
import json
import secrets
import struct
import sys
import time
import urllib.error
import urllib.request
from typing import Any


def check(condition: bool, label: str, detail: object = "") -> None:
    print(
        f"{'ok  ' if condition else 'FAIL'} {label}"
        + (f" ({detail})" if detail else "")
    )
    if not condition:
        sys.exit(1)


def totp(secret_b32: str, steps_ahead: int = 0) -> str:
    """RFC 6238 (SHA-1, 6 digits, 30 s), as an authenticator app computes it."""
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    counter = int(time.time()) // 30 + steps_ahead
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 1_000_000).zfill(6)


class Client:
    def __init__(self, base: str) -> None:
        if not base.startswith(("http://", "https://")):
            sys.exit("The base URL must start with http:// or https://")
        self.base = base.rstrip("/")
        self.token: str | None = None

    def call(
        self, method: str, path: str, body: Any = None
    ) -> tuple[int, Any, dict[str, str]]:
        for _ in range(3):
            status, data, headers = self._send(method, path, body)
            if status == 429 and path == "/api/auth/login":
                # Other smoke scripts share this client address's sign-in budget.
                print(
                    "     (sign-in rate limit reached; waiting for the window to pass)"
                )
                time.sleep(int(headers.get("retry-after", "60")) + 1)
                continue
            return status, data, headers
        return status, data, headers

    def _send(
        self, method: str, path: str, body: Any
    ) -> tuple[int, Any, dict[str, str]]:
        data = json.dumps(body).encode() if body is not None else None
        # The scheme was checked in __init__ (http/https only), so no file: or custom URLs.
        request = urllib.request.Request(self.base + path, data=data, method=method)  # noqa: S310
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
                raw = response.read()
                headers = {k.lower(): v for k, v in response.headers.items()}
                return response.status, json.loads(raw) if raw else None, headers
        except urllib.error.HTTPError as error:
            raw = error.read()
            headers = {k.lower(): v for k, v in error.headers.items()}
            return error.code, json.loads(raw) if raw else None, headers

    def login(self, email: str, password: str, **second: str) -> tuple[int, Any]:
        status, body, _ = self.call(
            "POST", "/api/auth/login", {"email": email, "password": password, **second}
        )
        if status == 200:
            self.token = body["access_token"]
        return status, body


def main(base: str, admin_email: str, admin_password: str) -> None:
    admin = Client(base)
    check(admin.login(admin_email, admin_password)[0] == 200, "admin signs in")

    email = f"mfa-{secrets.token_hex(4)}@ci.example"
    password = secrets.token_urlsafe(18)
    status, created, _ = admin.call(
        "POST", "/api/users", {"email": email, "password": password, "role": "ANALYST"}
    )
    check(status == 201, "admin creates an analyst", status)

    # Enrolment.
    user = Client(base)
    check(user.login(email, password)[0] == 200, "analyst signs in with the password")
    status, setup, _ = user.call("POST", "/api/auth/mfa/setup")
    check(
        status == 200 and setup["otpauth_uri"].startswith("otpauth://totp/"),
        "setup gives a key",
    )
    status, enabled, _ = user.call(
        "POST", "/api/auth/mfa/enable", {"code": totp(setup["secret"])}
    )
    check(
        status == 200 and len(enabled["recovery_codes"]) == 10,
        "a code turns it on",
        status,
    )
    recovery = enabled["recovery_codes"]

    # Sign-in now needs the second step; a code works once.
    fresh = Client(base)
    status, body = fresh.login(email, password)
    check(
        status == 401 and body["error"]["code"] == "mfa_required",
        "password alone is not enough",
    )
    code = totp(setup["secret"], 1)
    check(fresh.login(email, password, otp=code)[0] == 200, "password + code signs in")
    check(
        Client(base).login(email, password, otp=code)[0] == 401,
        "the same code is refused again",
    )

    # Admin password reset: temporary password, shown once, must be changed first.
    status, reset, headers = admin.call(
        "POST", f"/api/users/{created['id']}/reset-password"
    )
    check(
        status == 200 and headers.get("cache-control") == "no-store",
        "admin resets the password",
    )
    temporary = reset["temporary_password"]
    check(
        Client(base).login(email, password, otp=totp(setup["secret"], 1))[0] == 401,
        "old password no longer works",
    )
    after = Client(base)
    status, body = after.login(email, temporary, recovery_code=recovery[0])
    check(
        status == 200 and body["user"]["must_change_password"],
        "temporary password + recovery code",
    )
    status, body, _ = after.call("GET", "/api/alerts")
    check(
        status == 403 and body["error"]["code"] == "password_change_required",
        "nothing else until changed",
    )
    new_password = secrets.token_urlsafe(18)
    status, _, _ = after.call(
        "POST",
        "/api/auth/change-password",
        {"current_password": temporary, "new_password": new_password},
    )
    check(status == 204, "the user chooses a new password", status)

    # Admin two-factor reset, then the audit trail and its hash chain.
    status, body, _ = admin.call("POST", f"/api/users/{created['id']}/reset-mfa")
    check(
        status == 200 and body["mfa_enabled"] is False,
        "admin resets two-factor sign-in",
    )
    status, integrity, _ = admin.call("GET", "/api/audit/integrity")
    check(status == 200 and integrity["intact"], "audit hash chain intact", integrity)
    status, page, _ = admin.call("GET", "/api/audit?limit=100")
    actions = {entry["action"] for entry in page["items"]}
    for expected in (
        "MFA_ENABLED",
        "MFA_RECOVERY_CODE_USED",
        "PASSWORD_RESET",
        "MFA_RESET",
    ):
        check(expected in actions, f"audit log records {expected}")
    dumped = json.dumps(page)
    leaked = [
        s
        for s in (password, temporary, new_password, setup["secret"], *recovery)
        if s in dumped
    ]
    check(not leaked, "no password, key or recovery code in the audit log")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
