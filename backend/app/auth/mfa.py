"""Two-factor sign-in with time-based one-time passwords (TOTP, RFC 6238), Phase 13.

Standard authenticator apps work with it: SHA-1, 6 digits, 30-second steps; one step of clock
drift is accepted either way.

- The TOTP secret is not stored. It is derived from the server's SECRET_KEY and a random
  per-user salt (only the salt is in the database), so a database leak alone does not reveal
  anyone's codes. Consequence: rotating SECRET_KEY ends every enrolment (users enrol again;
  an admin can reset two-factor for someone locked out).
- A code is accepted once: the last used time step is stored, and that step or any earlier
  one is refused afterwards (no replay of a code seen over a shoulder).
- Ten recovery codes, shown once, stored as SHA-256 hashes; each works once.
"""

import base64
import hashlib
import hmac
import secrets
import struct
from datetime import datetime
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6
DRIFT_STEPS = 1
RECOVERY_CODES = 10
ISSUER = "SentinelX"


def new_salt() -> str:
    return secrets.token_hex(16)


def derive_secret(server_key: str, salt: str) -> bytes:
    """The user's TOTP key (160 bits), computable only with the server's SECRET_KEY."""
    return hmac.new(
        server_key.encode(), b"sentinelx-totp:" + salt.encode(), hashlib.sha256
    ).digest()[:20]


def hotp(secret: bytes, counter: int) -> str:
    """RFC 4226: an HMAC-SHA1 of the counter, dynamically truncated to DIGITS digits."""
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def time_step(now: datetime) -> int:
    return int(now.timestamp()) // STEP_SECONDS


def verify_totp(secret: bytes, code: str, now: datetime, last_step: int | None) -> int | None:
    """The time step the code belongs to, or None. Steps at or before `last_step` (already
    used) are refused."""
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = time_step(now)
    for step in range(current - DRIFT_STEPS, current + DRIFT_STEPS + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(hotp(secret, step), code):
            return step
    return None


def setup_details(secret: bytes, email: str) -> tuple[str, str]:
    """(the secret in base32 for typing in, the otpauth:// link authenticator apps read)."""
    encoded = base64.b32encode(secret).decode().rstrip("=")
    label = quote(f"{ISSUER}:{email}", safe=":@")
    uri = (
        f"otpauth://totp/{label}?secret={encoded}&issuer={ISSUER}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
    return encoded, uri


def _normalize_recovery(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(_normalize_recovery(code).encode()).hexdigest()


def new_recovery_codes() -> tuple[list[str], list[str]]:
    """(codes to show once, their hashes to store)."""
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = secrets.token_hex(5)
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, [hash_recovery_code(c) for c in codes]


def use_recovery_code(stored_hashes: list[str], code: str) -> list[str] | None:
    """The remaining hashes when `code` is one of them (it is used up), else None."""
    digest = hash_recovery_code(code)
    for index, stored in enumerate(stored_hashes):
        if hmac.compare_digest(stored, digest):
            return stored_hashes[:index] + stored_hashes[index + 1 :]
    return None
