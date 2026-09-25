import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt

ISSUER = "sentinelx"
ALGORITHM = "HS256"  # pinned on decode, so a token cannot choose its own algorithm


class InvalidTokenError(Exception):
    """The access token is missing a claim, expired, forged or otherwise unusable."""


def create_access_token(user_id: uuid.UUID, secret_key: str, expires_in: timedelta) -> str:
    """Short-lived signed token that only says who the user is.

    The role is deliberately NOT inside the token: it is read from the database on every
    request, so a demoted or deactivated user loses access immediately.
    """
    now = datetime.now(UTC)
    claims = {
        "sub": str(user_id),
        "iss": ISSUER,
        "iat": now,
        "exp": now + expires_in,
        "typ": "access",
    }
    return jwt.encode(claims, secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str, secret_key: str) -> uuid.UUID:
    try:
        claims = jwt.decode(
            token,
            secret_key,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "iss"]},
        )
        if claims.get("typ") != "access":
            raise InvalidTokenError("Wrong token type")
        return uuid.UUID(claims["sub"])
    except (jwt.PyJWTError, KeyError, ValueError) as exc:
        raise InvalidTokenError("Invalid token") from exc


def generate_refresh_token() -> str:
    """Opaque random value (about 384 bits). It carries no data and is useless without the DB."""
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    # A fast hash is fine here: the input is high-entropy random data, not a human password.
    return hashlib.sha256(token.encode()).hexdigest()
