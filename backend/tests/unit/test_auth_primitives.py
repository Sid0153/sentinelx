"""Passwords, access tokens, refresh tokens, rate limiting and client-IP resolution."""

import ipaddress
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from starlette.datastructures import Headers

from app.auth.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    hash_password,
    validate_password_policy,
    verify_password,
)
from app.auth.tokens import (
    ALGORITHM,
    ISSUER,
    InvalidTokenError,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_refresh_token,
)
from app.core.client_ip import parse_networks, resolve_client_ip
from app.core.rate_limit import sliding_count

KEY = secrets.token_urlsafe(48)


# ---------- passwords ----------


def test_password_hash_is_argon2id_and_verifies() -> None:
    hashed = hash_password("a-long-enough-passphrase")
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, "a-long-enough-passphrase")
    assert not verify_password(hashed, "a-long-enough-passphrasE")


def test_same_password_hashes_differently_each_time() -> None:
    assert hash_password("same-password-123") != hash_password("same-password-123")


def test_verify_rejects_garbage_hashes_instead_of_crashing() -> None:
    assert not verify_password("not-a-real-hash", "whatever-password")


@pytest.mark.parametrize(
    "password", ["x" * (MIN_PASSWORD_LENGTH - 1), "x" * (MAX_PASSWORD_LENGTH + 1)]
)
def test_password_policy_enforces_length(password: str) -> None:
    with pytest.raises(ValueError):
        validate_password_policy(password)


def test_password_policy_accepts_a_long_passphrase_without_symbols() -> None:
    assert validate_password_policy("correct horse battery staple")


# ---------- access tokens ----------


def test_access_token_round_trip() -> None:
    user_id = uuid.uuid4()
    token = create_access_token(user_id, KEY, timedelta(minutes=5))
    assert decode_access_token(token, KEY) == user_id


def test_access_token_carries_no_role_or_email() -> None:
    token = create_access_token(uuid.uuid4(), KEY, timedelta(minutes=5))
    claims = jwt.decode(token, KEY, algorithms=[ALGORITHM], issuer=ISSUER)
    assert set(claims) == {"sub", "iss", "iat", "exp", "typ"}


def test_expired_token_is_rejected() -> None:
    token = create_access_token(uuid.uuid4(), KEY, timedelta(seconds=-1))
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


def test_token_signed_with_another_key_is_rejected() -> None:
    token = create_access_token(uuid.uuid4(), secrets.token_urlsafe(48), timedelta(minutes=5))
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


def test_unsigned_alg_none_token_is_rejected() -> None:
    now = datetime.now(UTC)
    forged = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "iss": ISSUER,
            "iat": now,
            "exp": now + timedelta(hours=1),
            "typ": "access",
        },
        key="",
        algorithm="none",
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(forged, KEY)


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "someone-else", "typ": "access"},
        {"iss": ISSUER, "typ": "refresh"},
        {"iss": ISSUER},  # no typ
    ],
)
def test_wrong_issuer_or_type_is_rejected(claims: dict[str, str]) -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {"sub": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(hours=1), **claims},
        KEY,
        algorithm=ALGORITHM,
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


def test_token_with_non_uuid_subject_is_rejected() -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "admin",
            "iss": ISSUER,
            "iat": now,
            "exp": now + timedelta(hours=1),
            "typ": "access",
        },
        KEY,
        algorithm=ALGORITHM,
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, KEY)


# ---------- refresh tokens ----------


def test_refresh_tokens_are_long_random_and_hashed() -> None:
    first, second = generate_refresh_token(), generate_refresh_token()
    assert first != second
    assert len(first) >= 64  # 48 random bytes, base64url
    assert hash_refresh_token(first) != first
    assert len(hash_refresh_token(first)) == 64


# ---------- rate limiter ----------


def test_the_sliding_estimate_weights_the_previous_window() -> None:
    # At the start of a window all of the previous one still counts; at its end none does.
    assert sliding_count(previous=10, current=0, elapsed_fraction=0.0) == 10
    assert sliding_count(previous=10, current=2, elapsed_fraction=0.5) == 7
    assert sliding_count(previous=10, current=4, elapsed_fraction=1.0) == 4


# ---------- client IP ----------

NGINX = parse_networks("172.28.0.10/32")


def headers(xff: str | None) -> Headers:
    return Headers({"x-forwarded-for": xff} if xff is not None else {})


def test_without_trusted_proxies_the_peer_is_the_client() -> None:
    assert resolve_client_ip("203.0.113.5", headers("198.51.100.1"), ()) == "203.0.113.5"


def test_through_the_trusted_proxy_the_forwarded_address_is_used() -> None:
    assert resolve_client_ip("172.28.0.10", headers("198.51.100.7"), NGINX) == "198.51.100.7"


def test_forged_left_entries_are_ignored() -> None:
    # The client sent "X-Forwarded-For: 1.2.3.4"; nginx appended the real address.
    assert (
        resolve_client_ip("172.28.0.10", headers("1.2.3.4, 198.51.100.7"), NGINX) == "198.51.100.7"
    )


def test_requests_that_bypass_the_proxy_cannot_choose_their_address() -> None:
    # Straight to the backend port: the peer is the bridge gateway, not nginx.
    assert resolve_client_ip("172.28.0.1", headers("198.51.100.7"), NGINX) == "172.28.0.1"


def test_garbage_forwarded_entry_stops_the_walk() -> None:
    assert resolve_client_ip("172.28.0.10", headers("not-an-ip"), NGINX) == "172.28.0.10"


def test_all_hops_trusted_returns_the_leftmost_proxy() -> None:
    assert resolve_client_ip("172.28.0.10", headers("172.28.0.10"), NGINX) == "172.28.0.10"


def test_missing_peer_is_passed_through() -> None:
    assert resolve_client_ip(None, headers("198.51.100.7"), NGINX) is None


def test_invalid_trusted_proxy_setting_is_rejected() -> None:
    with pytest.raises(ValueError):
        parse_networks("172.28.0.10/33")


def test_named_proxy_groups_expand() -> None:
    """Render's chain (docs/deployment.md): private addresses, Cloudflare, Render's proxy."""
    networks = parse_networks("private, Cloudflare, 74.220.48.0/20")
    assert ipaddress.ip_network("10.0.0.0/8") in networks
    assert ipaddress.ip_network("104.16.0.0/13") in networks
    assert ipaddress.ip_network("2606:4700::/32") in networks
    assert networks[-1] == ipaddress.ip_network("74.220.48.0/20")


def test_rightmost_visitor_behind_render_and_cloudflare() -> None:
    """The chain measured on Render for CloudSentinel, same proxies: forged left entries,
    the visitor, Cloudflare, Render's proxy, Cloudflare, Render internal."""
    chain = "1.2.3.4, 203.0.113.9, 172.68.1.1, 74.220.48.5, 162.158.2.2"
    trusted = parse_networks("private, cloudflare, 74.220.48.0/20")
    assert resolve_client_ip("10.1.2.3", headers(chain), trusted) == "203.0.113.9"
