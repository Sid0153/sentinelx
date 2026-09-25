from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128  # bounds the work a single request can force Argon2 to do

# argon2-cffi's defaults give Argon2id with the library's current recommended cost settings.
_hasher = PasswordHasher()


def validate_password_policy(password: str) -> str:
    """Length rules only (no forced symbols), following current NIST guidance."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
    return password


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(password_hash: str, plain: str) -> bool:
    try:
        return _hasher.verify(password_hash, plain)
    except (VerificationError, InvalidHashError):
        return False


@lru_cache
def _dummy_hash() -> str:
    return _hasher.hash("not-a-real-password")


def verify_against_dummy(plain: str) -> None:
    """Spend the same time as a real check, so unknown accounts are not detectable by timing."""
    verify_password(_dummy_hash(), plain)
