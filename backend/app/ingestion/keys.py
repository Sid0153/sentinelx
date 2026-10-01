"""Per-source ingest keys (Phase 13, docs/security.md).

A log shipper should not hold a person's account. An ingest key is a credential for exactly
one thing: sending records to one log source. It cannot read anything, cannot send to another
source, and is useless once revoked or rotated.

- 256 random bits, shown once when issued: `sxk_<43 URL-safe characters>`.
- Stored only as its SHA-256 hash (a high-entropy random key needs no slow hash: there is
  nothing to brute-force), plus a short prefix so people can tell keys apart in lists, batch
  records and the audit log. The key itself is never stored, logged or audited.
- Issuing a key replaces any previous one (rotation); revoking removes it. Both are audited.
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.events import AuditAction, EntityType
from app.audit.service import record
from app.core.errors import AppError
from app.models.event import LogSource
from app.models.user import User

KEY_PREFIX = "sxk_"
MAX_KEY_LENGTH = 100  # anything longer is not a key: refused before hashing


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _label(key: str) -> str:
    """What may be shown: the scheme and the first few random characters."""
    return key[: len(KEY_PREFIX) + 6]


@dataclass(frozen=True)
class IssuedKey:
    key: str  # shown to the admin once, never again
    prefix: str
    created_at: datetime


def issue(db: Session, source: LogSource, actor: User | None) -> IssuedKey:
    """A new key for the source, replacing (and so revoking) any previous one."""
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    rotated = source.ingest_key_hash is not None
    now = datetime.now(UTC)
    source.ingest_key_hash = hash_key(key)
    source.ingest_key_prefix = _label(key)
    source.ingest_key_created_at = now
    source.ingest_key_last_used_at = None
    record(
        db,
        AuditAction.INGEST_KEY_ISSUED,
        actor=actor,
        entity_type=EntityType.LOG_SOURCE,
        entity_id=source.id,
        details={"source": source.name, "key_prefix": source.ingest_key_prefix, "rotated": rotated},
    )
    db.commit()
    return IssuedKey(key, source.ingest_key_prefix, now)


def revoke(db: Session, source: LogSource, actor: User) -> None:
    if source.ingest_key_hash is None:
        raise AppError(404, "This source has no ingest key")
    prefix = source.ingest_key_prefix
    source.ingest_key_hash = None
    source.ingest_key_prefix = None
    source.ingest_key_created_at = None
    source.ingest_key_last_used_at = None
    record(
        db,
        AuditAction.INGEST_KEY_REVOKED,
        actor=actor,
        entity_type=EntityType.LOG_SOURCE,
        entity_id=source.id,
        details={"source": source.name, "key_prefix": prefix},
    )
    db.commit()


def source_for_key(db: Session, key: str) -> LogSource | None:
    """The source this key belongs to, or None. Looked up by hash; the stored hash is compared
    again in constant time, so the comparison itself reveals nothing."""
    if not key.startswith(KEY_PREFIX) or len(key) > MAX_KEY_LENGTH:
        return None
    digest = hash_key(key)
    source = db.scalar(select(LogSource).where(LogSource.ingest_key_hash == digest))
    if source is None or source.ingest_key_hash is None:
        return None
    return source if hmac.compare_digest(source.ingest_key_hash, digest) else None
