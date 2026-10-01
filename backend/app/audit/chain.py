"""The audit log's hash chain (Phase 13, migration 0011, docs/security.md).

The database trigger links every new entry to the previous one; this module checks the
links and anchors them outside the database.

- `verify()` recomputes every entry's hash in PostgreSQL (the same function the trigger
  uses) and checks each entry points at the one before it. A changed, removed or reordered
  entry breaks the chain from that point on.
- After each commit, the sequence number and hash of every new entry go to the application
  log (`audit.chained`), which normally lives outside the database. Someone able to rewrite
  the whole table and recompute the chain would still disagree with those log lines: check
  them with `verify(anchors=...)` (`cli verify-audit --anchor SEQ:HASH`).

This makes tampering by the database owner or an operator detectable, not impossible.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog

logger = logging.getLogger("sentinelx.audit")

GENESIS = "0" * 64

_CHECK = text(
    """
    WITH chain AS (
        SELECT seq, entry_hash, prev_hash,
               audit_entry_digest(prev_hash, id, occurred_at, action, result, actor_id,
                                  actor_label, entity_type, entity_id, client_ip,
                                  request_id, details) AS recomputed,
               coalesce(lag(entry_hash) OVER (ORDER BY seq), :genesis) AS expected_prev
        FROM audit_logs
        WHERE entry_hash IS NOT NULL
    )
    SELECT count(*) AS chained,
           min(seq) FILTER (WHERE entry_hash <> recomputed OR prev_hash <> expected_prev)
               AS first_broken,
           max(seq) AS head_seq
    FROM chain
    """
)


@dataclass
class ChainReport:
    chained: int  # entries covered by the chain
    legacy: int  # entries written before the chain existed (not covered)
    first_broken: int | None  # the first entry whose hash or link does not match
    head_seq: int | None
    head_hash: str | None
    anchor_problems: list[str] = field(default_factory=list)

    @property
    def intact(self) -> bool:
        return self.first_broken is None and not self.anchor_problems


def verify(db: Session, anchors: list[tuple[int, str]] | None = None) -> ChainReport:
    """Checks the whole chain, and each (seq, hash) anchor taken from the application log."""
    row = db.execute(_CHECK, {"genesis": GENESIS}).one()
    legacy = db.scalar(text("SELECT count(*) FROM audit_logs WHERE entry_hash IS NULL")) or 0
    head_hash = (
        db.scalar(text("SELECT entry_hash FROM audit_logs WHERE seq = :seq"), {"seq": row.head_seq})
        if row.head_seq is not None
        else None
    )
    report = ChainReport(row.chained, legacy, row.first_broken, row.head_seq, head_hash)
    for seq, expected in anchors or []:
        stored = db.scalar(text("SELECT entry_hash FROM audit_logs WHERE seq = :seq"), {"seq": seq})
        if stored is None:
            report.anchor_problems.append(f"entry {seq} is missing")
        elif stored != expected:
            report.anchor_problems.append(f"entry {seq} has a different hash than logged")
    return report


# ---------- the log anchor ----------

_PENDING = "audit_chain_pending"


@event.listens_for(Session, "after_flush")
def _remember_new_entries(session: Session, _context: Any) -> None:
    entries = [obj for obj in session.new if isinstance(obj, AuditLog)]
    if entries:
        session.info.setdefault(_PENDING, []).extend(entries)


@event.listens_for(Session, "after_commit")
def _log_committed_entries(session: Session) -> None:
    for entry in session.info.pop(_PENDING, []):
        # Sequence number and hash only: never the entry's details.
        logger.info(
            "audit.chained",
            extra={"fields": {"seq": entry.seq, "hash": entry.entry_hash}},
        )


@event.listens_for(Session, "after_rollback")
def _forget_rolled_back_entries(session: Session) -> None:
    session.info.pop(_PENDING, None)  # nothing was stored, so nothing is anchored
