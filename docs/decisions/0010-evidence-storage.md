# ADR-0010: Evidence storage: exact bytes, append-only including TRUNCATE

**Context.** Phase 4 built the event store. Two things turned up while testing it:

1. PostgreSQL `text` cannot hold a NUL byte, and log input can contain NUL bytes or invalid
   UTF-8 (binary junk, other encodings, deliberate tampering). Storing raw records as text
   would either crash ingestion on such a record or require altering it first.
2. The design allowed `TRUNCATE` on the pipeline tables so the demo could be reset. That left
   one statement able to erase every piece of evidence.

**Options.**
- (a) Raw as text, stripping or escaping NUL bytes: the stored record would differ from what
  was received.
- (b) Raw as `bytea`, exactly the bytes received.
- For resets: (c) allow `TRUNCATE`; (d) block it like `audit_logs` and design the demo reset
  separately.

**Decision.** (b) and (d).
- `raw_events.raw_data` is `bytea`. Text input is stored as its UTF-8 bytes. The fingerprint
  is SHA-256 over `source_id ‖ 0x1F ‖ bytes`. The UI decodes for display with replacement
  characters (`RawEvent.display_text`); that decoded text is never used for matching.
- In the normalized `events` row, a NUL becomes U+FFFD. The normalized copy is derived data,
  and the raw record keeps the original. A NUL in a username is rejected like any other
  control character.
- `raw_events` and `events` reject UPDATE, DELETE and TRUNCATE (shared `reject_modification()`
  trigger function). Phase 16 designs the demo reset without reopening this, for example by
  recreating the demo database.

**Consequences.**
- Evidence is byte-exact, and malformed input is stored as a `FAILED` record instead of
  crashing ingestion.
- Raw records cannot be searched with SQL text operators. Hunting searches normalized fields
  (ADR-0002, `threat-hunting.md`).
- A database owner can still drop the triggers. That is a visible schema change, and it is a
  documented residual risk (`security.md`).
