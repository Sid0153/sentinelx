# ADR-0015: The demo environment is reset by replacing the database, keeping the accounts

**Context.** Phase 16 needs a demo environment that can be loaded, shown, and reset to the
same starting point. But raw records, events and the audit log are append-only: triggers
refuse UPDATE, DELETE and TRUNCATE (ADR-0010, Phase 13 hash chain). Alerts, incidents,
notes and activity all point at that evidence.

**Options.**
- (a) Delete the demo rows: drop the append-only triggers for the reset, or add a "demo"
  exception to them.
- (b) Mark demo data as hidden instead of deleting it.
- (c) Replace the whole database, as a restore does (ADR-0014): a new, empty database that
  the backend migrates, then the demo story loaded again through the normal pipeline.

**Decision.** (c), in `scripts/demo_reset.sh`, with three safeguards and one exception:
- It refuses unless every stored record is SIMULATED (`cli demo-status`): a database holding
  real evidence is never a demo, so the script cannot destroy one.
- It backs up the database first (unless `--no-backup`), so the audit log of the demo just
  given survives in the backup.
- The new audit log's DEMO_RESET entry records the newest entry of the one it replaced.
  The audit logs of successive resets can therefore be followed back through the backups.
- Exception: the users table is copied across, held only in the script's memory (password
  hashes are never written to disk). Presenters keep their accounts, passwords and
  two-factor settings.
  Sessions end.

**Consequences.**
- No code path can delete evidence. The append-only triggers have no exception, which (a)
  would have needed, and (b) would have left the database growing with every demo.
- A reset takes a backup, a restart and loading the story: 41 s on the development machine
  (loading the ~1,000 records itself: under 3 s). The site is down meanwhile. That is
  acceptable for a demo, and one more reason the script refuses real data.
- The story is anchored to one time (`--start`, default the start of the current hour), so
  the same anchor gives the same records, alerts and incidents. Loading twice stores nothing
  new: every record is a duplicate.
- A reset forgets analyst work in the demo (notes, statuses). That is the purpose.
