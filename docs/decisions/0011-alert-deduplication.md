# ADR-0011: Alert deduplication: one open alert per activity, evidence decides

**Status.** Accepted (Phase 7). Refines the Phase 1 design in
[detection-engine.md](../detection-engine.md), which is updated to match.

**Context.** The Phase 1 design extended an open alert only if the new detection started
within a per-rule `dedup_window` of the alert's last event, and otherwise created a new alert.
It also planned a partial unique index allowing one open alert per deduplication key. Those
two rules contradict each other: an open alert whose last event is older than the window
would block the new alert the design asks for. It also relied on unique evidence links alone
to make re-runs harmless, which is not enough: once an analyst closes an alert, a re-run over
the same time range would find no open alert and create a fresh one for activity already
handled.

**Options.**
- (a) Keep the window and drop the unique index (several open alerts per key possible).
- (b) Keep the window and auto-close stale alerts to make room (the engine overriding the
  analyst's queue).
- (c) Keep the unique index. While an alert is open, it is the analyst's work item for that
  activity and absorbs new detections whatever their timing. Whether a detection is new is
  decided by its evidence, not by time.

**Decision.** (c).
- Key: `sha256` of the rule ID, the indicator (PRIV-001's root shell and refused sudo are
  different findings) and the grouped values, JSON-encoded so values cannot shift between
  fields.
- A detection whose evidence is already linked to any alert with the same key, open or
  closed, changes nothing. Re-runs are therefore no-ops, including after an alert is closed.
- A detection with new evidence extends the open alert for its key or, if there is none,
  opens a new alert that points to the latest closed one (`previous_alert_id`). The engine
  never reopens a closed alert.
- `dedup_window` is removed from the rule format. It had no remaining job, and a field that
  does nothing misleads whoever tunes it.
- The alert's explanation, facts and guidance follow its **latest** detection, since they
  describe the current state of the activity. What each merged detection said is kept in the
  alert's `history`, and the rule version is recorded.

**Consequences.**
- "One open alert per activity" is enforced by the database, not only by code.
- A long-lived open alert keeps collecting activity, and its last-activity time and priority
  move with it. The queue can sort by recent activity to surface this.
- Removing `dedup_window` changed every rule's definition hash, so each rule moved to a new
  library version on the next start. This was expected and recorded.
- Evidence is linked up to 1,000 events per alert (a detection lists at most its first and
  last 50). When more matched, the alert says so (`evidence_truncated`) and `event_count` is
  a lower bound.
