# Testing strategy

> Status: **in force since Phase 2.** Items marked ✅ are implemented and run in CI; the others
> are written in the phase that builds the feature. CI fails under 90 % backend line coverage.
> Coverage is a floor, not the goal: the goal is behaviour tests like the ones below.
> Current totals are in `CLAUDE.md` (updated each phase).

## Layers

| Layer | Tooling | Database | What it proves |
|---|---|---|---|
| ✅ Unit (pure cores) | pytest | none | Parsers, normalization, enrichment, event schema, auth primitives, client IP, redaction, demo generators; later conditions, evaluators, explanation, correlation scoring, risk |
| ✅ Integration | pytest | **real PostgreSQL** (Docker) | Migrations up/down, models match migrations, every constraint and append-only trigger, index fit per query shape, event store round trip; later detection runs and the advisory lock |
| ✅ API | pytest + TestClient | real PostgreSQL | Validation, status codes, pagination, filtering, the route-access matrix (every route × every role), audit records, ingestion end to end, CLI commands |
| ✅ Frontend | Vitest + Testing Library | mocked `fetch` per route | Pages in real states (loading, empty, error, data), sign-in and session renewal, role-based controls, URL state, cross-tab refresh lock |
| ✅ Smoke | GitHub Actions + Docker Compose | real stack | Images start healthy; hardening; security headers; database outage → 503 and recovery; `scripts/auth_smoke.py`; `scripts/ingest_smoke.py`; a simulated scenario through the CLI; forged `X-Forwarded-For` on both ports; no secret in logs |
| Performance (Phase 14) | benchmark script | real PostgreSQL | Measured ingest rate and detection latency on generated data, recorded with the machine spec |

PostgreSQL rather than SQLite, because triggers, partial unique indexes, `inet`, `bytea`, JSONB,
`pg_trgm` and advisory locks are part of the design.

**Isolation.** Every database test runs inside a transaction that is rolled back. Code under
test may commit: its commits become savepoints. CLI commands, which open their own sessions,
are routed into the same transaction by the `cli_sessions` fixture. Nothing a test writes
survives, which matters because rows in append-only tables could never be cleaned up.

## Required behaviour tests

**Ingestion** ✅ (Phase 5)
- Every supported line shape parses to the expected normalized fields: table-driven cases per
  source in `tests/unit/test_parsers.py`, each a literal log line next to the fields it must
  produce. We chose inline cases over separate fixture files so a reviewer sees input and
  expectation together.
- Malformed records become `FAILED` raw records with a fixed reason code, informational ones
  become `SKIPPED`, the batch continues, and the counts add up.
- Missing optional fields give nulls; missing required ones fail the record with a code.
- The same record sent twice (in one batch or two) is stored once and counted as a duplicate.
  The same text from two sources gives two records.
- Syslog year rollover, time zones, PowerShell dates; naive JSON timestamps fail.
- Random bytes never crash a parser; hostile 60 KB lines parse in linear time.
- XSS-shaped values survive as inert text.
- Oversized payloads and too many records return `413` with nothing stored.

**Detection** ✅ (Phase 6; `tests/unit/test_detection_rules.py`,
`test_detection_validation.py`, `tests/integration/test_detection.py`,
`test_condition_sql.py`, `tests/api/test_detections.py`. Every rule has positive and negative
cases, and a meta-test fails if a rule is added that no demo scenario triggers)
- threshold: 4 → none, 5 → alert, 5 over 5 min 1 s → none, exactly 5 min → alert.
- sequence: success 4 min after failures → AUTH-002; 3 h later → no AUTH-002; success
  *before* failures → none.
- distinct: 4 accounts → none, 5 → AUTH-003; one account from 4 sources → none, 5 →
  AUTH-005 (while AUTH-001 stays silent: the gap it closes); invalid names and slow
  spreads → none.
- PROC-001: renamed PowerShell, `-ec:` and en-dash spellings, `bash <(curl …)`,
  `sh -c "$(wget …)"`, download then run → detected; tokens, UTF-8 base64 and
  download-then-extract → not; every pattern linear on 7–9 KB hostile input.
- new_value: no history → none (cold start); known /24 → none; new /24 → AUTH-004.
- Order independence: shuffled input gives the same detections. Batch split: failures in one
  batch and the success in the next still give AUTH-002, with evidence from both batches.
- Idempotence: repeating a manual run over the same range gives the same detections and
  changes no alert.
- Benign scenario → zero detections; each scenario → exactly its rules (in memory, in
  PostgreSQL, live).
- Condition language: over 500 conditions on stored events with awkward values, the SQL
  prefilter selects every event Python accepts, and exactly those where marked exact
  (mutation-checked). Invalid conditions and inconsistent rules are refused with a message;
  a broken library file stops startup naming the file.
- Storage: seeding is idempotent; a library change creates a version and keeps valid tuning;
  tuning outside the bounds, of a non-tunable field, or without a reason is refused;
  versions are append-only; retired rules stay, disabled.
- Engine failures: a rule over the candidate cap and a rule that raises are isolated; a failed
  run leaves the records stored and the batch `DETECTION_FAILED`; batches left `STORED` by a
  crash are flagged at startup.
- AUTH-004 uses history stored in PostgreSQL (new network → detection; known network or
  too little history → none).

**Alerts** ✅ (Phase 7; `tests/unit/test_priority.py`, `test_alert_rules.py`,
`tests/integration/test_alerts.py`, `tests/api/test_alerts.py`, `frontend/tests/alerts.test.tsx`)
- Dedup: continuing activity extends the open alert; re-running detection changes nothing,
  also after the alert was closed; new activity after closing opens a new alert with
  `previous_alert_id` and leaves the closed one alone; different indicators are different
  alerts; the database refuses a second open alert for a key. Mutation-checked (removing the
  evidence check or the extension makes tests fail).
- Priority: every factor, band edges 24/25, 49/50, 74/75, the cap, the documented example,
  inventory context from the current records; a weight change without a version bump fails.
  Open alerts are re-scored when the inventory changes (also for assets added after the
  events), closed alerts are not.
- Concurrency, with real concurrent transactions in a throwaway database
  (`test_alert_concurrency.py`): analyst closing vs a run extending, in both orders, and two
  batches of the same activity at once. Each lock was removed once to prove a test fails.
- Workflow: all 25 status pairs (allowed ones pass, the rest are refused); disposition and
  reason rules; `409` for changes the workflow does not allow, `400` for missing input;
  reopening blocked by a newer open alert; audit entries and timestamps; VIEWER `403`.
- Evidence cap, simulated flag, alerting failure → batch `DETECTION_FAILED` with records kept.
- UI: queue order and filters in the query, empty state, alert page content, raw evidence
  shown as text (an `<img onerror>` payload creates no element), resolving with a
  disposition, false positive needs a reason, server refusals shown.

**Incidents** ✅ (Phase 8; details in [correlation.md](correlation.md#testing))
- The full chain gives one incident with the correct alerts, links and reasons, in one batch
  and in four; the timeline is in order and pages identically by keyset.
- Unrelated medium alerts create no incident; one outside source against two hosts does.
- Window edges (pure and on stored alerts), a narrowed window, resolved incidents not extended
  (with the back-link), unlinked alerts not re-linked.
- Real concurrency (own database): an incident resolved while a run waits; two batches of one
  chain at once make one incident.
- Notes, evidence and activity are append-only (UPDATE and DELETE rejected); a closed
  incident refuses changes; every action is audited; VIEWER gets `403` on every action (RBAC
  matrix).
- Mutation-checked: partners, the unlink guard, the new-finding link and the incident row lock
  each have a test that fails without them.

**Auth / RBAC / audit** ✅ (Phase 3)
- Login success and failure, lockout, rate limit, refresh rotation, reuse detection (and
  post-logout refreshes *not* treated as reuse), logout revocation.
- Every route × {anonymous, VIEWER, ANALYST, ADMIN} matches the declared access table (401/403
  exactly where expected), and denials are audited as `DENIED`.
- No secret appears in audit `details` or in captured logs.

**Database** ✅ (Phases 2–5)
- Migrations upgrade from empty to head, downgrade to base, and upgrade again.
- The SQLAlchemy models match the migrated schema exactly.
- Every check constraint, foreign key and unique index is tested with a violating insert.
- Append-only triggers reject `UPDATE`, `DELETE` and `TRUNCATE`.
- Each planned query shape can use its intended index.

## Test data

- All sample data is synthetic: RFC 5737 outside addresses, 10.0.0.0/8 inside, the fictional
  `corp.example`.
- The demo generator (`app/demo/scenarios.py`) is **also** used by tests. Every scenario must
  parse with zero failures and have the shape its name promises. Each scenario is also
  tested to trigger (or, for benign activity, not trigger) exactly its documented rules.
- Time is injected (`now` / receive time as parameters): no sleeping, no wall-clock
  dependence.

## Commands

Backend (from `backend/`, with `TEST_DATABASE_URL` set): `ruff check .`, `ruff format
--check .`, `mypy`, `pytest --cov=app --cov-fail-under=90`, `pip-audit -r requirements.txt
--require-hashes --disable-pip` (and `requirements-dev.txt`).
Frontend (from `frontend/`): `npm run lint`, `npm run typecheck`, `npm test`, `npm run
build`, `npm audit --audit-level=moderate`.
Against a running stack: `python3 scripts/auth_smoke.py <url> <admin> <password>` and
`python3 scripts/ingest_smoke.py <url> <admin> <password>`.
CI runs all of these, plus gitleaks over the full history.
