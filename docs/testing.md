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

**Detection** (Phase 6; every rule has at least one positive and one negative case, and a
meta-test enforces it)
- threshold: 4 → none, 5 → alert, 5 over 5 min 1 s → none, exactly 5 min → alert.
- sequence: success 4 min after failures → AUTH-002; 3 h later → no AUTH-002; success
  *before* failures → none.
- distinct: 4 accounts → none, 5 → AUTH-003.
- new_value: no history → none (cold start); known /24 → none; new /24 → AUTH-004.
- Order independence: shuffled input gives the same detections. Batch-split independence:
  one batch vs two batches give the same alerts.
- Idempotence: re-running a batch leaves alerts and evidence unchanged.
- Benign scenario → zero alerts.
- Condition language: the SQL compile and the Python evaluation agree on shared cases.

**Alerts** (Phase 7)
- Dedup extends an active alert. A resolved alert is not reopened, and a new alert gets
  `previous_alert_id`.
- Priority breakdown values and band edges.
- Every legal transition succeeds and every illegal one returns `409`. The reason is required
  where specified.

**Incidents** (Phase 8)
- The full chain gives one incident with the correct alert set and timeline order.
- Medium-only unrelated alerts create no incident. A MEDIUM external-IP link across hosts
  links.
- Window edges.
- A closed incident is not extended.
- Concurrent batches give one incident.
- Notes and evidence are append-only (the DB rejects `UPDATE`).
- Assignment is audited.
- VIEWER attempting incident modification gets `403` and an `ACCESS_DENIED` audit row.

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
  parse with zero failures and have the shape its name promises. From Phase 6 on, each
  scenario is also tested to trigger (or, for benign activity, not trigger) exactly its
  documented rules.
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
