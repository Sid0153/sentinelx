# Testing strategy

> Status: **DESIGN (Phase 1)**. Tests are written in the same phase as the code they cover. CI
> fails under 90 % backend line coverage. Coverage is a floor, not the goal: the goal is
> behaviour tests like the ones below.

## Layers

| Layer | Tooling | Database | What it proves |
|---|---|---|---|
| Unit (pure cores) | pytest | none | Parsers, normalization, enrichment, conditions, evaluators, explanation, correlation scoring, risk, demo generators |
| Integration | pytest | **real PostgreSQL** (Docker) | Pipeline end to end, dedup under re-run, advisory-lock serialization, triggers, migrations |
| API | pytest + httpx `TestClient` | real PostgreSQL | Validation, status codes, pagination, filtering, RBAC matrix, audit records |
| Frontend | Vitest + Testing Library | mocked `fetch` per route | Pages render real states (loading, empty, error, data), role-based controls, URL state |
| Smoke | GitHub Actions + Docker Compose | real stack | Built images start, health/ready OK, a demo scenario produces the expected alert/incident |
| Performance (Phase 14) | pytest benchmark script | real PostgreSQL | Measured ingest rate and detection latency on generated data; results recorded with the machine spec |

We use PostgreSQL rather than SQLite for integration tests because triggers, partial unique
indexes, `inet`, JSONB, `pg_trgm` and advisory locks are part of the design.

## Required behaviour tests (non-exhaustive)

**Ingestion**
- Every supported line shape parses to the expected normalized fields (golden fixtures per
  source).
- Malformed and truncated records become `FAILED` raw events, the batch continues, and counts
  are correct.
- Missing optional fields give nulls, not crashes.
- The same record sent twice becomes one event plus `duplicates=1`. The same text from two
  sources gives two events.
- Syslog year rollover (Dec line received in Jan) and timezone handling.
- XSS-shaped values survive round-trip as inert text.
- Oversized payloads return `413` and nothing is stored.

**Detection** (every rule has at least one positive and one negative fixture; a meta-test
enforces it)
- threshold: 4 → none, 5 → alert, 5 over 5 min 1 s → none, exactly 5 min → alert.
- sequence: success 4 min after failures → AUTH-002; 3 h later → no AUTH-002; success
  *before* failures → none.
- distinct: 4 accounts → none, 5 → AUTH-003.
- new_value: no history → none (cold start); known /24 → none; new /24 → AUTH-004.
- Order independence: shuffled input gives the same detections. Batch-split independence:
  one batch vs two batches give the same alerts.
- Idempotence: re-running a batch leaves alerts and evidence unchanged.
- Benign scenario → zero alerts.
- Condition language: the SQL compile and the Python evaluation agree on a shared fixture
  set.

**Alerts**
- Dedup extends an active alert. A resolved alert is not reopened, and a new alert gets
  `previous_alert_id`.
- Priority breakdown values and band edges.
- Every legal transition succeeds and every illegal one returns `409`. The reason is required
  where specified.

**Incidents**
- The full chain gives one incident with the correct alert set and timeline order.
- Medium-only unrelated alerts create no incident. A MEDIUM external-IP link across hosts
  links.
- Window edges.
- A closed incident is not extended.
- Concurrent batches give one incident.
- Notes and evidence are append-only (the DB rejects `UPDATE`).
- Assignment is audited.

**Auth / RBAC / audit**
- Login success and failure, lockout, rate limit, refresh rotation, reuse detection,
  logout revocation.
- Every route × {anonymous, VIEWER, ANALYST, ADMIN} matches the declared access table
  (401/403 exactly where expected).
- VIEWER attempting incident modification gets `403` and an `ACCESS_DENIED` audit row.
- No secret appears in audit `details` or in captured logs.

**Database**
- Migrations upgrade from empty to head and downgrade back.
- Constraints reject invalid enums and ports.
- Append-only triggers reject `UPDATE`/`DELETE`.

## Test data

- Fixtures are small hand-written files per source, readable in review.
- The demo generator is **also** used by integration tests, so demo scenarios are guaranteed
  to trigger (or, for benign scenarios, not trigger) exactly the documented rules.
- Time is injected (`now` parameter), with no sleeping and no wall-clock dependence.

## Commands (planned, Phase 2)

Backend: `ruff check .`, `mypy`, `pytest --cov=app` (with `TEST_DATABASE_URL`),
`pip-audit -r requirements.txt --require-hashes --disable-pip`.
Frontend: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`,
`npm audit --audit-level=moderate`.
CI also runs gitleaks and the Compose smoke test.
