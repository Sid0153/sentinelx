# Testing strategy

> Status: **in force since Phase 2.** Every item below is implemented and runs in CI (✅).
> CI fails under 90 % backend line coverage. Coverage is a floor, not the goal: the goal is
> behaviour tests like the ones below. At Phase 17: 1,370 backend tests (98 % line coverage)
> and 116 frontend tests; totals are kept current in the README.

## Layers

| Layer | Tooling | Database | What it proves |
|---|---|---|---|
| ✅ Unit (pure cores) | pytest | none | Parsers, normalization, enrichment, event schema, auth primitives, client IP, redaction, demo generators; later conditions, evaluators, explanation, correlation scoring, risk |
| ✅ Integration | pytest | **real PostgreSQL** (Docker) | Migrations up/down, models match migrations, every constraint and append-only trigger, index fit per query shape, event store round trip; later detection runs and the advisory lock |
| ✅ API | pytest + TestClient | real PostgreSQL | Validation, status codes, pagination, filtering, the route-access matrix (every route × every role), audit records, ingestion end to end, CLI commands |
| ✅ Frontend | Vitest + Testing Library | mocked `fetch` per route | Pages in real states (loading, empty, error, data), sign-in and session renewal, role-based controls, URL state, cross-tab refresh lock. CI fails under 90 % lines / 78 % branches (Phase 14) |
| ✅ Smoke | GitHub Actions + Docker Compose | real stack | Images start healthy; hardening (every container, the database included); no fixable HIGH/CRITICAL vulnerability in any image (Trivy); security headers; database outage → 503 and recovery; `scripts/auth_smoke.py`; `scripts/ingest_smoke.py`; `scripts/security_smoke.py`; a simulated scenario through the CLI; forged `X-Forwarded-For` on both ports; no secret in logs |
| ✅ Production (Phase 15) | GitHub Actions + Docker Compose with `docker-compose.prod.yml` | real stack over https | Production settings in force (https-only cookie, docs off, unsafe settings refused, only the site published, http redirects, certificate verified); the three smoke scripts over https; backup, loss of the database, restore: identical counts, summaries equal to the rows, audit chain verified against the backup's anchor; no secret in logs |
| ✅ Query budget (Phase 14) | pytest | real PostgreSQL | Statements per request do not grow with the data (no N+1), on list and detail pages; every list response is bounded |
| ✅ Performance (Phase 14) | `backend/benchmarks/run.py` | real PostgreSQL (own `_bench` database) | Ingest rate, detection time as the tables grow, read latency and query plans on 1 million generated records; [performance.md](performance.md) |

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

**Dashboard and investigation pages** ✅ (Phase 9; `tests/api/test_dashboard.py`,
`frontend/tests/dashboard.test.tsx`, `inventory.test.tsx`, `detections.test.tsx`)
- An empty system shows zeros; with ingested data every dashboard number equals an independent
  SQL count; closed alerts and incidents stop counting; trends are zero-filled and add up to
  the totals; `days` outside 1–90 → 422.
- Asset and identity activity: an asset registered after its events still finds them by
  hostname; an idle asset shows zeros.
- Frontend: dashboard numbers, links, empty state, simulated note, chart table view and
  keyboard focus; event filters from the URL, cursor paging, a new filter restarting from the
  newest page (this test found a request sent with a stale cursor), raw log text never
  rendered as HTML; admin create/edit sending only changed fields, viewers without controls;
  rule tuning sending only changed fields with the required reason, bounds refused before
  sending.

**Threat hunting** ✅ (Phase 10; details in [threat-hunting.md](threat-hunting.md#tests))
- Hunt SQL selects exactly what the condition language accepts, row for row, for every
  allowed operator; injection-shaped values match literally; text search can use the
  trigram indexes (this found that the Phase 4 indexes were never usable).
- Every index the migrations build matches its model definition, expressions included
  (`test_schema.py`; Alembic's comparison only notices missing or extra indexes).
- The brief's example question on ingested data, stable keyset paging while events arrive,
  the capped count, alert filters, every template against its scenario and benign data, the
  statement timeout, saved-hunt access and audit.

**Risk, context and coverage** ✅ (Phase 11; `tests/api/test_insights.py`, `test_priority.py`,
`tests/integration/test_alerts.py`, `frontend/tests/coverage.test.tsx`)
- Metrics against alerts with known outcomes and times: counts, false-positive rate,
  median times, the period boundary, every rule listed (no rate until one is closed).
- Coverage: all 15 tactics in order, only mapped techniques, indicator attribution, a
  disabled rule not counting as coverage.
- A privileged target account counts once (unit and with the inventory); an inventory change
  updates the open incident's risk; `rescore` brings open work to the current model and leaves
  closed work alone. Mutation-checked: the rate's denominator, indicator attribution, target
  reprioritization and the incident refresh each have a test that fails without them.

**Detection engineering** ✅ (Phase 12; `tests/api/test_playground.py`,
`frontend/tests/playground.test.tsx`, `frontend/tests/alerts.test.tsx`)
- Playground: a rule firing on sample lines with its explanation and evidence lines, nothing
  stored (row counts unchanged), why a rule did not fire, what-if values accepted within
  bounds and refused outside them, sequence steps per line, exclusions and suppressions
  applied, input bounds, analysts only.
- Suppression windows: edges (start inside, end outside), validation, a tuned suppression
  stopping detection inside its window and not after it. Mutation-checked.
- Grouped queue: counts per rule and per source with filters; the version comparison and the
  suppression editor in the UI.

**Security review** ✅ (Phase 13; `tests/api/test_security_review.py`, `test_ingest_keys.py`,
`tests/integration/test_app_role.py`, CI)
- Every state-changing route needs ANALYST+ or has a stated reason; every request body model
  refuses unknown fields and bounds every string; errors leak no internals; docs off in
  production.
- Ingest keys: issue, use, wrong source, rotation, revocation, never logged or audited; the
  per-source rate limit; the CLI.
- Body limits: by declared length, while streaming (chunked), before authentication, the
  larger ingest limit.
- The application's database role cannot disable triggers, alter, drop, truncate, create, or
  update and delete evidence, and can do everything the application does.
- CI (running stack): the app connects only as the least-privilege role; CSP without
  `unsafe-inline`; no query value in the proxy log; an oversized body refused with nginx
  bypassed; a shipper ingests with its key; every secret, including the ingest key, absent from
  all container logs. Mutation-checked: the key's source binding and the suppression window.

**Residual risks closed** ✅ (Phase 13, after the review; `tests/api/test_mfa.py`,
`tests/integration/test_audit_chain.py`, `test_rate_limit.py`, `tests/api/test_raw_access.py`,
`frontend/tests/security.test.tsx`, `scripts/security_smoke.py`, CI)
- TOTP against the RFC 4226 test vectors; enrolment (a wrong code turns nothing on), sign-in
  needing the code, a code refused the second time, wrong codes locking the account, a
  recovery code working once, turning it off needing password and code, no secret or code in
  the database or audit details.
- Admin password reset: old password and sessions gone, every other route 403 until changed,
  the new password must differ, two-factor still required, the temporary password in no audit
  record. Admin two-factor reset. Neither reset on one's own account.
- Audit hash chain: an edited or deleted entry is found at the right `seq` (the tests turn
  the append-only trigger off as the owner could); a writer cannot choose the hashes;
  concurrent writers keep one chain; removing the newest entries, which the chain alone cannot
  show, is caught by an anchor; anchors are logged only after commit; CLI and API.
- Rate limits shared by two limiter instances (a restart, or replicas); the window slides.
- Raw text withheld from viewers in all four views, shown to analysts and admins.
- A source refuses records naming a host outside its allowlist.
- UI: the code step at sign-in, recovery codes, enrolment showing codes once, turning it off,
  the forced-change screen, the admin resets (with confirmation), the integrity panel
  (intact and broken), "withheld" raw records.
- CI (running stack): the security smoke script end to end; every database connection is
  TLS 1.3, plaintext refused, the server key absent from the backend; the audit chain
  verifies; HSTS sent.

**Test completion and performance** ✅ (Phase 14; `tests/api/test_query_budget.py`,
`tests/unit/test_benchmark_workload.py`, additions across the suites, `frontend/tests/*`)
- A coverage review (backend lines left unexecuted, frontend coverage measured for the first
  time: 88 % lines, 76 % branches) chose behaviour that had no test, not lines for their own
  sake. Added: every refusal of the incident actions (404/409/400, and that none leaves an
  activity entry or audit record), a resolved incident refusing new alerts; AUTH-004 with
  missing or malformed addresses, malformed history, IPv6 /64 comparison; parser shapes
  (sudo/su bookkeeping, "command not allowed", impossible ISO dates, useradd without a name,
  Windows logoff, `DOMAIN\user`); UI: every timeline activity kind, rename/assign/unpin with
  a refusal, closed incidents read-only, missing records, inventory filters and editing, hunt
  value typing and validation messages. Frontend coverage is now 91.7 % lines, 81.2 % branches.
- Query budget: each list endpoint is measured on a small and a five-times-larger data set
  with the session's identity map cleared (as in production); the statement count may not
  grow. **It found three N+1 queries** (asset and identity lists: two statements per row;
  saved hunts: one per hunt), now one statement per page. A second test checks the rewritten
  list figures equal each record's own activity, row by row. Detail pages: an incident with
  five alerts costs what one with one alert costs; long timeline and evidence pages cost
  what short ones cost.
- Bounded responses: every list or page in the OpenAPI schema has a capped `limit`, or is on a
  short list with the reason it cannot grow (mutation-checked). This found two unbounded
  lists, now bounded: rule versions (`limit`, default 100) and saved hunts (100 per user).
- The benchmark workload is tested: deterministic, every record parses, ordinary activity
  alone triggers no rule, every injected attack is detected.
- Per-day summaries (`tests/integration/test_daily_summaries.py`): after ingestion across
  midnight with re-sent duplicates, after hand-made inserts, and after four concurrent batches
  for the same accounts and days, both summary tables equal a fresh `GROUP BY` over the rows;
  the concurrent batches neither deadlock nor lose a count. AUTH-004's history from the
  summary equals reading every earlier event, event by event (mutation-checked); only the
  successful-logon question may use it (tested).

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
- The demo environment (Phase 16, [demo.md](demo.md)): `tests/integration/test_demo_environment.py`
  loads the whole story into PostgreSQL and checks every step's rules, the five incidents,
  the inventory links, that loading again stores nothing, and the audit entries;
  `tests/unit/test_demo.py` checks that the attacks are further apart than the correlation
  window and share no host or outside address. CI loads it on the running stack, loads it
  again, resets it with `scripts/demo_reset.sh` (same counts, accounts kept, audit chain
  intact) and checks the reset refuses a database holding real records.
- Time is injected (`now` / receive time as parameters): no sleeping, no wall-clock
  dependence.

## Commands

Backend (from `backend/`, with `TEST_DATABASE_URL` set): `ruff check .`, `ruff format
--check .`, `mypy`, `pytest --cov=app --cov-fail-under=90`, `pip-audit -r requirements.txt
--require-hashes --disable-pip` (and `requirements-dev.txt`).
Frontend (from `frontend/`): `npm run lint`, `npm run typecheck`, `npm test`, `npm run
build`, `npm audit --audit-level=moderate`.
Frontend coverage (as CI runs it): `npm run test:coverage`.
Against a running stack: `python3 scripts/auth_smoke.py <url> <admin> <password>`,
`python3 scripts/ingest_smoke.py <url> <admin> <password>` and
`python3 scripts/security_smoke.py <url> <admin> <password>`.
Benchmark (own database, never the test or app one): see [performance.md](performance.md#reproducing).
Production configuration and backup: [deployment.md](deployment.md); `tests/unit/test_deployment_docs.py`
fails if a setting, a Compose variable or an `.env.example` entry is not documented there.
The documentation itself (Phase 17): `tests/unit/test_docs.py` fails if a relative link or
its anchor is broken, if `api.md` names a route that does not exist or misses one that does,
or if any document names a CLI command, a script or a rule that does not exist.
CI runs all of these, plus gitleaks over the full history.
