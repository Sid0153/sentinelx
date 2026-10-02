# SentinelX: instructions for Claude Code

Read `SENTINELX_MASTER_PROMPT.md` first (git-ignored, personal). It is the project brief, and
its rules always apply:
- work phase by phase and STOP after each phase until told "Proceed to Phase N"
- report ACTUAL test results
- label everything IMPLEMENTED / TESTED / MOCKED / SIMULATED / PARTIALLY IMPLEMENTED /
  NOT IMPLEMENTED
- never claim something works without verifying it
- end each phase with the report format in section 51 of the brief

## Current state

| Phase | Status |
|---|---|
| 1 Architecture | Done (design docs only, no code) |
| 2 Foundation | Done, green in CI (46 backend tests, 96% coverage; 12 frontend tests; Compose smoke test incl. DB outage). Repo: https://github.com/Sid0153/sentinelx (public) |
| 3 Auth and RBAC | Done, green in CI (168 backend tests, 98% coverage; 39 frontend tests; auth smoke script and forged-XFF checks on both ports in the Compose job) |
| 4 Assets, identities, event model | Done, green in CI (311 backend tests, 97.8% coverage; 39 frontend tests; migration 0003 applied on the Compose stack) |
| 5 Ingestion and parsing | Done, green in CI (497 backend tests, 97% coverage; 39 frontend tests; ingest and auth smoke scripts in the Compose job) |
| 6 Detection engine | Done, green in CI (9 rules; 735 backend tests, 98% coverage; 39 frontend tests; every scenario triggers exactly its rules on the live stack; detection checked in the Compose smoke test) |
| 7 Alerts | Done, green in CI (857 backend tests incl. real-concurrency tests, 98% coverage; 47 frontend tests; alerts checked in the Compose smoke test; alert pages checked at desktop and phone widths) |
| 8 Correlation and incidents | Done, green in CI (1007 backend tests incl. real-concurrency tests, 98% coverage; 56 frontend tests; correlation checked in the Compose smoke test; pages checked at desktop and phone widths) |
| 9 Dashboard and investigation workspace | Done, green in CI (1028 backend tests, 98% coverage; 74 frontend tests; dashboard, events, assets, identities, detections checked on the live stack at phone width) |
| 10 Threat hunting | Done, green in CI (1133 backend tests, 98% coverage; 82 frontend tests; hunts and templates checked on the live stack at desktop and phone widths) |
| 11 Risk, context, coverage | Done, green in CI (1153 backend tests, 98% coverage; 87 frontend tests; risk model 3; coverage, metrics and context checked on the live stack) |
| 12 Advanced detection engineering | Done, green in CI (1178 backend tests, 98% coverage; 95 frontend tests; playground examples fire their rules on the live stack; ADR-0013) |
| 13 Security hardening | Done, green in CI (1254 backend, 105 frontend tests, 98% coverage; nine-area review in docs/security.md; least-privilege DB role, ingest keys, body limits; then every listed residual risk fixed or mitigated: 2FA, admin reset, shared rate limits, audit hash chain, host allowlist, raw text analyst-only, DB TLS, HSTS, digest pins) |
| 14 Testing and performance | Done, green in CI (1288 backend tests, 98% coverage; 115 frontend tests, 91.7% lines, floors in CI; query-budget tests found 3 N+1 queries and 2 unbounded lists, fixed; 1M-record benchmark in docs/performance.md found AUTH-004 failing past 20k earlier logons, fixed; per-day summaries kept by triggers make detection and the dashboard flat: 713 records/s) |
| 15 Deployment readiness | Done, green in CI (image scan found 71 fixable HIGH CVEs, fixed and gated in CI; database container hardened, gosu removed; production overlay with TLS run by CI over https; backup/restore scripts tested in CI; docs/deployment.md with a test-enforced configuration reference; ADR-0014) |
| 16 Demo environment | Done, green in CI (`cli demo-load`: inventory, sources, a 13-step story anchored to one time, ~1,040 records → 15 alerts, 5 incidents at any anchor, tested per step; `scripts/demo_reset.sh` replaces the database, refuses real data, keeps accounts; ADR-0015; docs/demo.md) |
| 17 Documentation and polish | Done, green in CI (README rewritten with screenshots from `scripts/screenshots.mjs` and a diagram; Mermaid diagrams in architecture.md; setup.md, limitations.md, future-architecture.md; stale statuses and a never-built demo API removed from the docs; `tests/unit/test_docs.py` checks links, routes, commands, scripts and rule names; audit log labels request-less entries "system") |
| 18 Final engineering review | Done (docs/review.md: 13 findings, 7 fixed: WCAG AA contrast on every page (axe: 0 violations on 16 pages), chart and link accessibility, a page error boundary, the pure-core claim made true and enforced by tests/unit/test_architecture.py, CI actions pinned by SHA and gitleaks by digest; 6 accepted with reasons; 1427 backend, 117 frontend tests) |
| 19 Interview and portfolio package | Done, in git-ignored `portfolio/` (explanations, deep dives, 32 Q&A, resume/GitHub text, demo script; facts from the Phase 18 state; update it if the project changes) |

Scope: **every feature in the brief must exist and work.** `docs/feature-coverage.md` maps each
one to its phase and status; update it at the end of every phase (a phase is not done until
its rows there are true), and never drop a feature silently.

Design: `docs/architecture.md` is the entry point; decisions are in `docs/decisions/`; the phase
plan and exit criteria are in `docs/roadmap.md`. When implementation diverges from a doc,
update the doc (and add an ADR for decisions) in the same change.

## Key design rules (from Phase 1)

- Modular monolith. Pure cores (parsers, normalize, evaluators, evaluate, explanation,
  correlation scoring, risk, the workflows, demo generators) import no SQLAlchemy/FastAPI/
  database module (enums from models only) and take `now` as a parameter; `conditions.py`
  (builds SQL expressions) and `enrich.py` (`load_snapshot` only) are the two documented
  exceptions. `tests/unit/test_architecture.py` enforces this and that each record type
  (RawEvent, Event, Alert, Incident, AuditLog) is built in one module only.
- Raw records go in `raw_events` (always, even on parse failure); normalized ones in `events`.
  Both are append-only (DB triggers), as are the audit log, incident notes, evidence and
  activity.
- Detection is stateless and idempotent: it re-reads windows from PostgreSQL, uses event time,
  runs under an advisory lock, and relies on unique evidence links and dedup keys.
- Rules are YAML data plus five evaluator kinds. No eval, no user-supplied regex, admin edits
  only to `tunable` fields; every change versioned and audited.
- Correlation links alerts to incidents by entity overlap within a window and stores a reason
  per link. Incidents are never auto-merged.
- Priority/risk score is "SentinelX priority score", never an industry standard; bump
  `RISK_MODEL_VERSION` on weight changes.
- ATT&CK: pinned version (v19.2 at design time), mappings verified on attack.mitre.org, UI
  says "Implemented coverage".
- Demo data = simulated raw log lines through the real pipeline, RFC 5737 outside IPs,
  labelled SIMULATED.
- Every API route in the RBAC access table test; backend is authoritative.
- List endpoints must not query per row (`tests/api/test_query_budget.py` measures statements
  on a small and a larger data set) and every list must be bounded: a capped `limit`, or an
  entry in `NATURALLY_BOUNDED` with the reason. Add new list routes to `LIST_ROUTES` there.
- A `new_value` rule's match must be exact in SQL and name stored columns (validated): the
  engine counts its history in SQL (`engine._history`); keep it exact (tested against reading
  every earlier event).
- `event_daily_counts` and `logon_success_daily` are written only by the triggers on
  `events` and `raw_events` (migration 0014); never write them from Python. A new way of
  removing events (retention) must update them too.
- Benchmarks: `backend/benchmarks/run.py`, only against a database named `*_bench` (it drops
  and recreates it). Never claim a number that is not in a results file under
  `docs/benchmarks/`. Do not run tests or builds during a benchmark run.
- Production configuration: `docker-compose.prod.yml` on top of `docker-compose.yml`
  (`COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml`); CI's `production` job runs it.
  nginx headers and routing live only in `frontend/nginx/app.conf` (both configurations
  include it). A new setting or Compose variable must be documented in docs/deployment.md
  (`tests/unit/test_deployment_docs.py`).
- Demo environment (`app/demo/environment.py`): a new attack step must stay more than the
  correlation window from its neighbours, on its own host and outside address
  (`tests/unit/test_demo.py`), and list what it triggers; update the tables in docs/demo.md
  and the totals CI greps for. `scripts/demo_reset.sh` must keep refusing databases with
  real records (`cli demo-status`).
- Accessibility: secondary text is `text-slate-400` (not 500) and primary buttons `bg-sky-700`,
  for WCAG AA contrast on the dark theme. A chart with focusable parts is a labelled `group`,
  not an `img`. Re-run the axe audit described in docs/review.md after visual changes.
- CI actions are pinned by commit SHA (release in a comment) and images by digest: change
  both together.
- Docs are tested (`tests/unit/test_docs.py`): a renamed heading, route, CLI command, script
  or rule must be updated in every document that names it. `api.md` must list every route
  with its full path. Screenshots come from `scripts/screenshots.mjs` on a throwaway stack
  with the demo loaded and a throwaway account (its email appears in the pictures).
- Restores go into an empty database (`scripts/restore.sh`): never load data into a migrated
  database, or the audit chain is recomputed and the daily summaries count twice.
- Every image must pass `trivy image --severity HIGH,CRITICAL --ignore-unfixed` (CI). The
  database runs as uid 70 without gosu; keep it that way.
- Frontend tests have a 20 s per-test timeout (whole-app renders under coverage on slow
  runners); a test that needs more is a bug.
- Security-relevant actions call `audit.record()` in the same transaction; never log secrets
  or raw event bodies at INFO.
- The app connects as a least-privilege DB role (`APP_DB_USER`, rows only; Phase 13);
  migrations and `cli setup-app-role` use the owner (`MIGRATION_DATABASE_URL`). New tables are
  granted automatically at startup; a new append-only table must also be added to
  `APPEND_ONLY_TABLES` in `app/database/roles.py`. Request bodies are capped at 1 MiB by the
  backend (`BodyLimitMiddleware`); every request model must forbid unknown fields and bound
  every string (`tests/api/test_security_review.py` checks both). nginx logs paths only.
- Audit log is hash-chained by a trigger (`audit_chain()`, migration 0011): never set `seq`,
  `prev_hash` or `entry_hash` from Python, and change `audit_entry_digest()` only with a new
  migration that keeps old entries verifiable. `cli verify-audit` checks it.
- Raw record text goes through `can_read_raw_records(user)` (analysts and admins); a new view
  of raw text must withhold it from viewers the same way.
- Users with `must_change_password` reach only `PASSWORD_CHANGE_ROUTES` (`auth/deps.py`). TOTP
  secrets derive from `SECRET_KEY` (rotating it ends 2FA enrolments).
- Compose database is TLS-only (`db/pg_hba.conf`; certificates from the `db-certs` service);
  the backend URLs use `sslmode=verify-full&sslrootcert=/tls-ca/ca.crt`. Base images are
  pinned by digest (Dependabot updates them): change tag and digest together.

## Environment (Windows)

Same machine as CloudSentinel (`C:\cloudsentinel`, a separate, finished project whose auth,
audit and CI patterns SentinelX reuses). Its stack uses host ports 5432/8000/8080, so
SentinelX uses **5433 (db) / 8001 (backend) / 8081 (frontend) / 5174 (Vite dev)**.

- Python 3.12 via `py -3.12`; backend venv `backend\.venv`. Node 24.
- Test database: `docker compose up -d db`, database `sentinelx_test`. `backend/.env.test`
  (git-ignored) holds `TEST_DATABASE_URL`; in Git Bash: `export $(cat .env.test)`.
- Use `127.0.0.1`, not `localhost`, in database URLs (IPv6-first lookup is slow here).
- Never commit `.env` or `.env.*` (except `.env.example`).
- The local `.env` needs `APP_DB_PASSWORD` (Compose refuses to start without it).
- In Git Bash, `docker run -v` and `docker compose exec` paths need `MSYS_NO_PATHCONV=1`.

## Checks before every commit

Backend (from `backend/`): `ruff check .`, `mypy`, `pytest --cov=app` (with
TEST_DATABASE_URL; CI fails under 90%), `pip-audit -r requirements.txt --require-hashes
--disable-pip` (and `requirements-dev.txt`).
Frontend (from `frontend/`): `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`,
`npm audit --audit-level=moderate`.
CI (`.github/workflows/ci.yml`) also runs gitleaks and a Compose smoke test (hardening,
headers, error shape, DB outage → 503 and recovery).
After changing an API route or schema: `python -m app.cli export-openapi` (from `backend/`)
and update `docs/api.md`; a test fails if `docs/openapi.json` is stale.

## Conventions

- Errors: raise `app.core.errors.AppError(status, message)`; every error body is
  `{"error": {"code", "message", "request_id", "details"?}}`. Validation errors never echo
  input. Unhandled exceptions become a generic 500 in `RequestContextMiddleware`.
- Logging: `logger.info("area.event_name", extra={"fields": {...}})`. JSON lines with request
  ID; redaction is a safety net, not permission to log secrets. Never log query strings or
  raw event bodies at INFO.
- Dependencies are locked. Backend: edit `requirements*.in`, then run the `uv pip compile`
  command at the top of the `.txt` lockfile; install with `pip install --require-hashes`.
  Frontend: `npm ci`; `package-lock.json` is committed.
- Frontend: API calls in `src/services/` via `apiRequest` (`ApiError` carries code and
  request ID), types in `src/types/api.ts`, pages load with `useApi`. Tests render the whole
  app with `tests/renderApp.tsx` and mock fetch per route with `tests/mockApi.ts` (unmocked
  calls fail the test). The nav lists only pages that exist.
- The backend is format-clean and CI runs `ruff format --check`: format everything you touch.
  `scripts/` uses the backend config: `ruff check --config backend/pyproject.toml scripts`.
- Security-relevant actions call `app.audit.service.record()` before the commit that saves the
  change (same transaction). Never put secrets in `details`. `audit_logs` is append-only (DB
  triggers): tests must not clean it up with DELETE.
- Every new API route must be added to `EXPECTED_ACCESS` or `PUBLIC_ROUTES` in
  `backend/tests/api/test_rbac.py`. Role checks: `CurrentUser` / `AnalystUser` / `AdminUser`
  from `app.auth.deps` (backend is authoritative; the UI only hides controls).
- Client IP: `app.core.middleware.client_ip(request)` / `client_ip_var`. Never read
  X-Forwarded-For yourself. Compose trusts only nginx at 172.28.0.10.
- Local test accounts for the Compose stack live in the git-ignored `.env.local`
  (`LOCAL_ADMIN_EMAIL` / `LOCAL_ADMIN_PASSWORD`); never print them in chat.
- Lists return `Page[T]` (`items`, `total`, `limit`, `offset`).
- Event model: `app/events/schema.py` (`NormalizedEvent`, controlled `ACTIONS` per category) is
  pure; `app/events/store.py` is the only writer of `raw_events` / `events`. Raw records are
  bytes (`raw_data`), never text. `raw_events`, `events` and `audit_logs` reject UPDATE, DELETE
  and TRUNCATE (ADR-0010): tests never clean them up.
- Admin input schemas use `extra="forbid"`; PATCH schemas list nullable fields in `CLEARABLE`.
- Ingestion: parsers are pure (`app/ingestion/parsers/`, registry in `__init__.py`); every
  record ends PARSED / SKIPPED / FAILED with a fixed reason code, never record text. Regexes
  must be anchored with bounded repetition (the linear-time test covers each parser). The
  store never flushes: `ingestion/service.py` flushes raw records before adding events.
- CLI tests use the `cli_sessions` fixture (CLI sessions become savepoints of the test
  transaction); never let tests commit rows into append-only tables for real.
- Sample and demo data is synthetic: RFC 5737 outside addresses, 10.0.0.0/8 inside,
  `corp.example`; ingesting it through `demo-ingest` marks it simulated.
- After changing a model: create a migration (`alembic revision --autogenerate`, then review);
  `tests/integration/test_schema.py` fails if models and migrations differ. Update
  `docs/database-schema.md`.
- Migrations must not change once committed. An uncommitted one may be edited, but then
  recreate the scratch database (`DROP DATABASE sentinelx_test` / `CREATE DATABASE ...`).
- Detection (`app/detection/`): conditions, evaluators, explain and the library loader are
  pure; `engine.py` is the only code that reads events for rules; `storage.py` the only code
  that writes rules. A new rule needs a YAML file named after its ID, techniques present in
  `attack_techniques.yaml` (pinned; re-check on attack.mitre.org before changing), a demo
  scenario listing it in `expected_rules`, and unit tests. Tests needing rules in the
  database use the `seeded_rules` fixture.
- Condition language: Python evaluation is authoritative; `to_sql()` must select a superset.
  Compare text with `fold()` (ASCII only), never `casefold()`/`lower()`; a column may skip
  folding in SQL only if listed in `LOWERCASE_COLUMNS`. `test_condition_sql.py` must stay
  green: add awkward values there when adding an operator or field.
- Alerts (`app/alerts/`): `service.py` is the only writer of alerts and runs inside the
  detection run's transaction. Dedup rules are in ADR-0011: evidence already linked to an
  alert with the key means "unchanged"; one open alert per key is a partial unique index.
  Status changes go through `workflow.check()` and are audited; the alert page's history
  comes from the audit log. Priority is `app/risk/priority.py`: changing a weight means
  bumping `RISK_MODEL_VERSION` and recording the new fingerprint in `tests/unit/test_priority.py`.
  Inventory changes that can affect priority must call `alerts.reprioritize_for_asset/identity`
  before their commit.
- Tests that need real concurrent transactions use a throwaway database (see
  `tests/integration/test_alert_concurrency.py`); never commit into the shared test database.
- Correlation and incidents (ADR-0009, ADR-0012): `correlation/scoring.py` is pure (link strength
  and reason); `correlation/service.py` runs inside the detection run's transaction; only
  `incidents/records.py` and `incidents/service.py` write incidents. Every analyst action writes an
  `incident_activity` row and an audit entry in the same transaction; notes, evidence and activity
  are append-only. Sessions do not autoflush: flush after a write that later lookups in the same
  pass must see (a missing flush once opened two incidents for one alert).
- Frontend layout: grid and flex children holding tables or long text need `min-w-0`, or the
  page scrolls sideways on phones (found live in Phase 7).
- Doc edits: check that they applied. A chained command that fails before a doc edit leaves the
  docs stale without an error (this happened in Phase 3).
