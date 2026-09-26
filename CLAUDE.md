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

Scope: **every feature in the brief must exist and work.** `docs/feature-coverage.md` maps each
one to its phase and status; update it at the end of every phase (a phase is not done until
its rows there are true), and never drop a feature silently.

Design: `docs/architecture.md` is the entry point; decisions are in `docs/decisions/`; the phase
plan and exit criteria are in `docs/roadmap.md`. When implementation diverges from a doc,
update the doc (and add an ADR for decisions) in the same change.

## Key design rules (from Phase 1)

- Modular monolith. Pure cores (parsers, normalize, enrich, detection evaluators and
  conditions, explanation, correlation scoring, risk, demo generators) import no
  SQLAlchemy/FastAPI and take `now` as a parameter.
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
- Security-relevant actions call `audit.record()` in the same transaction; never log secrets
  or raw event bodies at INFO.

## Environment (Windows)

Same machine as CloudSentinel (`C:\cloudsentinel`, a separate, finished project whose auth,
audit and CI patterns SentinelX reuses). Its stack uses host ports 5432/8000/8080, so
SentinelX uses **5433 (db) / 8001 (backend) / 8081 (frontend) / 5174 (Vite dev)**.

- Python 3.12 via `py -3.12`; backend venv `backend\.venv`. Node 24.
- Test database: `docker compose up -d db`, database `sentinelx_test`. `backend/.env.test`
  (git-ignored) holds `TEST_DATABASE_URL`; in Git Bash: `export $(cat .env.test)`.
- Use `127.0.0.1`, not `localhost`, in database URLs (IPv6-first lookup is slow here).
- Never commit `.env` or `.env.*` (except `.env.example`).
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
