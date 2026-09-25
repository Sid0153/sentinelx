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
| 2 Foundation | Done locally (46 backend tests, 96% coverage; 12 frontend tests; Compose smoke checks run by hand). CI written, not yet run: no GitHub remote yet |

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
- Do not run `ruff format` on existing files unless the file is already format-clean.
