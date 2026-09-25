# Implementation roadmap

Each phase ends with actual test results, a status label for every item (IMPLEMENTED / TESTED /
PARTIALLY IMPLEMENTED / MOCKED / SIMULATED / NOT IMPLEMENTED), and a stop. The next phase
starts only on "Proceed to Phase N".

| Phase | Scope | Exit criteria (verified, not claimed) | Status |
|---|---|---|---|
| 1 | Repository audit, architecture, data model, detection/correlation design, API/UI plan, security and test strategy, ADRs | Docs in `docs/`, reviewed | **Done** (design only) |
| 2 | Foundation: backend skeleton, frontend skeleton, PostgreSQL, SQLAlchemy, Alembic, Compose, config, JSON logging, request IDs, health/ready, CI | `docker compose up` healthy; CI green (lint, types, tests, build, audits, gitleaks) | **Done**, green in CI |
| 3 | Users, roles, login/refresh/logout, RBAC dependencies, audit log (append-only), frontend auth, RBAC matrix test | Auth and RBAC tests green; audit trigger tested | **Done**, green in CI |
| 4 | Assets, identities, `raw_events`/`events` tables, indexes, append-only triggers | Migrations up/down tested; constraints tested | **Done** (see CLAUDE.md for CI status) |
| 5 | Log sources, 5 parsers, normalization, enrichment, ingestion service and API, batch reports, dedup | Golden fixtures per source; malformed/duplicate tests | Not started |
| 6 | Rule schema, condition language, 5 evaluators, rule storage and versions, ATT&CK reference file, 8-rule library, explanations, detection runs | Positive/negative fixtures for every rule; order/split/idempotence tests | Not started |
| 7 | Alerts: dedup, evidence, priority, workflow, alert API and UI | Dedup and transition tests; UI tests | Not started |
| 8 | Correlation, incidents, state machine, notes, evidence pins, assignment, activity, timeline, settings | Chain → one incident; window edges; concurrency test | Not started |
| 9 | SOC dashboard, alert and incident workspaces, event explorer, asset and identity views | All numbers from the DB; empty states; visual check desktop + phone | Not started |
| 10 | Threat hunting: structured queries, templates, pivots, saved hunts, `pg_trgm` | Query compiler tests (incl. injection attempts); pagination tests | Not started |
| 11 | Incident risk, context display, rule metrics (triggers, FP rate, time to resolve), ATT&CK implemented-coverage view | Metric queries tested against known fixtures | Not started |
| 12 | Evaluate and build where justified: detection playground, version diff UI, suppression windows, alert grouping | Each item justified or explicitly deferred | Not started |
| 13 | Security review of all of the above; per-source ingest keys; threat model completed | Findings fixed or recorded as residual risk | Not started |
| 14 | Test completion; controlled benchmark (generated data, `EXPLAIN ANALYZE`) | Numbers recorded with machine spec, none invented | Not started |
| 15 | Production-style images, hardening checks in Compose smoke test, deployment docs | CI runs the production image | Not started |
| 16 | Demo environment: scenario loader, 10 scenarios, reset, SIMULATED labels | Each scenario triggers exactly its documented rules (test) | Not started |
| 17 | README, diagrams, screenshots, guides, limitations, future architecture | Docs match the code | Not started |
| 18 | Full engineering review and fixes | Review report; misleading claims removed | Not started |
| 19 | Interview and portfolio package (in git-ignored `portfolio/`) | Based only on what exists | Not started |

**Ordering note.** A thin slice of the demo generator (brute-force and benign scenarios only)
is built in Phase 5 as test data, because detection needs realistic input before Phase 16.
Phase 16 completes it. This is a change to the brief's ordering, made on purpose.

## Demo scenarios (planned, Phase 16)

Fictional environment: `corp.example`, hosts `web-01` (critical, prod), `db-01` (critical),
`jump-01` (high), `ws-*` workstations (medium), and users with fixed roles and working hours.
Outside addresses come from RFC 5737 ranges.

| # | Scenario | Expected result |
|---|---|---|
| 1 | Normal authentication (working-hours SSH and Windows logons) | No alerts |
| 2 | Brute force against one account | AUTH-001 |
| 3 | Password spraying-like (one source, many accounts, few tries each) | AUTH-003 |
| 4 | Success after failures | AUTH-001 + AUTH-002 → incident |
| 5 | Privilege escalation (sudo root shell) | PRIV-001 |
| 6 | Privileged account creation (useradd → usermod -aG sudo; 4720 → 4732) | ACCT-001 → incident |
| 7 | Suspicious process (encoded PowerShell on a workstation) | PROC-001 → incident |
| 8 | Suspicious network activity (internal host probing ports) | NET-001 |
| 9 | Multi-stage: 2 → 4 → 5 → 6 on `web-01` from one source | One incident, 4 alerts, full timeline |
| 10 | Benign look-alikes (admin's legitimate sudo commands, one typo then success, backup job connections) | No alerts (demonstrates tuning) |

Parameters: scenario, event count/intensity, start time, host, user, source IP, seed.
