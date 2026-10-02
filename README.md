# SentinelX

A security operations platform: it ingests security logs, detects attacks with explainable
rules, correlates alerts into incidents, and gives analysts one place to investigate, hunt
and record what they did.

> **Status: all 19 phases complete** ([roadmap](docs/roadmap.md)). Every feature of the brief is
> mapped to its phase and status in [feature-coverage.md](docs/feature-coverage.md).
> It is a **defensive** tool built as a portfolio project. Every attack it has seen is
> SIMULATED: generated log records of a fictional company, sent through the real pipeline and
> labelled as such everywhere. It has not been run against a real environment's logs.

![The incident workspace: four alerts correlated into one incident, each link with its reason, the risk breakdown and the timeline](docs/screenshots/incident-detail.png)

## What it does

```mermaid
flowchart LR
    logs["Security logs<br/>Linux, Windows, web,<br/>JSON"] --> ingest["Ingest<br/>parse, normalize,<br/>enrich"]
    ingest --> store[("Append-only<br/>evidence")]
    store --> detect["Detect<br/>9 rules,<br/>ATT&CK-mapped"]
    detect --> alerts["Alerts<br/>deduplicated,<br/>prioritized"]
    alerts --> incidents["Incidents<br/>correlated with<br/>a reason per link"]
    incidents --> analyst["Analyst<br/>investigate, hunt,<br/>respond"]
    analyst --> audit[("Hash-chained<br/>audit log")]
```

- **Ingestion**: five formats (Linux auth.log, Windows Security events as JSON, nginx/Apache
  access logs, application JSON, generic JSON). Formats come in through an API with
  per-source keys, a file or the demo generator. Every raw record is kept as exact bytes,
  even when it fails to parse ([event-model.md](docs/event-model.md)).
- **Detection**: nine reviewed YAML rules using five evaluator kinds: single event,
  threshold, distinct count, sequence and new value. The rules cover brute force, password
  spraying, distributed brute force, success after failures, logons from new networks, sudo
  root shells, privileged account creation, suspicious command lines and port scans. Every
  detection explains itself in a sentence and maps to MITRE ATT&CK v19.2
  ([detection-engine.md](docs/detection-engine.md), [mitre.md](docs/mitre.md)).
- **Alerts**: one open alert per activity (deduplicated by evidence), ordered by a
  transparent priority score (severity, confidence, asset criticality, privileged
  accounts), with a status workflow and false-positive tracking
  ([risk-model.md](docs/risk-model.md)).
- **Incidents**: alerts that share a host and account, a host and source, or an outside
  address are linked into one incident, each link with its reason. The timeline is rebuilt
  from the stored events. Analysts can add notes and pin evidence, assign the incident and
  move it through its statuses ([correlation.md](docs/correlation.md)).
- **Threat hunting**: structured queries over the event store, reviewed templates, pivots
  from any value, saved and shared hunts ([threat-hunting.md](docs/threat-hunting.md)).
- **Detection engineering**: a playground to test a rule on sample lines, version history
  and comparison, admin tuning within each rule's bounds, time-boxed suppressions, and an
  implemented ATT&CK coverage view.
- **Security**:
  - Argon2id passwords, optional TOTP two-factor sign-in and role-based access enforced by
    the backend (viewer, analyst, admin).
  - Every security-relevant action audited in a hash-chained, append-only log.
  - TLS to the database, a least-privilege database role, and hardened containers
    ([security.md](docs/security.md)).

## Screenshots

From the demo environment (SIMULATED data), taken with `scripts/screenshots.mjs`.

| | |
|---|---|
| ![SOC dashboard](docs/screenshots/dashboard.png) **Dashboard**: open work, top rules and sources, trends | ![Alert queue](docs/screenshots/alerts.png) **Alerts**: ordered by priority score |
| ![Alert detail](docs/screenshots/alert-detail.png) **Alert**: explanation, evidence, priority breakdown, ATT&CK, response steps | ![Incident queue](docs/screenshots/incidents.png) **Incidents**: by risk |
| ![Threat hunting](docs/screenshots/hunt.png) **Hunt**: everything one outside address did this week | ![Detection playground](docs/screenshots/playground.png) **Playground**: why a rule fires on sample lines |
| ![Detection rules](docs/screenshots/detections.png) **Detections**: the rule library and its health | ![ATT&CK coverage](docs/screenshots/coverage.png) **Coverage**: implemented ATT&CK coverage |
| ![Audit log](docs/screenshots/audit.png) **Audit log**: hash chain verified | ![Incident on a phone](docs/screenshots/incident-phone.png) **Phone width** |

## Quick start

Requirements: Docker with Compose v2. Full guide: [docs/setup.md](docs/setup.md).

```bash
git clone https://github.com/Sid0153/sentinelx.git && cd sentinelx
cp .env.example .env
# fill in POSTGRES_PASSWORD and APP_DB_PASSWORD (openssl rand -hex 24) and SECRET_KEY (openssl rand -hex 32)
docker compose up -d --build --wait
docker compose exec backend python -m app.cli create-admin --email you@example.com
docker compose exec backend python -m app.cli demo-load
```

Open http://localhost:8081 and sign in. The demo is a fictional company with three days of
ordinary activity and one example of every attack scenario: about 1,040 records, 15 alerts
and 5 incidents. [docs/demo.md](docs/demo.md) walks through a demonstration;
`scripts/demo_reset.sh` starts it over and keeps the accounts.

Every port is bound to 127.0.0.1: 8081 (the app), 8001 (the API directly, with its docs at
`/api/docs` in development) and 5433 (PostgreSQL). The production configuration (https,
production settings, only the site published) and backups:
[docs/deployment.md](docs/deployment.md).

## Architecture

A modular monolith: one FastAPI backend, one React single-page app behind nginx, and one
PostgreSQL database, run with Docker Compose. Ingestion stores evidence in its own
transaction, so detection can never lose it. Detection then re-reads its windows from the
database, which makes it stateless and safe to re-run. Alerts and correlation happen in the
same transaction as detection, so a batch's results appear all at once or not at all.
[docs/architecture.md](docs/architecture.md) has the diagrams, the module boundaries, the
pipeline and its failure modes. [docs/future-architecture.md](docs/future-architecture.md)
covers how it would scale and connect to real sources, and what would trigger each step.
The decisions and their alternatives are in [docs/decisions/](docs/decisions/README.md)
(15 ADRs).

## API

REST under `/api`, every route behind a role checked by the backend. The route table and
roles are in [docs/api.md](docs/api.md), and the OpenAPI document is
[docs/openapi.json](docs/openapi.json) (a test fails if it is stale). A test also fails if a
route is missing from the access table. Log shippers post batches to
`POST /api/ingest/{source_id}` with that source's `X-Ingest-Key`.

## Testing

- **Backend**: 1,427 tests at 98% line coverage. API and integration tests run on a real
  PostgreSQL, not a mock. They cover parsers against malformed input, each rule on its
  scenario, real concurrency, query budgets, the RBAC table and the audit chain.
- **Frontend**: 117 tests with coverage floors. Every page passes an axe WCAG 2 AA audit
  ([review.md](docs/review.md)).
- **CI**: on every push, lint, types, dependency audits, a secret scan and an image
  vulnerability scan. It also starts the development stack and the production configuration
  (over https) and runs end-to-end scripts, a backup and restore, and a demo load and reset.

Strategy: [docs/testing.md](docs/testing.md). Measured performance on 1 million generated
records (713 records/s through the full pipeline, paged reads in 8–27 ms):
[docs/performance.md](docs/performance.md).

## Limitations

A lab-scale platform, not a SIEM: one host, five log formats, nine rules, simulated data
only, no retention policy, no lateral-movement correlation, no notifications. The full list,
with reasons: [docs/limitations.md](docs/limitations.md).

## Develop

Backend (Python 3.12), from `backend/`:

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows; on Linux/macOS: source .venv/bin/activate
pip install --require-hashes -r requirements-dev.txt
docker compose up -d db           # from the repository root
# once: docker compose exec db psql -U sentinelx -c "CREATE DATABASE sentinelx_test"
export TEST_DATABASE_URL=postgresql+psycopg://sentinelx:PASSWORD@127.0.0.1:5433/sentinelx_test
ruff check . && mypy && pytest --cov=app
```

Frontend (Node 24), from `frontend/`: `npm ci`, then `npm run dev` (http://localhost:5174,
proxies `/api` to the Compose backend), `npm test`, `npm run lint`, `npm run typecheck`,
`npm run build`.

## Documentation

| Document | Contents |
|---|---|
| [setup.md](docs/setup.md) | **Setup guide**: install, first admin, demo, sending your own logs, troubleshooting |
| [demo.md](docs/demo.md) | **Demo guide**: the company, the story and its expected results, a walkthrough, reset |
| [feature-coverage.md](docs/feature-coverage.md) | Every feature of the brief, its phase and its status |
| [architecture.md](docs/architecture.md) | Diagrams, modules, pipeline, failure modes, frontend, observability, scale limits |
| [future-architecture.md](docs/future-architecture.md) | Queue, parallel detection, partitioning, search, more sources, HA, and what triggers each |
| [limitations.md](docs/limitations.md) | What SentinelX does not do, in one place |
| [event-model.md](docs/event-model.md) | Normalized schema, supported sources, duplicates, enrichment |
| [detection-engine.md](docs/detection-engine.md) | Rule format, evaluator kinds, the 9-rule library and its known weaknesses, alerts, dedup, workflow |
| [correlation.md](docs/correlation.md) | Alert → incident correlation, incident lifecycle, timeline |
| [threat-hunting.md](docs/threat-hunting.md) | Structured hunt queries, templates, pivoting, limits |
| [mitre.md](docs/mitre.md) | ATT&CK mappings, verified against attack.mitre.org (v19.2) |
| [risk-model.md](docs/risk-model.md) | SentinelX priority score (project-specific, not an industry standard) |
| [security.md](docs/security.md) | Authentication, RBAC, audit, the Phase 13 review, threat model, residual risks |
| [api.md](docs/api.md) | Routes and roles |
| [database-schema.md](docs/database-schema.md) | Tables, integrity rules, indexes |
| [testing.md](docs/testing.md) | Test strategy |
| [performance.md](docs/performance.md) | Measured throughput and read latency on 1 million records |
| [deployment.md](docs/deployment.md) | Production configuration, TLS, configuration reference, backup and restore, upgrades |
| [decisions/](docs/decisions/README.md) | Architecture decision records |
| [review.md](docs/review.md) | The final engineering review: what was checked, what was found, what was fixed or accepted |
| [repository-assessment.md](docs/repository-assessment.md) | What existed before SentinelX, and what was reused from CloudSentinel |

## Stack

FastAPI · SQLAlchemy · Alembic · PostgreSQL 16 · Pydantic · pytest ·
React · TypeScript · Vite · Tailwind · Docker Compose · GitHub Actions
