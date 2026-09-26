# SentinelX

Security operations platform for detection, correlation, threat hunting and incident response.

> **Status: Phase 5 (ingestion and parsing) complete.** Sign-in and roles, the audit log,
> the asset and identity inventory, and **ingestion**: five log formats parsed, normalized and
> enriched into an append-only event store, with batch reports and an events API. **Nothing
> detects yet**: detection arrives in Phase 6. The UI has no event or ingestion pages yet
> (Phase 9); use the API or the CLI below.
> [docs/roadmap.md](docs/roadmap.md) tracks what is built and what is not.

SentinelX is designed to:
- ingest security logs: Linux auth.log, Windows security events (JSON), web access logs,
  application JSON, generic JSON
- parse and normalize them into one event model, keeping the raw record as evidence
- enrich events with asset and identity context
- run declarative detection rules (single-event, threshold, distinct-count, sequence,
  new-value)
- deduplicate and prioritize the resulting alerts
- correlate alerts into incidents with a stated reason for every link
- give analysts an investigation workspace (timeline, evidence, notes, ATT&CK mapping,
  response guidance) and a threat-hunting interface
- audit every security-relevant action

It is a **defensive** tool. All attack scenarios are simulated log records sent through the
normal pipeline. There is no offensive capability of any kind.

## Run it locally

Requirements: Docker with Compose v2.

```bash
cp .env.example .env
# set POSTGRES_PASSWORD (openssl rand -hex 24) and SECRET_KEY (openssl rand -hex 32) in .env
docker compose up -d --build --wait
```

- Create the first admin (there is no self-registration; the password is prompted, hidden):
  `docker compose exec backend python -m app.cli create-admin --email you@example.com`
- App: http://localhost:8081 (sign in, then: system status, users, audit log, account)
- API health: http://localhost:8081/api/health · readiness: http://localhost:8081/api/ready
- API docs (development only): http://localhost:8001/api/docs
- Ingest simulated activity (marked SIMULATED everywhere) or a real log file:

  ```bash
  docker compose exec backend python -m app.cli create-source --name web-01-auth --type linux_auth
  docker compose exec backend python -m app.cli demo-scenarios
  docker compose exec backend python -m app.cli demo-ingest --scenario brute_force_success       --source web-01-auth --host web-01 --user root --source-ip 203.0.113.45 --count 12
  curl -X POST http://localhost:8081/api/ingest/<source-id> -H "Authorization: Bearer <token>"        -H "Content-Type: text/plain" --data-binary @auth.log
  ```

Every port is bound to 127.0.0.1. The host ports (5433, 8001, 8081) are chosen so the stack
can run next to others that use the usual 5432, 8000 and 8080.

## Develop

Backend (Python 3.12), from `backend/`:

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows; on Linux/macOS: source .venv/bin/activate
pip install --require-hashes -r requirements-dev.txt
docker compose up -d db           # from the repository root
# create a scratch database once: docker compose exec db psql -U sentinelx -c "CREATE DATABASE sentinelx_test"
export TEST_DATABASE_URL=postgresql+psycopg://sentinelx:PASSWORD@127.0.0.1:5433/sentinelx_test
ruff check . && mypy && pytest --cov=app
```

Frontend (Node 24), from `frontend/`: `npm ci`, then `npm run dev` (http://localhost:5174,
proxies `/api` to the Compose backend), `npm test`, `npm run lint`, `npm run typecheck`,
`npm run build`.

## Documentation

| Document | Contents |
|---|---|
| [feature-coverage.md](docs/feature-coverage.md) | **Every feature of the brief, its phase and its status** |
| [architecture.md](docs/architecture.md) | System shape, modules, pipeline, failure modes, frontend, observability, scale limits, extension plan |
| [event-model.md](docs/event-model.md) | Normalized schema, supported sources, duplicates, enrichment |
| [detection-engine.md](docs/detection-engine.md) | Rule format, evaluator kinds, the 8-rule library, alerts, dedup, workflow |
| [correlation.md](docs/correlation.md) | Alert → incident correlation, incident lifecycle, timeline |
| [threat-hunting.md](docs/threat-hunting.md) | Structured hunt queries, templates, pivoting, limits |
| [risk-model.md](docs/risk-model.md) | SentinelX priority score (project-specific, not an industry standard) |
| [mitre.md](docs/mitre.md) | ATT&CK mappings, verified against attack.mitre.org (v19.2) |
| [database-schema.md](docs/database-schema.md) | Tables, integrity rules, indexes |
| [api.md](docs/api.md) | Routes and roles (implemented and planned) |
| [security.md](docs/security.md) | Auth, RBAC, audit, threat model |
| [testing.md](docs/testing.md) | Test strategy |
| [decisions/](docs/decisions/README.md) | Architecture decision records |
| [repository-assessment.md](docs/repository-assessment.md) | What existed before SentinelX, and what was reused from CloudSentinel |

## Stack

FastAPI · SQLAlchemy · Alembic · PostgreSQL 16 · Pydantic · pytest ·
React · TypeScript · Vite · Tailwind · Docker Compose · GitHub Actions
