# SentinelX

Security operations platform for detection, correlation, threat hunting and incident response.

> **Status: Phase 2 (foundation) complete.** The backend, frontend, database, migrations,
> Docker Compose stack, structured logging, health checks and CI are in place. **No security
> features exist yet**: no sign-in, ingestion, detection or incidents.
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
# set POSTGRES_PASSWORD in .env, e.g. to the output of: openssl rand -hex 24
docker compose up -d --build --wait
```

- App: http://localhost:8081 (currently the system status page)
- API health: http://localhost:8081/api/health · readiness: http://localhost:8081/api/ready
- API docs (development only): http://localhost:8001/api/docs

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
| [architecture.md](docs/architecture.md) | System shape, modules, pipeline, failure modes, frontend, observability, scale limits, extension plan |
| [event-model.md](docs/event-model.md) | Normalized schema, supported sources, duplicates, enrichment |
| [detection-engine.md](docs/detection-engine.md) | Rule format, evaluator kinds, the 8-rule library, alerts, dedup, workflow |
| [correlation.md](docs/correlation.md) | Alert → incident correlation, incident lifecycle, timeline |
| [risk-model.md](docs/risk-model.md) | SentinelX priority score (project-specific, not an industry standard) |
| [mitre.md](docs/mitre.md) | ATT&CK mappings, verified against attack.mitre.org (v19.2) |
| [database-schema.md](docs/database-schema.md) | Tables, integrity rules, indexes |
| [api.md](docs/api.md) | Routes and roles (implemented and planned) |
| [security.md](docs/security.md) | Auth, RBAC, audit, threat model |
| [testing.md](docs/testing.md) | Test strategy |
| [decisions/](docs/decisions/README.md) | Architecture decision records |

## Stack

FastAPI · SQLAlchemy · Alembic · PostgreSQL 16 · Pydantic · pytest ·
React · TypeScript · Vite · Tailwind · Docker Compose · GitHub Actions
