# Architecture

> Status: **Phase 2 foundation implemented** (app skeleton, config, logging, errors, health,
> migrations baseline, Compose, CI). Everything else is still design. Each section says which
> phase builds it. This file is updated as phases land, and anything that changes during
> implementation is recorded in `docs/decisions/`.

SentinelX is a security operations platform. It ingests security logs, normalizes them into
one event model, runs detection rules over them, groups the resulting alerts into incidents,
and gives analysts a place to investigate, hunt and record what they did.

It is a **modular monolith** ([ADR-001](decisions/0001-modular-monolith.md)): one FastAPI
service, one React single-page app and one PostgreSQL database
([ADR-002](decisions/0002-postgresql-event-store.md)).

```
                 Linux auth.log   Windows events (JSON)   nginx/Apache access logs
                 app JSON logs    generic JSON events      demo generator (simulated)
                         │                 │                        │
                         └───── file upload / API batch / CLI ──────┘
                                           │
Browser ──► nginx (frontend) ──/api──► FastAPI ─────────────────────► PostgreSQL
                                           │
                     ingest → parse → normalize → enrich → store
                                           │
                             detection → alerts → correlation → incidents
                                           │
                              risk/context · ATT&CK · audit log
```

## Why this shape

The work is I/O-bound and the data is relational: events point to assets and identities,
alerts point to events, incidents point to alerts, and everything points to users and the
audit log. A single PostgreSQL database gives transactions across all of that. For example,
"alert created + evidence linked + incident updated" either all happens or none of it does.
With several services and a message bus we would need sagas to get the same guarantee.
Correlation is a set of joins and window queries, which PostgreSQL does well at the volumes
this project handles (up to roughly tens of millions of events on one machine; see "Scale
limits" below).

Module boundaries are drawn so that a component could later become its own process without a
rewrite:
- **Ingestion** hands the rest of the system only `NormalizedEvent` objects.
- **Detection** consumes events and produces `Detection` objects. It has no HTTP code and does
  not decide how events are stored.
- **Correlation** consumes alerts only.

## Backend packages

```
backend/app/
  core/          config, structured logging, request IDs, errors, security headers, rate limits
  database/      engine, session, base model
  models/        SQLAlchemy models (one file per aggregate)
  schemas/       Pydantic request/response models
  api/           FastAPI routers, thin: validate, authorize, call a service, map errors
  auth/          password hashing, tokens, current-user and role dependencies
  audit/         append-only audit log: record(), event names
  context/       assets and identities (inventory CRUD + lookup used by enrichment)
  ingestion/
    sources.py   log-source registry (which parser, timezone, default host)
    parsers/     one module per format; raw text/dict → ParsedRecord or ParseError (pure)
    normalize.py ParsedRecord → NormalizedEvent (pure)
    enrich.py    NormalizedEvent + context snapshot → enriched event (pure, given the snapshot)
    service.py   batch lifecycle: dedup, persist raw + normalized, then trigger detection
  detection/
    model.py     rule schema (Pydantic), Detection, Evidence
    conditions.py safe predicate language (field / operator / value), no eval
    evaluators/  single.py, threshold.py, distinct.py, sequence.py, new_value.py (pure)
    library/     YAML rule definitions shipped with the product (seeded into the DB)
    engine.py    picks candidate events from the DB, runs evaluators, returns detections
    explain.py   builds the WHAT/WHY/WHICH/WHO text from the evidence
  alerts/        dedup, persistence, workflow (status machine), prioritization
  correlation/   alert → incident linking (pure scoring + a persistence layer)
  incidents/     incident lifecycle, notes, evidence pins, activity, timeline assembly
  risk/          priority/risk model (pure functions, versioned)
  mitre/         ATT&CK reference data (pinned version) and coverage queries
  hunting/       structured query compiler (filters → SQLAlchemy), hunt templates, saved hunts
  dashboard/     aggregate queries
  demo/          simulated scenario generator; emits RAW log lines, never normalized rows
  cli.py         create-admin, seed-rules, ingest-file, run-detection, demo commands
```

### Dependency direction

```
api → services (ingestion, alerts, incidents, hunting, ...) → pure cores → models/database
                                                     ↑
         pure cores: ingestion/parsers, normalize, enrich; detection/evaluators,
                     conditions, explain; correlation scoring; risk; demo generators
```

Rules we will enforce with tests or review:
- Parsers, evaluators, correlation scoring and risk take plain data and return plain data. They
  do not import SQLAlchemy, FastAPI or the clock. The clock is always passed in, which makes
  time-window tests deterministic.
- Only `ingestion/service.py` writes `raw_events` and `events`.
- Only `alerts/` writes alerts; only `incidents/` and `correlation/` write incidents.
- Security-relevant writes call `audit.record()` in the same transaction as the change.

## Pipeline and processing model

[ADR-008](decisions/0008-synchronous-bounded-pipeline.md) has the full reasoning. Summary:

```
POST /api/ingest/{source}  (or file upload, CLI, demo generator)
  1. validate request: size ≤ 5 MB, ≤ 5,000 records, source exists and is enabled
  2. create ingestion_batch (RECEIVED)
  ── transaction A ──────────────────────────────────────────────────────────────
  3. for each record:
       fingerprint = sha256(source_id ‖ raw)          → duplicate? count it, skip
       parse (pure)          → ParsedRecord | ParseError
       store raw_events row  (ALWAYS, including parse failures: status PARSED/FAILED)
       normalize (pure)      → NormalizedEvent
       enrich (pure, with a context snapshot loaded once per batch)
       store events row
  4. batch → STORED with counts (received, parsed, failed, duplicates)
  ── commit ─────────────────────────────────────────────────────────────────────
  ── transaction B (serialized with pg_advisory_xact_lock('detection')) ─────────
  5. detection: for each enabled rule, load candidate events for the batch's time span
     widened by the rule's window, run the evaluator → detections
  6. alerts: dedup / create / extend, link evidence, compute priority
  7. correlation: link alerts to incidents or create incidents
  8. batch → PROCESSED (alerts created/updated, incidents created/updated)
  ── commit ─────────────────────────────────────────────────────────────────────
  9. respond 200 with the batch report
```

Design points:
- **Events are committed before detection runs.** If detection fails, no evidence is lost. The
  batch is marked `DETECTION_FAILED` and an admin can re-run detection over a time range
  (`POST /api/detections/run`, the CLI `run-detection`).
- **Detection is idempotent.** Evidence links are unique on `(alert_id, event_id)` and alerts
  deduplicate on a key. Re-running over the same events changes nothing, so a retry after a
  crash is always safe.
- **Stateless detection.** Window state is not kept in memory. Every run re-reads the relevant
  window from PostgreSQL. This handles late and out-of-order events (a late failure still
  completes a threshold) and survives restarts. The cost is repeated reads, bounded by the
  batch's time span and indexed columns.
- **Event time vs ingest time.** Rules use the event's own `timestamp`. `ingested_at` is kept
  for auditing and for detecting clock problems.
- **Serialization.** An advisory lock makes one detection pass run at a time, so two
  concurrent batches cannot both create "the first" alert for the same key. Ingestion
  (transaction A) stays concurrent.
- **Bounded synchronous work.** This is the simplest design that works, and an HTTP request is
  a natural backpressure point. A job queue is the documented next step when batches get
  larger or ingestion must be asynchronous (Level 4, not planned).

### Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Malformed record | That record only | Raw kept with `parse_status=FAILED` and a short error code; counted in the batch report |
| Whole payload invalid (not JSON, too big) | Request | `400`/`413`, nothing stored, audited as a rejected ingest |
| Unknown / disabled source | Request | `404`/`409` |
| DB error in transaction A | Batch | Rolled back; batch `FAILED`; client may retry (duplicates are skipped) |
| Evaluator raises for one rule | That rule | Logged with rule ID and batch ID; other rules still run; batch `PROCESSED_WITH_ERRORS` |
| DB error in transaction B | Detection for the batch | Events stay stored; batch `DETECTION_FAILED`; re-run is safe |
| Process restart mid-batch | Batch | Startup reconciler marks `RECEIVED`/`STORED` batches older than N minutes as `DETECTION_FAILED` |

## Threat hunting (Phase 10)

Hunts are **structured queries** (a required time range of at most 31 days, allowlisted
fields and operators, keyset pagination), compiled to parameterized SQL by the same compiler
as detection conditions. Reviewed SQL templates cover questions that flat filters cannot
answer. Full design, trade-offs and limits: [threat-hunting.md](threat-hunting.md).

## Frontend architecture

- React + TypeScript + Vite + Tailwind; React Router. No component library. A small set of our
  own components keeps the dependency count and bundle small and avoids a generic
  template look.
- `src/services/` holds all API calls, `src/types/api.ts` mirrors backend schemas, and pages
  load data through a `useApi` hook. The access token lives in memory only (see
  `security.md`).
- **URL is state.** Filters, time ranges, pagination cursors and hunt definitions live in the
  query string, so an investigation view can be bookmarked, shared and reached through a
  pivot link.
- Core components: `SeverityBadge`, `StatusBadge`, `EntityChip` (IP/user/host with pivot
  menu), `DataTable` (server-side sort/pagination), `TimeRangePicker`, `EventViewer`
  (normalized fields beside the raw record, raw shown as preformatted text, never as HTML),
  `Timeline`, `EvidenceList`, `AttackTag`, `RiskBreakdown`, `EmptyState`.
- Charts (severity distribution, trends) are small hand-written SVG components. A charting
  library is added only if these become hard to maintain.
- Pages: `/login /dashboard /events /hunt /detections /detections/:id /alerts /alerts/:id
  /incidents /incidents/:id /assets /identities /audit /settings` (users, log sources, and
  demo controls when enabled).
- Anything produced by the demo generator carries a visible **SIMULATED** label.

## Observability

Implemented in Phase 2: JSON log lines (`core/logging.py`) with `request_id`, one
`http.request` line per request (method, path without query string, status, duration; health
checks at DEBUG), redaction of tokens / passwords / URL credentials as a safety net,
`/api/health` and `/api/ready` (database reachable **and** schema revision equals the code's
Alembic head, so a deploy that skipped migrations reports not ready). The request ID comes
from nginx (`$request_id`) or a safe caller-supplied value, is returned in `X-Request-ID`, and
is included in every error body. Planned below:

- JSON logs with `request_id` (accepted from a trusted proxy or generated) and `user_id` where
  known.
- One summary log line per pipeline stage with counts and durations:
  `ingest.batch_stored`, `detection.run_completed` (per-rule matches and time, errors),
  `correlation.completed`.
- Rule health is visible in the product: last run, last match, evaluation errors, match count.
- `/api/health` (process up) and `/api/ready` (database reachable, migrations at head).
- Logs never include passwords, tokens, or raw event bodies at INFO level. Raw events can
  carry attacker-controlled text and sometimes secrets, so they are logged only by reference.

## Scale limits (honest)

- The design is sized for one PostgreSQL instance and one backend process: a lab, a demo, or a
  small environment. It is not a replacement for a SIEM at enterprise ingest rates.
- The in-process rate limiter and the advisory-lock detection model assume one backend
  instance.
- There is no retention policy at first. The `events` table is designed to be partitioned by
  month later (a time-leading primary key and a BRIN index option); see `database-schema.md`.
- Controlled benchmarks (Phase 14) will measure ingest rate and detection latency on this
  machine. Until then no throughput numbers are claimed.

## Real-world extension plan

How real sources would connect without changing detection:
- **Linux**: a log shipper (rsyslog `omhttp`, Vector, Fluent Bit) posts auth.log lines to
  `/api/ingest/{source}` with a per-source ingest key (Phase 13 design; see `security.md`).
- **Windows**: Windows Event Forwarding → a collector → Winlogbeat/NXLog JSON. A parser
  mapping for that JSON shape is added under `ingestion/parsers/`.
- **Cloud audit logs** (CloudTrail, Azure Activity): a new parser and new rules. Detection and
  correlation work on normalized fields, so they do not change.
- **Endpoint/EDR**: a JSON parser for process and network telemetry. These feed PROC/NET-style
  rules.
- **Identity providers**: sign-in logs map to the `authentication` category.

Each new source needs a parser, fixtures and tests only. When the rate exceeds what a
synchronous API can absorb, a queue (Redis Streams/Kafka) goes in front of the same ingestion
service. That trigger is documented, not built.
