# Architecture decision records

Each record is short: the context, the options considered, the choice, and its consequences.
When a decision changes, a new ADR supersedes the old one. Old ADRs are not rewritten.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-modular-monolith.md) | Modular monolith | Accepted (Phase 1) |
| [0002](0002-postgresql-event-store.md) | PostgreSQL as the event store and search backend | Accepted (Phase 1) |
| [0003](0003-normalized-event-schema.md) | Flat normalized event schema, raw stored separately | Accepted (Phase 1) |
| [0004](0004-declarative-rule-engine.md) | Declarative rules and a few evaluator kinds | Accepted (Phase 1) |
| [0005](0005-explainable-risk-model.md) | Explainable, versioned additive priority model | Accepted (Phase 1) |
| [0006](0006-simulated-demo-data.md) | Simulated raw logs instead of attack infrastructure | Accepted (Phase 1) |
| [0007](0007-backend-authoritative-rbac.md) | Backend-authoritative RBAC with a test-enforced route table | Accepted (Phase 1) |
| [0008](0008-synchronous-bounded-pipeline.md) | Synchronous, bounded, idempotent pipeline (no queue yet) | Accepted (Phase 1) |
| [0009](0009-entity-based-incident-correlation.md) | Entity-overlap correlation of alerts into incidents | Accepted (Phase 1) |
| [0010](0010-evidence-storage.md) | Evidence storage: exact bytes, append-only including TRUNCATE | Accepted (Phase 4) |
| [0011](0011-alert-deduplication.md) | Alert deduplication: one open alert per activity, evidence decides | Accepted (Phase 7) |
| [0012](0012-correlation-by-finding.md) | Correlation links new kinds of finding on the same host; stages are findings, not tactics | Accepted (Phase 8) |
