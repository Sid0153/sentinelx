# ADR-0001: Modular monolith

**Context.** SentinelX has many subsystems (ingestion, detection, alerts, correlation,
incidents, hunting) and one developer. Changes often span subsystems and need to be atomic, and
the whole system must run on a laptop.

**Options.**
- (a) Microservices with a message bus.
- (b) A single app with no internal structure.
- (c) A modular monolith with enforced package boundaries.

**Decision.** (c): one FastAPI process, one React app, one database. Packages expose small
service interfaces. Pure cores (parsers, evaluators, correlation scoring, risk) have no
framework imports.

**Consequences.**
- Changes across subsystems are atomic: alert, evidence and incident are written in one
  transaction.
- Local setup is three containers.
- Scaling is vertical until a boundary is split out. Ingestion is the first candidate because
  it already hands off only `NormalizedEvent` objects.
- The in-process rate limiter and the detection lock assume one backend instance. This is
  documented.
