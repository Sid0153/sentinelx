# ADR-0006: Simulated raw logs instead of attack infrastructure

**Context.** The platform must be demonstrable with realistic attacks, with no real
exploitation, no offensive tooling and no paid infrastructure.

**Options.**
- (a) Run real attacks in a lab.
- (b) Insert rows directly into the normalized table.
- (c) Generate **raw** log records (auth.log lines, Windows event JSON, access logs, JSON
  events) for scripted scenarios and send them through the normal ingestion pipeline.

**Decision.** (c).
- The generator is deterministic (seeded).
- Outside addresses come from the documentation IP ranges (RFC 5737).
- The environment is coherent and fictional: fixed hosts, users and working hours.
- Every generated record is flagged `simulated` and labelled SIMULATED in the UI.

**Consequences.**
- Demos exercise the real parsers, detection and correlation, so demo scenarios also serve as
  integration tests.
- Nothing offensive is implemented.
- Limitation: synthetic data is cleaner than real logs, so parsers are also tested against
  malformed input.
