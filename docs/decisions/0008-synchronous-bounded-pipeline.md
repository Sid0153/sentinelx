# ADR-0008: Synchronous, bounded, idempotent pipeline (no queue yet)

**Context.** Ingestion must be reliable, and detection must see late events, without adding
Redis or Kafka.

**Options.**
- (a) A queue with workers and in-memory streaming windows.
- (b) FastAPI background tasks.
- (c) Synchronous processing of bounded batches: store the events and commit, then run
  detection and correlation in a second transaction, serialized by a PostgreSQL advisory lock,
  re-reading time windows from the database.

**Decision.** (c), with a limit of 5 MB and 5,000 records per request.

**Consequences.**
- No evidence is lost if detection fails, because events are committed first.
- Re-running detection is safe, because alert keys and evidence links are unique.
- Late and out-of-order events are handled, because windows are re-read from the database.
- Throughput is limited by request latency. The trigger for adding a queue (measured batch
  latency, or shippers that need asynchronous ingestion) is documented in
  [architecture.md](../architecture.md).
- One backend instance is assumed.
