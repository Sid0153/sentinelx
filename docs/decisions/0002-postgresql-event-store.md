# ADR-0002: PostgreSQL as the event store and search backend

**Context.** Events must be stored, filtered by time and entity, joined to alerts and
incidents, and searched by substring for hunting.

**Options.**
- (a) PostgreSQL only.
- (b) PostgreSQL plus Elasticsearch/OpenSearch for events.
- (c) A column store (ClickHouse) for events.

**Decision.** (a). The design uses:
- composite `(value, timestamp)` B-tree indexes
- `pg_trgm` GIN indexes for substring search
- JSONB for source-specific attributes
- keyset pagination

**Consequences.**
- One system to run, back up and secure.
- Evidence and investigation data share transactions and foreign keys, so an event cited by
  an alert cannot disappear.
- Not suited to SIEM ingest rates or to free-text relevance ranking.
- Growth path: monthly partitioning and retention first. A search engine or column store fed
  from the same ingestion service comes only when measured volumes require it (Level 4, not
  planned).
