# ADR-0009: Entity-overlap correlation of alerts into incidents

**Context.** An incident must group related alerts into one story, not mirror alerts one to
one, and analysts must see why alerts were grouped.

**Options.**
- (a) One incident per alert.
- (b) Grouping by time bucket.
- (c) Graph clustering over all entities.
- (d) Scored entity overlap (host + user, host + source, external source) within a time
  window, with explicit rules for creating incidents and a stored reason for every link.

**Decision.** (d). See [correlation.md](../correlation.md). Incidents are never merged or
split automatically. Analysts can link, unlink and escalate.

**Consequences.**
- Every link can be explained in one sentence.
- Weak overlaps (host only, user only) are shown as related, not linked. This trades some
  recall for fewer wrong merges.
- Transitive clustering (graph-based) is future work, if analysts need it.
