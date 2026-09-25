# ADR-0003: Flat normalized event schema, raw stored separately

**Context.** Five source formats must feed one detection engine, and logs are evidence.

**Options.**
- (a) Adopt ECS or OCSF in full.
- (b) Store the source JSON only and make rules aware of each format.
- (c) A small flat schema with ECS-style category / action / outcome, typed columns for fields
  that rules and indexes use, JSONB for the rest, and the raw text stored untouched in its own
  table.

**Decision.** (c). See [event-model.md](../event-model.md).

**Consequences.**
- Rules do not depend on the source. AUTH-002 works the same on SSH, Windows and app logs.
- Adding a source means one parser plus fixtures.
- Mapping to ECS or OCSF later is mechanical because the names follow the same idea.
- Raw records survive parse failures and are never modified (append-only triggers).
- Enrichment values are point-in-time snapshots. This is documented.
