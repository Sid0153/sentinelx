# Database design

> Status: tables marked ✅ exist (migrations 0001–0005) and are tested; the rest are design and
> are created in the phase shown. PostgreSQL 16. UUID primary keys (generated in the app)
> unless noted. All timestamps are `timestamptz`, stored in UTC. A test compares the SQLAlchemy
> models with the migrated database and fails on any difference.

## Entity overview

```
users ─┬─< refresh_tokens
       ├─< audit_logs (actor)                                  [append-only]
       └─< saved_hunts

log_sources ─< ingestion_batches ─< raw_events ─1:1─ events    [raw_events, events: append-only]
                                                      │  │
assets ──────────────────────────────────────────────<┘  │
identities ─────────────────────────────────────────────<┘

detection_rules ─< detection_rule_versions
detection_rules >─< mitre_techniques   (detection_rule_techniques: reason)
detection_rules ─< alerts ─< alert_events >─ events
                     │
incidents ─< incident_alerts >─┘
incidents ─< incident_notes            [append-only]
incidents ─< incident_evidence         [append-only]
incidents ─< incident_activity         [append-only]
```

Each table has a purpose tied to a feature. The brief's `Role` entity is an enum column on
`users`: three fixed roles do not need a table. `IncidentTimeline` is a view assembled from
events, alerts and activity, not a stored table, so it cannot drift from its sources.

## Tables

| Table | Phase | Purpose / key columns |
|---|---|---|
| `users` ✅ | 3 | email (unique; check: lowercase), password_hash (Argon2id), role (check: ADMIN/ANALYST/VIEWER), is_active, failed_login_count, locked_until, last_login_at, created_at |
| `refresh_tokens` ✅ | 3 | user_id (FK, cascade), token_hash (SHA-256, unique), expires_at, revoked_at, revoked_reason (ROTATED/LOGOUT/PASSWORD_CHANGED/DEACTIVATED/REUSE_DETECTED), created_at |
| `audit_logs` ✅ | 3 | occurred_at, action, result (check: SUCCESS/FAILURE/DENIED), actor_id (FK without cascade: a user with audit history cannot be deleted), actor_label (email at the time), entity_type, entity_id, client_ip, request_id, details JSONB (sanitized, no secrets). **Append-only** |
| `assets` ✅ | 4 | hostname (unique; check: lowercase), ip_addresses inet[] (GIN), asset_type, environment, criticality (low/medium/high/critical), owner, description, tags, status (active/retired), created_at, updated_at |
| `identities` ✅ | 4 | username (unique; check: lowercase), display_name, department, title, privilege_level (standard/privileged/service), status (active/disabled), tags, created_at, updated_at |
| `log_sources` ✅ | 4 | name (unique), source_type (check: the five parsers), description, default_host, timezone, enabled. `ingest_key_hash` arrives in Phase 13 |
| `ingestion_batches` ✅ | 5 | source_id, submitted_by (null for CLI/demo), channel (api/text/cli/demo), status (check: STORED → PROCESSED / PROCESSED_WITH_ERRORS / DETECTION_FAILED), received / parsed / skipped / failed / duplicate / rejected counts (check: they add up to received), detection_count (Phase 6), issues JSONB (first 50), first/last event time, simulated, created_at. Not append-only: detection moves it through its states |
| `raw_events` ✅ | 4, 5 | source_id (FK), batch_id (FK, Phase 5), received_at, raw_data **bytea** (exact bytes, ≤ 64 KiB), fingerprint (unique), parse_status (PARSED / SKIPPED / FAILED; check: parse_detail present ⇔ not PARSED), parse_detail (short reason code; `parse_error` until migration 0004), simulated. **Append-only** |
| `events` ✅ | 4 | normalized + enrichment columns ([event-model.md](event-model.md)); raw_event_id (unique FK), source_id (FK), asset_id / identity_id (FK, restrict). Checks: category, outcome, action format, port ranges, lowercase host/user, IP scope, criticality, sizes. **Append-only** |
| `detection_rules` ✅ | 6 | rule_id (PK text, e.g. AUTH-001), name, category, kind, library_definition JSONB, library_hash, overrides JSONB (admin changes to tunable fields only), version, enabled, in_library (false once removed from the shipped library: kept, never run), last_run_at, last_match_at, match_count, error_count, created_at, updated_at |
| `detection_rule_versions` ✅ | 6 | rule_id (FK), version, definition JSONB (the full effective definition), overrides, library_hash, source (check: library/admin), changed_by (FK users), change_reason, created_at; unique (rule_id, version). **Append-only** |
| `mitre_techniques` ✅ | 6 | technique_id (PK), name, tactics text[], attack_version. Loaded from the checked-in, pinned reference file; the page URL is derived from the ID |
| `detection_rule_techniques` ✅ | 6 | PK (rule_id, technique_id, indicator); indicator is `""` for the rule as a whole, or an indicator ID (PROC-001, PRIV-001); reason |
| `detection_runs` ✅ | 6 | trigger (check: batch/manual), batch_id (FK), requested_by (FK users), range_start ≤ range_end (check), status (check: COMPLETED / COMPLETED_WITH_ERRORS), rule_results JSONB (per rule: version, candidates, detections, error code, ms), detections JSONB (each with explanation, facts, evidence IDs, ATT&CK), detection_count, duration_ms, started_at (indexed). Phase 7 turns detections into alerts |
| `alerts` | 7 | see [detection-engine.md](detection-engine.md#alert-record); unique partial index on dedup_key WHERE status is active |
| `alert_events` | 7 | alert_id, event_id, PK (alert_id, event_id), role (e.g. `step:failure`, `step:success`) |
| `incidents` | 8 | see [correlation.md](correlation.md#incident-record) |
| `incident_alerts` | 8 | incident_id, alert_id (**unique**: an alert belongs to at most one incident), link_strength, shared_entities JSONB, reason, link_source (engine/analyst), linked_by, linked_at |
| `incident_notes` | 8 | incident_id, author_id, body (≤ 10 KB), created_at. Append-only |
| `incident_evidence` | 8 | incident_id, event_id or alert_id, tag, comment, action (PIN/UNPIN), actor, created_at. Append-only |
| `incident_activity` | 8 | incident_id, actor, kind (STATUS/ASSIGN/NOTE/EVIDENCE/LINK/RENAME/CREATED), from/to JSONB, created_at. Append-only |
| `saved_hunts` | 10 | owner_id, name, definition JSONB (validated structured query), shared bool |
| `app_settings` | 8 | key/value for admin configuration (correlation window, internal networks); changes audited |

`log_sources` moved from Phase 5 to Phase 4: every event references its source, so the event
store cannot exist without it. The batches that group records per ingest request stay in
Phase 5.

## Integrity rules enforced by the database

- Check constraints on every enum-like column, port ranges, lowercase identifiers and size
  limits (implemented for all ✅ tables and tested one by one), later also on
  `event_count ≥ 1`.
- Foreign keys without cascade on evidence chains. An asset or identity that events reference
  cannot be deleted (it is retired or disabled instead), and neither can a user in the audit
  log. The only cascade is refresh tokens with their user. Alerts will hold events in place
  the same way (Phase 7).
- **Append-only triggers** reject UPDATE and DELETE (per row) and TRUNCATE (per statement) on
  `audit_logs`, `raw_events`, `events` and `detection_rule_versions` (✅), later on `incident_notes`,
  `incident_evidence` and `incident_activity`. They share one trigger function,
  `reject_modification()`. How the demo is reset (Phase 16) will be designed without
  weakening this ([ADR-0010](decisions/0010-evidence-storage.md)).
- The partial unique index `alerts(dedup_key) WHERE status IN ('NEW','TRIAGED','IN_PROGRESS')`
  makes "one active alert per key" a database guarantee, not just application logic.
- `incident_alerts(alert_id)` is unique.

## Indexes (from the queries we know we will run)

| Index | Serves |
|---|---|
| ✅ `events (timestamp DESC, id DESC)` | Event explorer, keyset pagination, dashboard "today" |
| ✅ `events (event_category, event_action, timestamp)` | Rule candidate prefilter |
| ✅ `events (source_ip, timestamp)` | Pivots, AUTH rules, hunts |
| ✅ `events (username, timestamp)` | Pivots, AUTH-004 history |
| ✅ `events (host, timestamp)` | Pivots, host views |
| ✅ `events (destination_ip, timestamp)` | Hunts, NET-001 |
| ✅ `events USING gin (command_line gin_trgm_ops)`, same on `message` | Substring hunt search (`pg_trgm`) |
| ✅ `events (asset_id)`, `events (identity_id)` | Asset and identity views; FK checks |
| ✅ `raw_events (fingerprint)` unique | Duplicate detection |
| ✅ `assets USING gin (ip_addresses)` | Enrichment: which asset owns this IP |
| ✅ `audit_logs (occurred_at)`, `(entity_type, entity_id)`, `(action)`, `(actor_id)` | Audit views, incident history |
| `alerts (status, priority_score DESC)` | Alert queue |
| `alerts (rule_id, created_at)` | Rule metrics, coverage |
| `alerts (created_at)` | Trends |
| `incidents (status, last_activity_at)` | Correlation candidates, queue |

Composite indexes lead with the equality column and end with `timestamp`, because almost every
query is "value X within time range T".

**How the indexes are tested now** (`tests/integration/test_schema.py`): for each query shape,
sequential scans are disabled and the generic time index is dropped inside the rolled-back
test transaction. The plan must then use the intended index, with the time range in its index
condition rather than as a filter. This proves each index *fits* its query. It does not prove
the planner *chooses* it at every table size: that needs real data, and Phase 14 checks it with
`EXPLAIN ANALYZE` on a generated data set. No performance numbers are claimed before then.

**Write cost.** Each event insert updates ten indexes on `events` (two of them GIN). That is
the price of fast pivots and hunts, and it bounds ingest throughput. Phase 14 measures it
rather than guessing; if it is too high, the trigram indexes are the first candidates to drop
or defer.

## Growth plan (documented, not built)

- Partition `events` and `raw_events` by month (declarative partitioning). The primary key
  would become `(timestamp, id)`, which is why keyset pagination already uses that pair.
- A retention job drops old partitions. Evidence referenced by open incidents would be copied
  or its partition held back. Dropping partitions is a deliberate operator action, separate
  from the append-only triggers that stop the application from deleting rows.
- A BRIN index on `timestamp` for very large, append-ordered partitions.
