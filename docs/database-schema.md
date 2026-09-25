# Database design

> Status: **DESIGN (Phase 1)**. Tables are created by Alembic migrations in the phase shown.
> PostgreSQL 16. UUID primary keys (generated in the app) unless noted. All timestamps are
> `timestamptz`, stored in UTC.

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
| `users` | 3 | email (unique, lowercased), password_hash (Argon2id), role (ADMIN/ANALYST/VIEWER), is_active, failed_login_count, locked_until, created_at |
| `refresh_tokens` | 3 | user_id, token_hash (SHA-256, unique), expires_at, revoked_at, replaced_by |
| `audit_logs` | 3 | timestamp, actor_user_id, actor_label, action, entity_type, entity_id, result (SUCCESS/DENIED/FAILED), client_ip, request_id, details JSONB (no secrets). **Append-only trigger** |
| `assets` | 4 | hostname (unique, lowercased), ip_addresses inet[], asset_type, environment, criticality (low/medium/high/critical), owner, tags text[], status |
| `identities` | 4 | username (unique, normalized), display_name, department, privilege_level (standard/privileged/service), status, tags |
| `log_sources` | 5 | name, source_type (parser), default_host, timezone, syslog_year_policy, enabled, ingest_key_hash (Phase 13) |
| `ingestion_batches` | 5 | source_id, submitted_by, channel (api/upload/cli/demo), status, received/parsed/failed/duplicate counts, alert/incident counts, error, started/finished_at |
| `raw_events` | 5 | source_id, batch_id, received_at, raw_text, fingerprint (unique), parse_status (PARSED/FAILED), parse_error, simulated. **Append-only** |
| `events` | 4/5 | normalized + enrichment columns ([event-model.md](event-model.md)); raw_event_id unique FK. **Append-only** |
| `detection_rules` | 6 | rule_id (PK text, e.g. AUTH-001), library_definition JSONB, library_hash, overrides JSONB, current_version, enabled, last_run_at, last_match_at, error_count |
| `detection_rule_versions` | 6 | rule_id, version, effective_definition JSONB, source (library/admin), changed_by, change_reason, created_at; unique (rule_id, version) |
| `mitre_techniques` | 6 | technique_id (PK), name, tactics text[], url, attack_version. Seeded from a checked-in file |
| `detection_rule_techniques` | 6 | rule_id, technique_id, reason, indicator (for PROC-001's per-indicator mapping) |
| `alerts` | 7 | see [detection-engine.md](detection-engine.md#alert-record); unique partial index on dedup_key WHERE status is active |
| `alert_events` | 7 | alert_id, event_id, PK (alert_id, event_id), role (e.g. `step:failure`, `step:success`) |
| `incidents` | 8 | see [correlation.md](correlation.md#incident-record) |
| `incident_alerts` | 8 | incident_id, alert_id (**unique**: an alert belongs to at most one incident), link_strength, shared_entities JSONB, reason, link_source (engine/analyst), linked_by, linked_at |
| `incident_notes` | 8 | incident_id, author_id, body (≤ 10 KB), created_at. Append-only |
| `incident_evidence` | 8 | incident_id, event_id or alert_id, tag, comment, action (PIN/UNPIN), actor, created_at. Append-only |
| `incident_activity` | 8 | incident_id, actor, kind (STATUS/ASSIGN/NOTE/EVIDENCE/LINK/RENAME/CREATED), from/to JSONB, created_at. Append-only |
| `saved_hunts` | 10 | owner_id, name, definition JSONB (validated structured query), shared bool |
| `app_settings` | 8 | key/value for admin configuration (correlation window, internal networks); changes audited |

## Integrity rules enforced by the database

- Check constraints on every enum-like column, on `event_count ≥ 1`, and on port ranges.
- Foreign keys with `ON DELETE RESTRICT` for evidence chains (an event referenced by an alert
  cannot disappear).
- Append-only triggers on `audit_logs`, `raw_events`, `events`, `incident_notes`,
  `incident_evidence` and `incident_activity`. They reject `UPDATE`/`DELETE`; demo reset uses
  an audited `TRUNCATE` of pipeline tables only.
- The partial unique index `alerts(dedup_key) WHERE status IN ('NEW','TRIAGED','IN_PROGRESS')`
  makes "one active alert per key" a database guarantee, not just application logic.
- `incident_alerts(alert_id)` is unique.

## Indexes (from the queries we know we will run)

| Index | Serves |
|---|---|
| `events (timestamp DESC, id)` | Event explorer, keyset pagination, dashboard "today" |
| `events (event_category, event_action, timestamp)` | Rule candidate prefilter |
| `events (source_ip, timestamp)` | Pivots, AUTH rules, hunts |
| `events (username, timestamp)` | Pivots, AUTH-004 history |
| `events (host, timestamp)` | Pivots, host views |
| `events (destination_ip, timestamp)` | Hunts, NET-001 |
| `events USING gin (command_line gin_trgm_ops)`, same on `message` | Substring hunt search (`pg_trgm`) |
| `raw_events (fingerprint)` unique | Duplicate detection |
| `alerts (status, priority_score DESC)` | Alert queue |
| `alerts (rule_id, created_at)` | Rule metrics, coverage |
| `alerts (created_at)` | Trends |
| `incidents (status, last_activity_at)` | Correlation candidates, queue |
| `audit_logs (timestamp DESC)`, `(entity_type, entity_id)` | Audit views, incident history |

Composite indexes lead with the equality column and end with `timestamp`, because almost every
query is "value X within time range T". Phase 14 checks the plans with `EXPLAIN ANALYZE` on a
generated data set and records the measured results; no numbers are claimed before then.

## Growth plan (documented, not built)

- Partition `events` and `raw_events` by month (declarative partitioning). The primary key
  would become `(timestamp, id)`, which is why keyset pagination already uses that pair.
- A retention job drops old partitions. Evidence referenced by open incidents would be copied
  or its partition held back.
- A BRIN index on `timestamp` for very large, append-ordered partitions.
