# Database design

> Status: every table below exists (migrations 0001–0014) and is tested; the Phase column says
> when it was added. PostgreSQL 16. UUID primary keys (generated in the app)
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
| `users` ✅ | 3 | email (unique; check: lowercase), password_hash (Argon2id), role (check: ADMIN/ANALYST/VIEWER), is_active, failed_login_count, locked_until, last_login_at, created_at; Phase 13: mfa_enabled, totp_salt / totp_pending_salt (the TOTP secret is derived from SECRET_KEY + salt, never stored), totp_last_step (replay protection), mfa_recovery_hashes JSONB (SHA-256), must_change_password |
| `refresh_tokens` ✅ | 3 | user_id (FK, cascade), token_hash (SHA-256, unique), expires_at, revoked_at, revoked_reason (ROTATED/LOGOUT/PASSWORD_CHANGED/DEACTIVATED/REUSE_DETECTED), created_at |
| `audit_logs` ✅ | 3 | occurred_at, action, result (check: SUCCESS/FAILURE/DENIED), actor_id (FK without cascade: a user with audit history cannot be deleted), actor_label (email at the time), entity_type, entity_id, client_ip, request_id, details JSONB (sanitized, no secrets); Phase 13: seq (unique, from `audit_logs_seq`), prev_hash, entry_hash (the hash chain, set by the `audit_logs_chain` trigger; null on entries from before it). **Append-only** |
| `assets` ✅ | 4 | hostname (unique; check: lowercase), ip_addresses inet[] (GIN), asset_type, environment, criticality (low/medium/high/critical), owner, description, tags, status (active/retired), created_at, updated_at |
| `identities` ✅ | 4 | username (unique; check: lowercase), display_name, department, title, privilege_level (standard/privileged/service), status (active/disabled), tags, created_at, updated_at |
| `log_sources` ✅ | 4 | name (unique), source_type (check: the five parsers), description, default_host, timezone, enabled, ingest_key_hash (SHA-256, unique, nullable), ingest_key_prefix, ingest_key_created_at, ingest_key_last_used_at (Phase 13; the key itself is never stored), allowed_hosts (text array, default empty: any host) |
| `ingestion_batches` ✅ | 5 | source_id, submitted_by (null for CLI/demo), channel (api/text/cli/demo), status (check: STORED → PROCESSED / PROCESSED_WITH_ERRORS / DETECTION_FAILED), received / parsed / skipped / failed / duplicate / rejected counts (check: they add up to received), detection_count (Phase 6), alerts_created / alerts_updated (Phase 7), issues JSONB (first 50), first/last event time, simulated, created_at. Not append-only: detection moves it through its states |
| `raw_events` ✅ | 4, 5 | source_id (FK), batch_id (FK, Phase 5), received_at, raw_data **bytea** (exact bytes, ≤ 64 KiB), fingerprint (unique), parse_status (PARSED / SKIPPED / FAILED; check: parse_detail present ⇔ not PARSED), parse_detail (short reason code; `parse_error` until migration 0004), simulated. **Append-only** |
| `events` ✅ | 4 | normalized + enrichment columns ([event-model.md](event-model.md)); raw_event_id (unique FK), source_id (FK), asset_id / identity_id (FK, restrict). Checks: category, outcome, action format, port ranges, lowercase host/user, IP scope, criticality, sizes. **Append-only** |
| `detection_rules` ✅ | 6 | rule_id (PK text, e.g. AUTH-001), name, category, kind, library_definition JSONB, library_hash, overrides JSONB (admin changes to tunable fields only), version, enabled, in_library (false once removed from the shipped library: kept, never run), last_run_at, last_match_at, match_count, error_count, created_at, updated_at |
| `detection_rule_versions` ✅ | 6 | rule_id (FK), version, definition JSONB (the full effective definition), overrides, library_hash, source (check: library/admin), changed_by (FK users), change_reason, created_at; unique (rule_id, version). **Append-only** |
| `mitre_techniques` ✅ | 6 | technique_id (PK), name, tactics text[], attack_version. Loaded from the checked-in, pinned reference file; the page URL is derived from the ID |
| `detection_rule_techniques` ✅ | 6 | PK (rule_id, technique_id, indicator); indicator is `""` for the rule as a whole, or an indicator ID (PROC-001, PRIV-001); reason |
| `detection_runs` ✅ | 6 | trigger (check: batch/manual), batch_id (FK), requested_by (FK users), range_start ≤ range_end (check), status (check: COMPLETED / COMPLETED_WITH_ERRORS), rule_results JSONB (per rule: version, candidates, detections, error code, ms), detections JSONB (each with explanation, facts, evidence IDs, ATT&CK), detection_count, alerts_created / alerts_updated (Phase 7; each stored detection also names its alert and whether it was created, updated or unchanged), duration_ms, started_at (indexed) |
| `alerts` ✅ | 7 | see [detection-engine.md](detection-engine.md#alert-record-alerts-alert_events). Checks: status, severity, confidence, band, disposition values; disposition present exactly when RESOLVED; score 0–100; event_count ≥ 1; first ≤ last event. **Partial unique index on dedup_key WHERE status is open** (one open alert per activity, tested). FKs to rules, assets, identities, users, previous alert, all without cascade |
| `alert_events` ✅ | 7 | alert_id, event_id (both FK, no cascade: an alert holds its evidence in place), linked_at; PK (alert_id, event_id), so evidence cannot be linked twice; index on event_id (alerts citing an event) |
| `incidents` ✅ | 8 | see [correlation.md](correlation.md#incident-record-incidents); `number` (identity, unique, shown as INC-n); arrays hosts / usernames / source_ips (GIN), tactics, techniques. Checks: status, severity, band, disposition values; disposition and resolution present exactly when RESOLVED or CLOSED; risk 0–100; first ≤ last activity |
| `incident_alerts` ✅ | 8 | PK (incident_id, alert_id), alert_id **unique** (an alert belongs to at most one incident), link_strength (check: STRONG/MEDIUM/WEAK/MANUAL/ORIGIN), shared_entities JSONB, reason, link_source (engine/analyst), linked_by, linked_at |
| `incident_notes` ✅ | 8 | incident_id, author_id, body (check: 1–10,000 characters), created_at. **Append-only** |
| `incident_evidence` ✅ | 8 | incident_id, event_id or alert_id (check: exactly one), tag, comment, action (PIN/UNPIN), actor_id, created_at. **Append-only** |
| `incident_activity` ✅ | 8 | incident_id, seq (identity: insertion order), actor_id (null: the engine), kind (CREATED/LINK/UNLINK/STATUS/ASSIGN/NOTE/EVIDENCE/RENAME), details JSONB, created_at. **Append-only** |
| `saved_hunts` ✅ | 10 | owner_id (FK users), name (unique per owner), description, kind (check: query/template), definition JSONB (validated again on every load), shared (indexed), created_at, updated_at |
| `app_settings` ✅ | 8 | key, value JSONB, updated_at, updated_by: the correlation and sequence windows; changes audited |
| `rate_limit_counters` ✅ | 13 | key (scope + client or source), window_start, count; PK (key, window_start). Sliding-window rate limits shared by every backend instance; old windows removed now and then |
| `event_daily_counts` ✅ | 14 | kind (check: event/raw), day (UTC), records; PK (kind, day). Events per day of their own time, raw records per day of receipt. **Written only by triggers** (below); the dashboard reads totals and trends from it |
| `logon_success_daily` ✅ | 14 | username, source_ip (inet), day (UTC), logons (> 0), last_logon; PK (username, source_ip, day). Successful logons per account and address. **Written only by triggers**; AUTH-004 reads whole days of its 14-day history from it |

`log_sources` moved from Phase 5 to Phase 4: every event references its source, so the event
store cannot exist without it. The batches that group records per ingest request stay in
Phase 5.

## Integrity rules enforced by the database

- **Per-day summaries cannot drift** (Phase 14, migration 0014): statement-level `AFTER INSERT`
  triggers on `events` and `raw_events` (`count_inserted_events()`,
  `count_inserted_raw_events()`) add each inserted statement's rows to `event_daily_counts`
  and `logon_success_daily` in the same statement, whatever code inserts them. Both source
  tables are append-only, so counting inserts is exact. Rows are written in a fixed order, so
  concurrent batches do not deadlock. Tested: the summaries equal a fresh `GROUP BY` over the
  rows after ingestion, after hand-made inserts, and after four concurrent batches.

- Check constraints on every enum-like column, port ranges, lowercase identifiers and size
  limits (implemented for all ✅ tables and tested one by one), later also on
  `event_count ≥ 1`.
- Foreign keys without cascade on evidence chains. An asset or identity that events reference
  cannot be deleted (it is retired or disabled instead), and neither can a user in the audit
  log. The only cascade is refresh tokens with their user. Alerts will hold events in place
  the same way (Phase 7).
- **Append-only triggers** reject UPDATE and DELETE (per row) and TRUNCATE (per statement) on
  `audit_logs`, `raw_events`, `events`, `detection_rule_versions`, `incident_notes`,
  `incident_evidence` and `incident_activity`. They share one trigger function,
  `reject_modification()`. The demo reset (Phase 16) does not weaken this: it replaces the
  whole database ([ADR-0010](decisions/0010-evidence-storage.md),
  [ADR-0015](decisions/0015-demo-environment-reset.md)).
- The partial unique index `alerts(dedup_key) WHERE status IN ('NEW','TRIAGED','IN_PROGRESS')`
  makes "one active alert per key" a database guarantee, not just application logic.
- `incident_alerts(alert_id)` is unique.
- **Audit hash chain** (Phase 13): the `BEFORE INSERT` trigger `audit_logs_chain` runs
  `audit_chain()`, which takes an advisory lock, assigns the next `seq`, links `prev_hash` to
  the newest entry and computes `entry_hash` with `audit_entry_digest()` (SHA-256 over the
  entry's fields as a JSON array). The application cannot choose these values: the trigger
  overwrites them.

## Indexes (from the queries we know we will run)

| Index | Serves |
|---|---|
| ✅ `events (timestamp DESC, id DESC)` | Event explorer, keyset pagination, dashboard "today" |
| ✅ `events (event_category, event_action, timestamp)` | Rule candidate prefilter |
| ✅ `events (source_ip, timestamp)` | Pivots, AUTH rules, hunts |
| ✅ `events (username, timestamp)` | Pivots, AUTH-004 history |
| ✅ `events (host, timestamp)` | Pivots, host views |
| ✅ `events (destination_ip, timestamp)` | Hunts, NET-001 |
| ✅ `events USING gin (translate(command_line, 'A..Z', 'a..z') gin_trgm_ops)`, same on `message` | Substring search in hunts and rule prefilters (`pg_trgm`), on the ASCII-folded text the queries compare. Migration 0008 replaced the Phase 4 indexes on the raw columns, which no query could use |
| ✅ `events (asset_id)`, `events (identity_id)` | Asset and identity views; FK checks |
| ✅ `raw_events (fingerprint)` unique | Duplicate detection |
| ✅ `assets USING gin (ip_addresses)` | Enrichment: which asset owns this IP |
| ✅ `audit_logs (occurred_at)`, `(entity_type, entity_id)`, `(action)`, `(actor_id)` | Audit views, incident history |
| ✅ `alerts (status, priority_score DESC)` | Alert queue |
| ✅ `alerts (rule_id, created_at)` | Rule metrics, coverage |
| ✅ `alerts (last_event_at)`, `(host)`, `(username)`, `(source_ip)`, `(asset_id)`, `(identity_id)` | Queue by recent activity, filters, related alerts |
| ✅ `alerts (dedup_key) WHERE status IN (open)` unique | Deduplication |
| ✅ `alert_events (event_id)` | Alerts citing an event |
| `alerts (created_at)` | Trends |
| ✅ `incidents (status, risk_score DESC)`, `(last_activity_at)` | Queue |
| ✅ `incidents USING gin (hosts)`, `(usernames)`, `(source_ips)` | Correlation candidates (array overlap) |

Composite indexes lead with the equality column and end with `timestamp`, because almost every
query is "value X within time range T".

**How the indexes are tested now** (`tests/integration/test_schema.py`): for each query shape,
sequential scans are disabled and the generic time index is dropped inside the rolled-back
test transaction. The plan must then use the intended index, with the time range in its index
condition rather than as a filter. This proves each index *fits* its query. It does not prove
the planner *chooses* it at every table size: that needs real data. Phase 14 ran every page's
reads under `EXPLAIN (ANALYZE, BUFFERS)` on 921,000 generated events
([performance.md](performance.md)): the explorer, hunts and evidence pages use their intended
indexes (time, host, username, source IP, trigram); the alert and incident tables are read by
sequential scan at their size (149 and 61 rows), which is the cheapest plan there.

**Write cost.** Each event insert updates ten indexes on `events` (two of them GIN). That is
the price of fast pivots and hunts, and it bounds ingest throughput. Measured in Phase 14:
storing costs about 0.65–0.8 ms per record (duplicate check, raw record, event, enrichment,
the summary triggers, commit) and does not grow with the table up to 1 million records. The
trigram indexes stay.

## Growth plan (documented, not built)

- Partition `events` and `raw_events` by month (declarative partitioning). The primary key
  would become `(timestamp, id)`, which is why keyset pagination already uses that pair.
- A retention job drops old partitions. Evidence referenced by open incidents would be copied
  or its partition held back. Dropping partitions is a deliberate operator action, separate
  from the append-only triggers that stop the application from deleting rows.
- A BRIN index on `timestamp` for very large, append-ordered partitions.
