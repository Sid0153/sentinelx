# API plan

> Status: routes marked ✅ are implemented and tested (health, auth, users, audit, assets,
> identities, sources, ingestion, events, detections, ATT&CK techniques, alerts, incidents,
> settings). Everything else is planned in the phase shown. OpenAPI is served at
> `/api/docs` (disabled in production unless enabled explicitly) and exported to
> `docs/openapi.json`. A test fails if the export is stale.

Conventions:
- JSON only. Pydantic validation on every body and query. Validation errors never echo
  submitted values.
- Status codes: `200`/`201`, `204` (no body), `400` (semantic error), `401` (no or invalid
  token), `403` (role), `404`, `409` (state conflict, e.g. illegal transition), `413`
  (payload too large), `422` (validation), `429` (rate limit).
- Errors use one shape: `{"error": {"code": "...", "message": "...", "request_id": "..."}}`.
- Request bodies reject unknown fields (422). PATCH changes only the fields sent; `null` clears
  an optional field and is rejected for required ones.
- Lists return `{"items": [...], "total", "limit", "offset"}`: `limit` (default 50, max 200),
  offset pagination for small tables. **Keyset cursor**
  (`(timestamp, id)`, opaque) for events, hunts and timelines.
- Time ranges: `from`/`to` in ISO 8601. Event queries require a range of at most 31 days.

Roles: **V** = VIEWER+, **A** = ANALYST+, **AD** = ADMIN. Every route is declared in a
test-enforced access table (`tests/api/test_rbac.py`), and every protected route is exercised
with every role plus an unauthenticated call.

| Method & path | Role | Phase | Purpose |
|---|---|---|---|
| GET `/api/health`, `/api/ready` | public | 2 ✅ | Liveness (no DB) / readiness (DB reachable and schema at the code's migration head; 503 with `checks` otherwise, no internal details) |
| POST `/api/auth/login` | public (rate-limited, 10/min per client IP) | 3 ✅ | Email + password → access token (body) and refresh token (`sx_refresh` cookie). One generic 401 for every failure; lockout after 5 failures |
| POST `/api/auth/refresh` | refresh cookie | 3 ✅ | Rotates the refresh token, returns a new access token. Replaying a rotated token revokes every session of the user |
| POST `/api/auth/logout` | public (refresh cookie) | 3 ✅ | Revokes this session and clears the cookie; works after the access token expired |
| GET `/api/auth/me` | V | 3 ✅ | Current user |
| POST `/api/auth/change-password` | V | 3 ✅ | Needs the current password (400 if wrong); ends every session of the user |
| GET/POST `/api/users` · PATCH `/api/users/{user_id}` | AD | 3 ✅ | List (paged), create, change role / deactivate / reactivate. Never delete; not yourself (400) |
| GET `/api/audit` | AD | 3 ✅ | Audit log, newest first. Filters: `action` (repeatable), `result`, `actor_id`, `entity_type`, `entity_id`, `since`, `until` |
| GET `/api/assets` · GET `/api/assets/{asset_id}` | V | 4 ✅ | Inventory. Filters: `criticality`, `environment`, `status`, `tag`, `search` (literal substring of hostname, owner or description). Alert and incident counts added in Phase 9 |
| POST `/api/assets` · PATCH `/api/assets/{asset_id}` | AD | 4 ✅ | Create (409 on a duplicate hostname), change the fields sent. Hostname is fixed; retire with `status: retired`. Unknown fields → 422. Audited with before/after values |
| GET `/api/identities` · GET `/api/identities/{identity_id}` | V | 4 ✅ | Filters: `privilege_level`, `status`, `tag`, `search` (username, display name, department) |
| POST `/api/identities` · PATCH `/api/identities/{identity_id}` | AD | 4 ✅ | Same rules as assets; disable with `status: disabled` |
| GET `/api/sources` · GET `/api/sources/{source_id}` | V | 5 ✅ | Log sources (paged) |
| POST `/api/sources` · PATCH `/api/sources/{source_id}` | AD | 5 ✅ | Create (409 on a duplicate name), change name / description / default host / time zone (IANA) / enabled. The source type is fixed after creation. Audited |
| POST `/api/ingest/{source_id}` | A (Phase 13: or a per-source ingest key) | 5 ✅ | `application/json` `{"records": ["<raw line or JSON text>", ...]}` or `text/plain` (one record per line; CRLF and blank lines handled). Limits: 5 MB, 5,000 records, 64 KiB per record. Returns the batch report (201). 404 unknown source, 409 disabled source, 413 over a limit, 415 other content types, 422 malformed JSON body; every refusal is audited as `INGEST_REJECTED` |
| GET `/api/ingest/batches` · `/api/ingest/batches/{batch_id}` | V | 5 ✅ | Batch reports, newest first (`source_id` filter): per-outcome counts, the first 50 issues, event-time span. Since Phase 6 also `status` (`PROCESSED`, `PROCESSED_WITH_ERRORS`, `DETECTION_FAILED`) and `detection_count`; since Phase 7 `alerts_created` and `alerts_updated` |
| GET `/api/ingest/batches/{batch_id}/records` | V | 5 ✅ | The batch's raw records (`parse_status` filter), shown as text (undecodable bytes as U+FFFD, at most 4,096 characters) |
| GET `/api/events` | V | 5 ✅ | Normalized events, newest first, keyset-paged (`next_cursor` → `cursor`, no total). `from`/`to` (default: last 24 h, at most 31 days), `source_id`, `batch_id`, `category`, `action`, `outcome`, `host`, `username`, `source_ip`. 400 for a bad range, cursor or IP |
| GET `/api/events/{event_id}` | V | 5 ✅ | One event with its raw record, source name, and the alerts citing it as evidence (7) |
| GET `/api/detections` · `/api/detections/{rule_id}` · `/api/detections/{rule_id}/versions` | V | 6 ✅ | Rules with state and statistics; one rule's effective definition, admin overrides, tunable bounds and ATT&CK mapping (per indicator); its versions, newest first. Rule IDs must look like `AUTH-001` (422 otherwise), 404 unknown |
| PATCH `/api/detections/{rule_id}` | AD | 6 ✅ | Tunable fields only (`threshold`, `time_window`, `severity`, `confidence`, `enabled`, `exclusions`), within the rule's bounds (400), `reason` required (5–500 characters). Anything else → 422. Creates a version; audited as `RULE_UPDATED` with from/to values. 409 for a rule retired from the library |
| GET `/api/detections/runs` · `/api/detections/runs/{run_id}` | V | 6 ✅ | Detection runs, newest first (`trigger` = `batch` / `manual`); one run with the per-rule outcome and every detection (explanation, facts, evidence event IDs, ATT&CK) |
| POST `/api/detections/run` | AD | 6 ✅ | `{"from", "to"}` with time zones, at most 31 days (400 otherwise). Runs every enabled rule over the range; deterministic, so repeating it gives the same detections. Audited as `DETECTION_RUN_REQUESTED`. Returns the run (201) |
| POST `/api/detections/{rule_id}/test` | A | 12 | Playground: evaluate supplied sample events, nothing stored |
| GET `/api/alerts` | V | 7 ✅ | The queue, by priority score then latest activity (`sort=recent`: latest activity). Filters: `status`, `severity`, `band` (each repeatable), `rule_id`, `host`, `username` (case-insensitive), `source_ip`, `since` / `until` on the alert's event times. 400 for an unknown level or a bad IP |
| GET `/api/alerts/{alert_id}` | V | 7 ✅ | One alert: explanation and facts, priority breakdown, entities with inventory context, ATT&CK (with links), investigation and response steps, merged detections, status history (from the audit log), related alerts (sharing host, user or source within 24 h), previous alert, `allowed_transitions`, `incident_id` (Phase 8) |
| GET `/api/alerts/{alert_id}/events` | V | 7 ✅ | The evidence events in time order, each with its raw record as text (at most 4,096 characters) |
| POST `/api/alerts/{alert_id}/transition` | A | 7 ✅ | `{status, disposition?, reason?}`. RESOLVED needs a disposition; FALSE_POSITIVE and reopening need a reason (400); changes the workflow does not allow are 409. Audited as `ALERT_STATUS_CHANGED` |
| POST `/api/alerts/{alert_id}/escalate` | A | 8 ✅ | `{reason}`: open an incident from a standalone alert (409 if it already belongs to one). Audited as `INCIDENT_CREATED` |
| GET `/api/incidents` | V | 8 ✅ | The queue, by risk then latest activity (`sort=recent`). Filters: `status`, `severity` (repeatable), `assigned` (`me` or `unassigned`), `host`, `username`, `source_ip` (affected entities) |
| GET `/api/incidents/assignees` | A | 8 ✅ | Active analysts and admins (who incidents can be assigned to) |
| GET `/api/incidents/{incident_id}` | V | 8 ✅ | The workspace: summary, reason it was opened, risk breakdown, linked alerts with strength and reason, notes, current pins, activity, ATT&CK (with rules and links), grouped response, related incident, `allowed_transitions` |
| GET `/api/incidents/{incident_id}/timeline` | V | 8 ✅ | Evidence events (each once, with citing rules and raw text), alerts and activity, oldest first; `limit` ≤ 200, keyset `cursor` |
| POST `/api/incidents/{incident_id}/transition` | A | 8 ✅ | `{status, disposition?, resolution?, reason?}`: RESOLVED needs disposition + resolution, reopening a reason (400); not allowed 409; CLOSED final |
| POST `/api/incidents/{incident_id}/assign` · `/notes` · `/evidence` | A | 8 ✅ | Assign (analysts/admins only, `null` unassigns); append-only note (1–10,000 characters; 201); pin/unpin an event or alert with a tag and comment. 409 on a closed incident |
| POST `/api/incidents/{incident_id}/alerts` · `/alerts/{alert_id}/unlink` · PATCH `/api/incidents/{incident_id}` | A | 8 ✅ | Link an alert by hand, unlink it (both with a reason; an unlinked alert is never linked back by the engine), rename (the title then stays) |
| GET `/api/mitre/techniques` | V | 6 ✅ | The ATT&CK techniques (pinned v19.2) SentinelX rules map to, with the rules mapped to each. Implemented coverage only, not all of ATT&CK |
| GET `/api/mitre/coverage` | V | 11 | Coverage view (tactics × techniques) |
| GET `/api/dashboard/summary` · `/api/dashboard/trends` | V | 9 | SOC dashboard aggregates |
| POST `/api/hunt/query` | V | 10 | Structured query → events page |
| GET `/api/hunt/templates` · POST `/api/hunt/templates/{id}/run` | V | 10 | Parameterized hunts |
| GET/POST/DELETE `/api/hunt/saved…` | A (own) | 10 | Saved hunts |
| GET/PATCH `/api/settings` | AD | 8 ✅ | Correlation window (15–1,440 min) and sequence window (5–240 min, not longer). Audited as `SETTINGS_CHANGED`. Internal networks stay environment configuration (reviewed with deployments) |
| GET `/api/demo/scenarios` · POST `/api/demo/run` · POST `/api/demo/reset` | AD, only when `DEMO_ENABLED` | 16 | Simulated data |

Open decision for Phase 16: whether VIEWER may run demo scenarios on a public demo instance.
The default is no.
