# API plan

> Status: routes marked ✅ are implemented and tested (health, auth, users, audit, assets,
> identities, sources, ingestion, events, detections, ATT&CK techniques). Everything else is planned in the phase shown. OpenAPI is served at
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
| GET `/api/ingest/batches` · `/api/ingest/batches/{batch_id}` | V | 5 ✅ | Batch reports, newest first (`source_id` filter): per-outcome counts, the first 50 issues, event-time span. Since Phase 6 also `status` (`PROCESSED`, `PROCESSED_WITH_ERRORS`, `DETECTION_FAILED`) and `detection_count` |
| GET `/api/ingest/batches/{batch_id}/records` | V | 5 ✅ | The batch's raw records (`parse_status` filter), shown as text (undecodable bytes as U+FFFD, at most 4,096 characters) |
| GET `/api/events` | V | 5 ✅ | Normalized events, newest first, keyset-paged (`next_cursor` → `cursor`, no total). `from`/`to` (default: last 24 h, at most 31 days), `source_id`, `batch_id`, `category`, `action`, `outcome`, `host`, `username`, `source_ip`. 400 for a bad range, cursor or IP |
| GET `/api/events/{event_id}` | V | 5 ✅ | One event with its raw record and source name (alerts citing it: Phase 7) |
| GET `/api/detections` · `/api/detections/{rule_id}` · `/api/detections/{rule_id}/versions` | V | 6 ✅ | Rules with state and statistics; one rule's effective definition, admin overrides, tunable bounds and ATT&CK mapping (per indicator); its versions, newest first. Rule IDs must look like `AUTH-001` (422 otherwise), 404 unknown |
| PATCH `/api/detections/{rule_id}` | AD | 6 ✅ | Tunable fields only (`threshold`, `time_window`, `severity`, `confidence`, `enabled`, `exclusions`), within the rule's bounds (400), `reason` required (5–500 characters). Anything else → 422. Creates a version; audited as `RULE_UPDATED` with from/to values. 409 for a rule retired from the library |
| GET `/api/detections/runs` · `/api/detections/runs/{run_id}` | V | 6 ✅ | Detection runs, newest first (`trigger` = `batch` / `manual`); one run with the per-rule outcome and every detection (explanation, facts, evidence event IDs, ATT&CK) |
| POST `/api/detections/run` | AD | 6 ✅ | `{"from", "to"}` with time zones, at most 31 days (400 otherwise). Runs every enabled rule over the range; deterministic, so repeating it gives the same detections. Audited as `DETECTION_RUN_REQUESTED`. Returns the run (201) |
| POST `/api/detections/{rule_id}/test` | A | 12 | Playground: evaluate supplied sample events, nothing stored |
| GET `/api/alerts` · `/{id}` · `/{id}/events` · `/{id}/related` | V | 7 | Queue and investigation |
| POST `/api/alerts/{id}/transition` | A | 7 | Status change (+ disposition/reason) |
| POST `/api/alerts/{id}/escalate` | A | 8 | Create incident from alert |
| GET `/api/incidents` · `/{id}` · `/{id}/timeline` · `/{id}/activity` | V | 8 | Workspace data |
| POST `/api/incidents/{id}/transition` · `/assign` · `/notes` · `/evidence` · `/alerts` (link/unlink) · PATCH title | A | 8 | Analyst actions |
| GET `/api/mitre/techniques` | V | 6 ✅ | The ATT&CK techniques (pinned v19.2) SentinelX rules map to, with the rules mapped to each. Implemented coverage only, not all of ATT&CK |
| GET `/api/mitre/coverage` | V | 11 | Coverage view (tactics × techniques) |
| GET `/api/dashboard/summary` · `/api/dashboard/trends` | V | 9 | SOC dashboard aggregates |
| POST `/api/hunt/query` | V | 10 | Structured query → events page |
| GET `/api/hunt/templates` · POST `/api/hunt/templates/{id}/run` | V | 10 | Parameterized hunts |
| GET/POST/DELETE `/api/hunt/saved…` | A (own) | 10 | Saved hunts |
| GET/PATCH `/api/settings` | AD | 8 | Correlation window, internal networks |
| GET `/api/demo/scenarios` · POST `/api/demo/run` · POST `/api/demo/reset` | AD, only when `DEMO_ENABLED` | 16 | Simulated data |

Open decision for Phase 16: whether VIEWER may run demo scenarios on a public demo instance.
The default is no.
