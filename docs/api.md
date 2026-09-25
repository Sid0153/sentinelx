# API plan

> Status: routes marked ✅ are implemented and tested (health, auth, users, audit, assets,
> identities). Everything else is planned in the phase shown. OpenAPI is served at
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
| GET/POST/PATCH `/api/sources…` | V / AD | 5 | Log sources |
| POST `/api/ingest/{source_id}` | A (Phase 13: or a per-source ingest key) | 5 | JSON `{records: [...]}` or `text/plain` lines |
| POST `/api/ingest/{source_id}/upload` | A | 5 | Multipart file (same limits) |
| GET `/api/ingest/batches` · `/{id}` | V | 5 | Batch reports |
| GET `/api/events` · `/api/events/{id}` | V | 5/9 | Filtered list; detail with raw record, alerts citing it |
| GET `/api/detections` · `/{rule_id}` · `/{rule_id}/versions` | V | 6 | Rules, effective config, history |
| PATCH `/api/detections/{rule_id}` | AD | 6 | Tunable fields only; `change_reason` required |
| POST `/api/detections/run` | AD | 6 | Re-run detection over a time range (idempotent) |
| POST `/api/detections/{rule_id}/test` | A | 12 | Playground: evaluate supplied sample events, nothing stored |
| GET `/api/alerts` · `/{id}` · `/{id}/events` · `/{id}/related` | V | 7 | Queue and investigation |
| POST `/api/alerts/{id}/transition` | A | 7 | Status change (+ disposition/reason) |
| POST `/api/alerts/{id}/escalate` | A | 8 | Create incident from alert |
| GET `/api/incidents` · `/{id}` · `/{id}/timeline` · `/{id}/activity` | V | 8 | Workspace data |
| POST `/api/incidents/{id}/transition` · `/assign` · `/notes` · `/evidence` · `/alerts` (link/unlink) · PATCH title | A | 8 | Analyst actions |
| GET `/api/mitre/techniques` · `/api/mitre/coverage` | V | 6/11 | Reference data, implemented coverage |
| GET `/api/dashboard/summary` · `/api/dashboard/trends` | V | 9 | SOC dashboard aggregates |
| POST `/api/hunt/query` | V | 10 | Structured query → events page |
| GET `/api/hunt/templates` · POST `/api/hunt/templates/{id}/run` | V | 10 | Parameterized hunts |
| GET/POST/DELETE `/api/hunt/saved…` | A (own) | 10 | Saved hunts |
| GET/PATCH `/api/settings` | AD | 8 | Correlation window, internal networks |
| GET `/api/demo/scenarios` · POST `/api/demo/run` · POST `/api/demo/reset` | AD, only when `DEMO_ENABLED` | 16 | Simulated data |

Open decision for Phase 16: whether VIEWER may run demo scenarios on a public demo instance.
The default is no.
