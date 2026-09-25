# API plan

> Status: **Implemented: `GET /api/health`, `GET /api/ready` (Phase 2).** Everything else is
> planned. Routes are built in the phase shown. OpenAPI is served at
> `/api/docs` (disabled in production unless enabled explicitly) and exported to
> `docs/openapi.json`. A test fails if the export is stale.

Conventions:
- JSON only. Pydantic validation on every body and query. Validation errors never echo
  submitted values.
- Status codes: `200`/`201`, `204` (no body), `400` (semantic error), `401` (no or invalid
  token), `403` (role), `404`, `409` (state conflict, e.g. illegal transition), `413`
  (payload too large), `422` (validation), `429` (rate limit).
- Errors use one shape: `{"error": {"code": "...", "message": "...", "request_id": "..."}}`.
- Lists: `limit` (default 50, max 200). Offset pagination for small tables. **Keyset cursor**
  (`(timestamp, id)`, opaque) for events, hunts and timelines.
- Time ranges: `from`/`to` in ISO 8601. Event queries require a range of at most 31 days.

Roles: **V** = VIEWER+, **A** = ANALYST+, **AD** = ADMIN. Every route is declared in a
test-enforced access table (`tests/api/test_rbac.py`), and every protected route is exercised
with every role plus an unauthenticated call.

| Method & path | Role | Phase | Purpose |
|---|---|---|---|
| GET `/api/health`, `/api/ready` | public | 2 ✅ | Liveness (no DB) / readiness (DB reachable and schema at the code's migration head; 503 with `checks` otherwise, no internal details) |
| POST `/api/auth/login` | public (rate-limited) | 3 | Email + password → access token, refresh cookie |
| POST `/api/auth/refresh` | cookie | 3 | Rotate refresh token |
| POST `/api/auth/logout` | V | 3 | Revoke session |
| GET `/api/auth/me` · POST `/api/auth/change-password` | V | 3 | Current user |
| GET/POST `/api/users` · PATCH `/api/users/{id}` | AD | 3 | Create users, change role, deactivate |
| GET `/api/assets` · GET `/api/assets/{id}` | V | 4 | Inventory (with alert/incident counts in Phase 9) |
| POST/PATCH `/api/assets…` | AD | 4 | Maintain inventory |
| GET/POST/PATCH `/api/identities…` | V / AD | 4 | Same for identities |
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
| GET `/api/audit` | AD | 3/9 | Audit log search |
| GET `/api/demo/scenarios` · POST `/api/demo/run` · POST `/api/demo/reset` | AD, only when `DEMO_ENABLED` | 16 | Simulated data |

Open decision for Phase 16: whether VIEWER may run demo scenarios on a public demo instance.
The default is no.
