# API

> Status: every route below is implemented and tested (✅, with the phase that built it).
> OpenAPI is served at `/api/docs` (disabled in production unless enabled explicitly) and
> exported to [openapi.json](openapi.json). A test fails if the export is stale, and another
> if a route is missing from the role table (`backend/tests/api/test_rbac.py`).

Conventions:
- Request bodies: at most 1 MiB (5 MB on ingest), refused with 413 `payload_too_large` by the
  backend itself, whatever proxy is in front (Phase 13). Every body model refuses unknown
  fields and bounds every string (tested over the OpenAPI schema).
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
| POST `/api/auth/login` | public (rate-limited, 10/min per client IP) | 3 ✅ | Email + password → access token (body) and refresh token (`sx_refresh` cookie). One generic 401 for every failure; lockout after 5 failures. With two-factor sign-in on: a right password alone gets 401 code `mfa_required`; send it again with `otp` (6 digits) or `recovery_code`. Wrong codes count towards the lockout (13) |
| POST `/api/auth/refresh` | refresh cookie | 3 ✅ | Rotates the refresh token, returns a new access token. Replaying a rotated token revokes every session of the user |
| POST `/api/auth/logout` | public (refresh cookie) | 3 ✅ | Revokes this session and clears the cookie; works after the access token expired |
| GET `/api/auth/me` | V | 3 ✅ | Current user |
| POST `/api/auth/change-password` | V | 3 ✅ | Needs the current password (400 if wrong; 400 if the new one is the same); ends every session of the user; clears `must_change_password` |
| POST `/api/auth/mfa/setup` · `/api/auth/mfa/enable` · `/api/auth/mfa/disable` | V (own account) | 13 ✅ | Setup returns a new key and `otpauth://` link (409 when already on). Enable takes `{code}` from the app and returns ten recovery codes, once (400 wrong code). Disable takes `{password, code}` (code or recovery code; 400 if either is wrong). Audited `MFA_ENABLED` / `MFA_DISABLED`, failures included |
| POST `/api/users/{user_id}/reset-password` | AD | 13 ✅ | Returns `{temporary_password}` once (`Cache-Control: no-store`); unlocks the account and ends its sessions; the user must change it before any other call (403 `password_change_required`). Not your own account (400). Audited `PASSWORD_RESET` without the password |
| POST `/api/users/{user_id}/reset-mfa` | AD | 13 ✅ | Turns two-factor sign-in off for a user who lost their device; ends their sessions. Not your own account (400). Audited `MFA_RESET` |
| GET/POST `/api/users` · PATCH `/api/users/{user_id}` | AD | 3 ✅ | List (paged), create, change role / deactivate / reactivate. Never delete; not yourself (400) |
| GET `/api/audit` | AD | 3 ✅ | Audit log, newest first. Filters: `action` (repeatable), `result`, `actor_id`, `entity_type`, `entity_id`, `since`, `until`. Entries carry `seq` (their place in the hash chain; null before it existed) |
| GET `/api/audit/integrity` | AD | 13 ✅ | Recomputes the audit hash chain: `intact`, `chained`, `legacy` (entries before the chain), `first_broken_seq`, `head_seq`, `head_hash` (compare with the `audit.chained` log lines) |
| GET `/api/assets` · GET `/api/assets/{asset_id}` | V | 4 ✅ | Inventory. Filters: `criticality`, `environment`, `status`, `tag`, `search` (literal substring of hostname, owner or description). List items add `open_alerts` (open alerts involving the host) and `last_seen_at` (its latest event) |
| POST `/api/assets` · PATCH `/api/assets/{asset_id}` | AD | 4 ✅ | Create (409 on a duplicate hostname), change the fields sent. Hostname is fixed; retire with `status: retired`. Unknown fields → 422. Audited with before/after values |
| GET `/api/identities` · GET `/api/identities/{identity_id}` | V | 4 ✅ | Filters: `privilege_level`, `status`, `tag`, `search` (username, display name, department). List items add `open_alerts` (actor or target) and `last_seen_at` |
| GET `/api/assets/{asset_id}/activity` · GET `/api/identities/{identity_id}/activity` | V | 9 ✅ | Open and total alerts and incidents that involve it, its latest event, the 10 most recent alerts and incidents. An asset matches by asset ID, hostname or short hostname (events that arrived before it was registered count too); an identity by ID, username or target username |
| POST `/api/identities` · PATCH `/api/identities/{identity_id}` | AD | 4 ✅ | Same rules as assets; disable with `status: disabled` |
| GET `/api/sources` · GET `/api/sources/{source_id}` | V | 5 ✅ | Log sources (paged) |
| POST `/api/sources` · PATCH `/api/sources/{source_id}` | AD | 5 ✅ | Create (409 on a duplicate name), change name / description / default host / time zone (IANA) / enabled / `allowed_hosts` (13: up to 200 host names; when set, a record naming any other host is stored as FAILED, code `host_not_allowed`). The source type is fixed after creation. Audited |
| POST `/api/ingest/{source_id}` | A, or the source's ingest key (`X-Ingest-Key`, Phase 13) | 5 ✅ | `application/json` `{"records": ["<raw line or JSON text>", ...]}` or `text/plain` (one record per line; CRLF and blank lines handled). Limits: 5 MB, 5,000 records, 64 KiB per record. Returns the batch report (201). 404 unknown source, 409 disabled source, 413 over a limit, 415 other content types, 422 malformed JSON body, 401 a key that is not this source's, 429 over the per-source rate limit (120/min, `Retry-After`); every refusal is audited as `INGEST_REJECTED` |
| POST · DELETE `/api/sources/{source_id}/ingest-key` | AD | 13 ✅ | Issue (201, the key in this response only; replaces any previous key) or revoke (204; 404 when there is none). Audited `INGEST_KEY_ISSUED` / `INGEST_KEY_REVOKED` with the prefix only. Sources show `ingest_key_prefix`, `ingest_key_created_at`, `ingest_key_last_used_at`, never the key |
| GET `/api/ingest/batches` · `/api/ingest/batches/{batch_id}` | V | 5 ✅ | Batch reports, newest first (`source_id` filter): per-outcome counts, the first 50 issues, event-time span. Since Phase 6 also `status` (`PROCESSED`, `PROCESSED_WITH_ERRORS`, `DETECTION_FAILED`) and `detection_count`; since Phase 7 `alerts_created` and `alerts_updated` |
| GET `/api/ingest/batches/{batch_id}/records` | V | 5 ✅ | The batch's raw records (`parse_status` filter), shown as text (undecodable bytes as U+FFFD, at most 4,096 characters). For viewers `text` is null and `withheld` true (13: raw text is analyst-only) |
| GET `/api/events` | V | 5 ✅ | Normalized events, newest first, keyset-paged (`next_cursor` → `cursor`, no total). `from`/`to` (default: last 24 h, at most 31 days), `source_id`, `batch_id`, `category`, `action`, `outcome`, `host`, `username`, `source_ip`. 400 for a bad range, cursor or IP |
| GET `/api/events/{event_id}` | V | 5 ✅ | One event with its raw record, source name, and the alerts citing it as evidence (7). Viewers get the raw record without its text (`withheld`, 13) |
| GET `/api/detections` · `/api/detections/{rule_id}` · `/api/detections/{rule_id}/versions` | V | 6 ✅ | Rules with state and statistics; one rule's effective definition, admin overrides, tunable bounds and ATT&CK mapping (per indicator); its versions, newest first (`limit`, default 100, at most 200; Phase 14). Rule IDs must look like `AUTH-001` (422 otherwise), 404 unknown |
| PATCH `/api/detections/{rule_id}` | AD | 6 ✅ | Tunable fields only (`threshold`, `time_window`, `severity`, `confidence`, `enabled`, `exclusions`), within the rule's bounds (400), `reason` required (5–500 characters). Anything else → 422. An exclusion may carry `active_from` / `active_until` (a suppression window, at most 90 days; Phase 12). Creates a version; audited as `RULE_UPDATED` with from/to values. 409 for a rule retired from the library |
| POST `/api/detections/{rule_id}/test` | A | 12 ✅ | Detection playground: `{source_type, records (≤ 500, ≤ 256 KiB), timezone?, default_host?, changes?}`. Runs the real parser, enrichment and evaluator; stores nothing. Returns `triggered`, the rule as tried, a summary, the detections (explanation, severity, confidence, evidence lines, ATT&CK) and each line's outcome. What-if `changes` are checked like a real tune (400); `enabled` is refused |
| GET `/api/detections/runs` · `/api/detections/runs/{run_id}` | V | 6 ✅ | Detection runs, newest first (`trigger` = `batch` / `manual`); one run with the per-rule outcome and every detection (explanation, facts, evidence event IDs, ATT&CK) |
| POST `/api/detections/run` | AD | 6 ✅ | `{"from", "to"}` with time zones, at most 31 days (400 otherwise). Runs every enabled rule over the range; deterministic, so repeating it gives the same detections. Audited as `DETECTION_RUN_REQUESTED`. Returns the run (201) |
| POST `/api/detections/{rule_id}/test` | A | 12 ✅ | Playground: evaluate supplied sample events, nothing stored |
| GET `/api/alerts/groups?by=` | V | 12 ✅ | The queue grouped by `rule`, `host`, `username` or `source_ip`, with the same filters as the list: per group alerts, open, highest priority and band, latest activity; at most 100 groups (highest priority first) and the `total`. A view only |
| GET `/api/alerts` | V | 7 ✅ | The queue, by priority score then latest activity (`sort=recent`: latest activity). Filters: `status`, `severity`, `band` (each repeatable), `rule_id`, `host`, `username` (case-insensitive), `source_ip`, `since` / `until` on the alert's event times. 400 for an unknown level or a bad IP |
| GET `/api/alerts/{alert_id}` | V | 7 ✅ | One alert: explanation and facts, priority breakdown, entities with inventory context, ATT&CK (with links), investigation and response steps, merged detections, status history (from the audit log), related alerts (sharing host, user or source within 24 h), previous alert, `allowed_transitions`, `incident_id` (Phase 8) |
| GET `/api/alerts/{alert_id}/events` | V | 7 ✅ | The evidence events in time order, each with its raw record as text (at most 4,096 characters; null with `raw_withheld` for viewers, 13) |
| POST `/api/alerts/{alert_id}/transition` | A | 7 ✅ | `{status, disposition?, reason?}`. RESOLVED needs a disposition; FALSE_POSITIVE and reopening need a reason (400); changes the workflow does not allow are 409. Audited as `ALERT_STATUS_CHANGED` |
| POST `/api/alerts/{alert_id}/escalate` | A | 8 ✅ | `{reason}`: open an incident from a standalone alert (409 if it already belongs to one). Audited as `INCIDENT_CREATED` |
| GET `/api/incidents` | V | 8 ✅ | The queue, by risk then latest activity (`sort=recent`). Filters: `status`, `severity` (repeatable), `assigned` (`me` or `unassigned`), `host`, `username`, `source_ip` (affected entities) |
| GET `/api/incidents/assignees` | A | 8 ✅ | Active analysts and admins (who incidents can be assigned to) |
| GET `/api/incidents/{incident_id}` | V | 8 ✅ | The workspace: summary, reason it was opened, risk breakdown, linked alerts with strength and reason, notes, current pins, activity, ATT&CK (with rules and links), grouped response, related incident, `allowed_transitions` |
| GET `/api/incidents/{incident_id}/timeline` | V | 8 ✅ | Evidence events (each once, with citing rules and raw text; raw text null for viewers, 13), alerts and activity, oldest first; `limit` ≤ 200, keyset `cursor` |
| POST `/api/incidents/{incident_id}/transition` | A | 8 ✅ | `{status, disposition?, resolution?, reason?}`: RESOLVED needs disposition + resolution, reopening a reason (400); not allowed 409; CLOSED final |
| POST `/api/incidents/{incident_id}/assign` · `/api/incidents/{incident_id}/notes` · `/api/incidents/{incident_id}/evidence` | A | 8 ✅ | Assign (analysts/admins only, `null` unassigns); append-only note (1–10,000 characters; 201); pin/unpin an event or alert with a tag and comment. 409 on a closed incident |
| POST `/api/incidents/{incident_id}/alerts` · `/api/incidents/{incident_id}/alerts/{alert_id}/unlink` · PATCH `/api/incidents/{incident_id}` | A | 8 ✅ | Link an alert by hand, unlink it (both with a reason; an unlinked alert is never linked back by the engine), rename (the title then stays) |
| GET `/api/mitre/techniques` | V | 6 ✅ | The ATT&CK techniques (pinned v19.2) SentinelX rules map to, with the rules mapped to each. Implemented coverage only, not all of ATT&CK |
| GET `/api/mitre/coverage?days=` | V | 11 ✅ | "Implemented coverage": all 15 ATT&CK tactics in order (with the techniques covered under each), every technique the library maps to with its rules (state, severity, indicator, reason, alerts in the period, last trigger), and a summary. `days` 1–365 (default 30) |
| GET `/api/detections/metrics?days=` | V | 11 ✅ | Per rule, for the alerts it created in the period: open, confirmed, benign, false positives, closed, false-positive rate (null until one is closed), median time to triage and to close, detections and last match |
| GET `/api/dashboard/summary` | V | 9 ✅ | Counted from the database on each request: records processed, events stored and today (UTC), alerts today, open alerts (and how many simulated), open critical/high, severity distribution, open incidents and those under investigation, hosts that sent events in 24 h, inventory assets, active and library rules, top 5 rules and source IPs (alerts, 7 days), 8 recent alerts, 5 recent incidents |
| GET `/api/dashboard/trends?days=` | V | 9 ✅ | Per UTC day, zero-filled: alerts created by severity, incidents opened, events (by event time). `days` 1–90, default 14 |
| GET `/api/hunt/fields` | V | 10 ✅ | Fields a hunt may filter on, with their type and operators (for the query builder) |
| POST `/api/hunt/query` | V | 10 ✅ | Structured query ([threat-hunting.md](threat-hunting.md)): `time_range` (required, ≤ 31 days, `from`/`to` or `last`), ≤ 20 `filters`, optional `alert` filters, `sort` newest/oldest, `limit` ≤ 200, keyset `cursor`. Returns events, `total` (counted up to 10,000, `total_capped` beyond), the resolved `from`/`to`. 422 for an invalid query, 400 for a bad cursor, 503 `hunt_timeout` after the statement timeout (5 s) |
| GET `/api/hunt/templates` · POST `/api/hunt/templates/{template_id}/run` | V | 10 ✅ | Four reviewed SQL templates with typed, bounded parameters; `{params, time_range}`; ≤ 200 rows (`truncated`). 404 unknown template, 422 bad parameters, 503 timeout |
| GET `/api/hunt/saved` · GET `/api/hunt/saved/{hunt_id}` | V | 10 ✅ | Your saved hunts and those shared by others; each with `valid` and `problem` (a definition from an older version is flagged, never run). A private hunt of someone else is 404 |
| POST `/api/hunt/saved` · PATCH · DELETE `/api/hunt/saved/{hunt_id}` | A (owner) | 10 ✅ | Save (201; name unique per owner, 409; at most 100 saved hunts per user, 409 beyond, Phase 14), change name, description, definition or `shared`, delete (204). Owner only (403). Audited `HUNT_SAVED` / `HUNT_UPDATED` / `HUNT_DELETED` with name, kind and sharing, never filter values |
| GET/PATCH `/api/settings` | AD | 8 ✅ | Correlation window (15–1,440 min) and sequence window (5–240 min, not longer). Audited as `SETTINGS_CHANGED`. Internal networks stay environment configuration (reviewed with deployments) |

The demo environment has no API routes: it is loaded and reset by an operator on the server
(`python -m app.cli demo-load`, `scripts/demo_reset.sh`; [demo.md](demo.md)). The design
first planned admin routes behind a `DEMO_ENABLED` setting. Phase 16 dropped them, because a
reset replaces the whole database (ADR-0015), which an API request should not be able to do.
