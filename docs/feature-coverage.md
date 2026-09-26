# Feature coverage

Every feature the project brief asks for, the phase that builds it, and where it stands.
Updated at the end of every phase; a phase is not done until its rows here are true.

✅ done and tested · ◐ partly done (what is missing is named) · ⬜ planned (phase)

Last updated: **Phase 8**.

## Primary product capabilities (brief §"Primary product capabilities")

| # | Capability | Phase | Status |
|---|---|---|---|
| 1 | Multi-source security log ingestion | 5 | ✅ Linux auth, Windows security (JSON), HTTP access, application JSON, generic JSON; API (JSON / text), file (CLI), batch import, demo generator |
| 2 | Event parsing | 5 | ✅ five parsers, fuzzed and linear-time |
| 3 | Event normalization | 4, 5 | ✅ `NormalizedEvent`, controlled vocabulary, DB checks |
| 4 | Event enrichment | 5 | ✅ normalized users, host → asset, source classification, internal/external IP, categorization, asset criticality, identity context (actor). ◐ target-account context: Phase 11 |
| 5 | Detection engineering | 6 | ✅ rule library as reviewed YAML, validated at startup; versions; tests per rule and per scenario |
| 6 | Rule-based detection | 6 | ✅ declarative YAML rules, safe condition language (Python authoritative, SQL prefilter proven a superset) |
| 7 | Temporal detection | 6 | ✅ threshold, distinct, sequence (with max gap) and new-value windows on event time |
| 8 | Event correlation | 8 | ✅ alerts into incidents by host, user, source, time window and new kinds of finding; a stated reason per link (`correlation.md`, ADR-0009/0012) |
| 9 | Alert generation | 7 | ✅ from every detection, in the run's transaction |
| 10 | Alert deduplication | 7 | ✅ dedup key, evidence-based idempotence, one open alert per key enforced by the database (ADR-0011) |
| 11 | Alert prioritization | 7 | ✅ SentinelX priority score with stored breakdown and model version (`risk-model.md`) |
| 12 | Incident creation | 8 | ✅ by correlation (high-severity alert, or multi-stage partners) and by analysts (escalation); not one incident per alert |
| 13 | Incident investigation | 8, 9 | ⬜ |
| 14 | Timeline reconstruction | 8 | ✅ from stored events, alerts and activity, paged by keyset |
| 15 | Threat hunting | 10 | ⬜ structured queries, templates, pivots, saved hunts |
| 16 | MITRE ATT&CK mapping | 6, 8, 11 | ◐ pinned v19.2 reference file, re-checked on attack.mitre.org; stored per rule and per indicator, `GET /api/mitre/techniques`. Shown on alerts (7 ✅) and incidents with links and the rules mapping to each (8 ✅); coverage view (11) |
| 17 | Evidence management | 7, 8 | ✅ alert evidence with raw records, events → alerts citing them, incident evidence pins (append-only, tagged) |
| 18 | Analyst notes | 8 | ✅ append-only (database triggers) |
| 19 | Response recommendations | 6, 8 | ◐ per-rule investigation and response steps, filled from the evidence, on every detection and alert; grouped per finding and de-duplicated on incidents ✅ |
| 20 | Detection-rule management | 6, 12 | ◐ API: tunable fields within bounds, reason required, versions (append-only), audit, retire on library removal. UI: Phase 9/12 |
| 21 | Search and filtering | 5, 10 | ◐ events API: time range, source, batch, category, action, outcome, host, user, source IP, keyset paging. Full hunting: Phase 10 |
| 22 | Security analytics | 9, 11 | ⬜ dashboard aggregates, rule metrics |
| 23 | Risk/context scoring | 7, 11 | ⬜ |
| 24 | RBAC | 3 | ✅ ADMIN / ANALYST / VIEWER enforced by the API; route × role matrix test |
| 25 | Audit logging | 3+ | ✅ append-only; rule changes and manual detection runs audited (6); alert status changes (7); every incident action and settings change (8) |
| 26 | API | 2+ | ◐ health, auth, users, audit, assets, identities, sources, ingest, batches, events, detections, detection runs, MITRE techniques, alerts, incidents, settings done; hunt, coverage, dashboard in their phases |
| 27 | SOC dashboard | 9 | ⬜ |
| 28 | Dockerized deployment | 2 | ✅ Compose: postgres, backend, frontend; hardened; health checks |
| 29 | Automated testing | 2+ | ✅ 500+ backend tests (97 % coverage), frontend tests, smoke scripts |
| 30 | CI/CD | 2, 15 | ✅ CI (lint, types, tests, audits, gitleaks, Compose smoke). ⬜ production-style configuration and deployment docs: Phase 15 |
| 31 | Security hardening | 2+, 13 | ◐ headers, CSP, rate limit, validation, hardened containers, spoofing-proof client IP; full review: Phase 13 |
| 32 | Comprehensive documentation | every phase, 17 | ◐ design docs and ADRs current; screenshots, guides, demo guide: Phase 17 |

## Detection (brief §4–§7)

| Item | Phase | Status |
|---|---|---|
| Rule fields: id, name, description, category, severity, confidence, enabled, conditions, threshold, time window, aggregation, MITRE, investigation and response guidance | 6 | ✅ all of them, plus kind, tunable bounds, exclusions, per-indicator ATT&CK |
| A single-event, B threshold, C temporal, D sequence, E aggregation | 6 | ✅ `single`, `threshold`, time windows, `sequence`, `distinct` (count of distinct values per group); plus `new_value` |
| F cross-event correlation | 8 | ✅ incident correlation (above) |
| AUTH-001, AUTH-002, AUTH-003, AUTH-004, PRIV-001, ACCT-001, PROC-001, NET-001 | 6 | ✅ each fires on its scenario, in memory, in PostgreSQL and live; AUTH-004 with stored history. Plus AUTH-005 (distributed brute force), added to close a documented gap |
| Explainable alerts (what, why, which events, entities, confidence, severity, next steps) from real evidence | 6, 7 | ✅ every alert: what (explanation), why (description, facts), which events (evidence with raw records), entities, confidence, severity, next steps; all from its evidence |

## Alerts, incidents, risk (brief §8–§12, §16, §22, §45)

| Item | Phase | Status |
|---|---|---|
| Alert fields and statuses NEW / TRIAGED / IN_PROGRESS / RESOLVED / FALSE_POSITIVE | 7 | ✅ every brief field (mapping in `detection-engine.md`); workflow tested over all 25 status pairs |
| Deduplication strategy documented | 1, 7 | ✅ `detection-engine.md`, ADR-0011 |
| Transparent prioritization | 7 | ✅ (`risk-model.md`; breakdown shown on every alert) |
| Incident fields and statuses OPEN / TRIAGED / INVESTIGATING / CONTAINED / RESOLVED / CLOSED | 8 | ✅ every brief field (mapping in `correlation.md`); workflow tested over all 36 status pairs |
| Correlation on source IP, host, user, time window, sequence, detection relationships | 8 | ✅ (sequence and detection relationships: a new kind of finding after a foothold on the same host, within the sequence window); standalone alerts are swept in when an incident grows, and manual runs backfill |
| Timeline from stored events and actions | 8 | ✅ |
| Explainable risk level and score | 7, 8, 11 | ✅ alert priority (7) and incident risk (8), breakdowns shown; context display: Phase 11 |
| Defensive response recommendations, never automatic actions | 6, 8 | ✅ per alert and per incident; nothing is ever executed |
| False-positive handling (confirmed / false positive / resolved, counts, resolution times) | 7, 11, 12 | ◐ analyst actions tracked: disposition, false positive with reason, who and when, audit ✅; counts and resolution times shown: Phase 11. No machine-learning feedback (none claimed) |

## Context (brief §17–§18)

| Item | Phase | Status |
|---|---|---|
| Asset model: id, hostname, IP addresses, type, environment, criticality, owner, tags, status | 4 | ✅ API (read all, ADMIN writes, audited) |
| Identity model: id, username, display name, role (as `title`), department, privilege level, status, tags | 4 | ✅ API |
| Events reference assets | 4, 5 | ✅ enrichment links `events.asset_id` |
| Incidents reference assets | 8, 11 | ◐ through their alerts (asset of the evidence) and affected hosts; asset context on the incident page: Phase 11 |

## Frontend pages (brief §29)

| Page | Phase | Status |
|---|---|---|
| /login | 3 | ✅ |
| /dashboard | 9 | ⬜ |
| /events | 9 | ⬜ (API ready) |
| /hunt | 10 | ⬜ |
| /detections | 9, 11, 12 | ⬜ list, detail and enable/disable (9); coverage (11); versions and playground (12) |
| /alerts, /alerts/:id | 7 | ✅ queue with filters; alert page with the brief's §20 content (incident association: Phase 8); checked on desktop and phone widths |
| /incidents, /incidents/:id | 8 | ✅ queue, workspace (actions for analysts), checked on desktop and phone widths |
| /assets, /identities | 9 | ⬜ (API ready) |
| /audit | 3 | ✅ |
| /settings | 3, 8 | ✅ account and password (3), users (3), correlation windows at `/correlation` (8). Internal networks stay environment configuration (decision in `api.md`) |
| Status page (not in the brief; health at a glance) | 2 | ✅ |

## API areas (brief §28)

| Area | Status |
|---|---|
| /api/auth, /api/users, /api/audit | ✅ (3) |
| /api/assets, /api/identities | ✅ (4) |
| /api/events (+ /api/sources, /api/ingest) | ✅ (5) |
| /api/detections, /api/mitre/techniques | ✅ (6); /api/mitre/coverage ⬜ (11) |
| /api/alerts | ✅ (7) |
| /api/incidents, /api/settings | ✅ (8) |
| /api/dashboard | ⬜ (9) |
| /api/hunt | ⬜ (10) |

## SOC dashboard metrics (brief §19)

All ⬜ Phase 9, from the database, with empty states: events processed, events today, alerts
today, critical and high alerts, open incidents, incidents under investigation, monitored
hosts, active rules, top triggered rules, top source IPs, severity distribution, alert and
incident trends, recent alerts and incidents.

## Audit actions (brief §25)

| Action | Phase | Status |
|---|---|---|
| Login, logout, failed login | 3 | ✅ (plus lockout, rate limit, token reuse, access denied) |
| User creation, role modification | 3 | ✅ (plus deactivate / reactivate) |
| Configuration changes | 4, 5, 8 | ✅ assets, identities, log sources, correlation settings |
| Rule modification | 6 | ✅ `RULE_UPDATED` with from/to values and reason; library add/update/retire; manual runs |
| Alert status change | 7 | ✅ `ALERT_STATUS_CHANGED` with from/to, disposition, reason |
| Incident status change, assignment, note creation | 8 | ✅ plus evidence, links, rename, escalation (note ID only, never its text) |

## Demo data system (brief §30)

| Item | Phase | Status |
|---|---|---|
| Scenario selection, event count, time range (start and interval), host, user, source IP | 5 | ✅ `demo-ingest` options, validated; unsupported options refused |
| 1 normal authentication · 10 benign activity | 5, 6 | ✅ `benign`, tested to trigger no rule |
| 2 brute force · 3 password spraying · 4 success after failures | 5 | ✅ plus `distributed_brute_force` (AUTH-005) |
| 5 privilege escalation · 6 privileged account creation · 7 suspicious process · 8 suspicious network | 6 | ✅ each in its own source format, tested to trigger exactly its rule |
| 9 multi-stage correlated incident | 8 | ✅ `multi_stage_attack`: four rules, one incident (tested in one batch and in four, live, in CI) |
| Clearly marked simulated; internally consistent | 5 | ✅ `simulated` flag on batch, raw record and event; RFC 5737 addresses |
| Repeatable demonstrations, reset of the demo environment | 16 | ⬜ |

## Engineering requirements

| Item (brief section) | Status |
|---|---|
| Modular monolith (§ARCHITECTURAL PRINCIPLE) | ✅ ADR-0001 |
| Raw and normalized stored separately; raw never modified (§46) | ✅ bytes, append-only incl. TRUNCATE (ADR-0010) |
| Threat model: assets, trust boundaries, attack surfaces, threats, mitigations, residual risks (§26) | ◐ initial in `security.md`; completed in Phase 13 |
| Observability: request IDs, structured logs, ingestion counts, processing and database errors (§34) | ✅ including detection runs (per-rule candidates, detections, errors, time; `detection.run_completed` log) |
| Docker: health checks, env config, persistent volume, documented start (§35) | ✅ |
| ADR-001 … ADR-007 (§38) | ✅ plus 0008–0010 |
| Performance: indexes, pagination, bounded responses, batch ingestion (§33) | ✅ so far (index-fit tests, keyset paging, batched inserts); measured benchmarks: Phase 14 |
| Detection coverage view, labelled "Implemented coverage" (§43) | ⬜ Phase 11 |
| Detection testing playground (§44) | ⬜ Phase 12 |
| Real-world extension plan (§49) | ✅ `architecture.md` |
| Interview and portfolio package (§48, Phase 19) | ⬜ |

## Deliberate interpretations (documented, not omissions)

- Event fields: `event_category` / `event_action` / `event_outcome` replace the brief's
  overlapping `event_type` / `status` / `action`; `hostname` = `host`, `user_id` =
  `identity_id`, `metadata` = `attributes` (ADR-0003).
- Role is a column on users, not a table (three fixed roles).
- Audit fields: `details` = metadata, `occurred_at` = timestamp; the actor is `actor_id` plus
  `actor_label`.
- VIEWER may change their own password (`security.md`).
- Files are ingested by sending them as `text/plain` to the ingest endpoint: no separate
  upload route.
