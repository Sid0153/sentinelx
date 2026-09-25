# Correlation and incidents

> Status: **DESIGN (Phase 1)**. Built in Phase 8. See
> [ADR-009](decisions/0009-entity-based-incident-correlation.md).

Correlation groups **alerts** (not raw events) into **incidents**. Rules answer "did this
pattern happen?". Correlation answers "are these alerts parts of the same story?".

## Inputs

Each alert exposes a set of **entities**, taken from its group values and evidence:
- `source_ip`, with its scope (internal/external)
- `host` (and `asset_id`)
- `username` (actor) and `target_username` (e.g. the account that was created)

Plus its time span (`first_event_at`, `last_event_at`) and its rule's ATT&CK tactics.

## Link strength

A pure function scores an alert against an open incident (the union of the incident's
entities):

| Shared entities (with the incident) | Strength | Auto-link? |
|---|---|---|
| host **and** username (actor, or actor ↔ target) | STRONG | yes |
| host **and** source_ip | STRONG | yes |
| external source_ip only (different hosts) | MEDIUM | yes. One outside source acting against several hosts is one campaign from the analyst's view |
| host only | WEAK | no. Shown under "related alerts" |
| username only (different hosts) | WEAK | no. Shown as related (possible lateral movement, but too noisy to auto-merge) |
| internal source_ip only | WEAK | no (shared NAT, jump hosts) |
| nothing | NONE | no |

**Time condition:** the alert's `first_event_at` must be within the **correlation window**
(default 2 h, admin-configurable 15 min – 24 h) of the incident's `last_activity_at`.

The incident only accepts alerts while its status is `OPEN`, `TRIAGED`, `INVESTIGATING` or
`CONTAINED`. A `RESOLVED`/`CLOSED` incident is never extended. Related new activity starts a
new incident that links back to the old one (`related_incident_id`).

## Algorithm (runs after alerts are created or extended in a detection pass)

```
for each alert touched in this pass, in order of first_event_at:
    if alert already belongs to an incident:            # extended alert
        refresh that incident (entities, span, severity, risk); continue
    candidates = open incidents within the correlation window sharing ≥1 entity   (indexed)
    best = highest strength ≥ MEDIUM; ties → most recent last_activity_at, then lowest id
    if best: link(alert, best, reason); continue
    if alert.severity ≥ HIGH:
        create incident from alert (reason: "high-severity alert")
    else:
        partners = unincorporated active alerts from a DIFFERENT rule, STRONG link, in window
        if partners: create incident from alert + partners (reason: "multi-stage activity")
        else: leave as a standalone alert
```

Consequences:
- A low- or medium-severity alert on its own does **not** create an incident. Not every alert
  becomes one.
- AUTH-001 (medium) + AUTH-002 (high) + PRIV-001 + ACCT-001 on the same host with the same
  user and source become **one** incident. AUTH-002 creates it, the earlier AUTH-001 joins as
  a STRONG partner, and later alerts link to it.
- Incidents are **never merged or split automatically**. An analyst can link or unlink an
  alert manually, and can escalate a standalone alert to a new incident. Manual links are
  audited and marked `link_source=analyst`.
- Correlation runs inside the serialized detection transaction, so two concurrent batches
  cannot create two incidents for the same activity.

Every link stores **why** it happened: `incident_alerts(link_strength, shared_entities,
reason)`. For example: *"Linked: shares host web-01 and user deploy with ALRT-0142; 38 s after
the incident's last activity."* The UI shows this next to each alert.

## Incident record

`id, title, summary, status, severity (max of alerts), risk_score, risk_band,
risk_breakdown, assigned_to, created_at, updated_at, first_activity_at, last_activity_at,
affected hosts / users / source entities (derived from linked alerts, stored denormalized for
listing), tactics and techniques (union), resolution, resolved_at, closed_at,
related_incident_id, simulated`.

The title is generated from the dominant entities and stages, for example *"Authentication
compromise chain on web-01 (deploy from 203.0.113.45)"*. Analysts can rename it (audited).

## State machine

```
OPEN → TRIAGED → INVESTIGATING → CONTAINED → RESOLVED → CLOSED
  └───────┴───────────┴─────→ RESOLVED        (e.g. benign after triage)
RESOLVED → INVESTIGATING                       (reopen, reason required)
```

- `RESOLVED` requires a resolution summary and a disposition.
- `CLOSED` is final: no status changes, but notes can still be read.
- ANALYST and ADMIN can move incidents. VIEWER cannot (tested).
- Every transition, assignment, note, evidence pin, manual link and rename is written to
  `incident_activity` (shown in the workspace) **and** to the audit log.

## Timeline

Built on request from stored data, never hardcoded:
1. Evidence events of all linked alerts (timestamp, category/action/outcome, entities,
   message, link to the raw record), de-duplicated.
2. Alert milestones (created, extended).
3. Incident activity (status changes, assignment, notes, pinned evidence).

Sorted by time. Detection-time and analyst-time entries are visually distinct, and each entry
links to its source row. Large incidents page through the timeline (keyset on
`(timestamp, id)`).

## Evidence and notes

- **Pinned evidence**: an analyst pins an event or alert to the incident with a tag
  (`initial_access`, `privilege`, `persistence`, `benign`, `needs_review`) and a comment.
  Pins are append-only; "unpin" is itself an activity entry.
- **Notes**: append-only. They cannot be edited or deleted. A correction is a new note. This
  preserves the investigation history.

## Response recommendations

Taken from the `response` guidance of each linked rule, de-duplicated and grouped by stage.
Values are filled from incident facts (host, user, source). These are **recommendations only**:
SentinelX never blocks, disables or changes anything on monitored systems.

## Testing

Pure tests for the strength function (every row of the table) and for window edges (exactly
2 h vs 2 h + 1 s). Integration tests cover:
- the full chain → exactly one incident with four alerts in timeline order
- two unrelated brute forces → no incident from medium alerts alone
- the same source against two hosts → one incident (MEDIUM, external)
- a resolved incident followed by new activity → a new incident with a back-link
- concurrent batches → one incident.
