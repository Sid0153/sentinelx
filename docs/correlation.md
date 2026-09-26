# Correlation and incidents

> Status: **IMPLEMENTED and TESTED (Phase 8)**. See
> [ADR-0009](decisions/0009-entity-based-incident-correlation.md) and
> [ADR-0012](decisions/0012-correlation-by-finding.md). Code: `app/correlation/` (scoring is
> pure; `service.py` runs in the detection transaction) and `app/incidents/` (records,
> workflow, analyst actions, queries).

Correlation groups **alerts** (not raw events) into **incidents**. Rules answer "did this
pattern happen?". Correlation answers "are these alerts parts of the same story?".

## Inputs

Each alert exposes, from its grouped values and **all** its linked evidence (not the 10 most
frequent values an alert keeps for display: a spray from many sources was once split into
seven incidents because each alert showed only 10 of its 100 sources; tested since):
- hosts, source addresses (scope: internal or external, from `INTERNAL_NETWORKS`), and users
  (the actor and the account acted upon, e.g. the account that was created);
- its time span (`first_event_at`, `last_event_at`);
- its ATT&CK techniques (and tactics).

An incident is the union of its alerts (stored on the incident, with GIN indexes on hosts,
users and sources to find candidates quickly).

## Link strength (`app/correlation/scoring.py`)

| Shared with the incident | Strength | Links? |
|---|---|---|
| host **and** user (actor or target) | STRONG | yes |
| host **and** source address | STRONG | yes |
| an external source address (any hosts) | MEDIUM | yes. One outside source acting against several hosts is one campaign |
| host where the incident already shows **access**, then a **new kind of finding** (a technique the incident does not have) starting at or after that access, within the **sequence window** | MEDIUM | yes. The brief's "event sequence": what follows a foothold on a host. How the chain reaches its account-creation stage, whose records do not name the actor (ADR-0012) |
| host only (same kind of finding), user only, or an internal source only | WEAK | no. Shared NAT and jump hosts make internal addresses poor evidence |
| nothing | NONE | no |

**Access** on a host: an alert on that host mapped to Initial Access or Privilege Escalation
whose evidence includes a successful event (a logon that worked, a sudo that ran). A refused
sudo maps to a privilege-escalation technique but is not a foothold (tested). Sharing only a
host, without that foothold, or before it, stays WEAK: two unrelated findings on a busy host
are not merged.

**Time:** the alert and the incident must be within the **correlation window** of each other
(default 2 h, admin-configurable 15 min – 24 h), inclusive: exactly 2 h links, 2 h 1 s does
not (tested at both edges). The sequence window defaults to 30 min (5 – 240 min, never longer
than the correlation window).

Every link stores its strength, the shared entities and a sentence, e.g. *"Same host and user
(host web-01, user deploy and source 203.0.113.45), 3 s apart."* or *"On web-01, after the
access the incident shows there (since 2026-09-26 10:00:00 UTC): a new kind of finding
(T1098.007, T1136.001), 93 s apart."* The workspace shows it next to each alert.

## Algorithm (`app/correlation/service.py`)

Runs after alerting, **inside the detection run's transaction** and under its advisory lock:
two concurrent batches cannot create two incidents for the same activity, and a run, its
alerts and its incident changes are stored together or not at all.

```
for each alert created or extended in this run, oldest activity first:
    if it already belongs to an incident: refresh that incident; continue
    candidates = open incidents (OPEN/TRIAGED/INVESTIGATING/CONTAINED) sharing a host, user or
                 source within the window, locked FOR UPDATE
    best = STRONG or MEDIUM link, not previously unlinked by an analyst;
           ties → stronger, then most recent activity, then lowest number
    if best: link(alert, best, reason); continue
    partners = open alerts in no incident that link to this alert STRONG or MEDIUM
    if alert is high or critical: open an incident ("High-severity alert: …")
    elif partners:                 open an incident ("Multi-stage activity: … with N related alert(s)")
    else:                          leave it a standalone alert
    link the opening alert (strength ORIGIN) and every partner (with its own reason);
    point the new incident to a resolved/closed one for the same activity (30 days back), if any
    (an incident is refreshed right after every link, so the next alert sees it as it is now)
for every incident changed in this run:
    refresh it: entities, span, access, severity (highest alert), risk, title, summary
    sweep: open alerts in no incident that now link to it STRONG or MEDIUM join it (it may have
           grown: a new host, user or foothold); repeat until nothing more joins
```

A **manual** detection run (`POST /api/detections/run`, `cli run-detection`) also correlates
every open alert in no incident whose activity overlaps its range: the backfill for alerts
from before correlation existed, or that were missed. Repeating it changes nothing (tested).

Consequences (all tested):
- A lone low or medium alert does **not** create an incident.
- The brief's chain (AUTH-001 + AUTH-002 + PRIV-001 + ACCT-001, demo scenario
  `multi_stage_attack`) is **one** incident, in one batch or in four.
- Two brute forces from different sources on different hosts: no incident. The same outside
  source against two hosts: one incident (MEDIUM).
- A `RESOLVED`/`CLOSED` incident is never extended; new activity opens a new incident with
  `related_incident_id` pointing back.
- Incidents are **never merged or split automatically**. Analysts link alerts by hand
  (`MANUAL`, with a reason), unlink them (with a reason; the engine then never links that
  alert back to that incident), and escalate a standalone alert into a new incident.
- The engine locks candidate incidents before extending them. An analyst resolving an incident
  at the same moment is either seen (the incident is skipped, and a new one opens) or waits
  (tested with real concurrent transactions).

- A standalone alert that only belongs with an incident after the incident grew joins in the
  sweep, without new activity of its own (tested).

Not built: transitive clustering (future work, ADR-0009).

## Incident record (`incidents`)

The brief's fields (§11) and where they are: `incident_id` = `id` (plus `number`, shown as
INC-n), `title` (generated until an analyst renames it), `description` = `summary` (generated
from the alerts: rules, tactics, entities, time span) plus `created_reason`, `severity` (highest
alert), `risk` = `risk_score` / `risk_band` / `risk_breakdown` ([risk-model.md](risk-model.md)),
`status`, `created_at`, `updated_at`, `assigned_to`, `affected_hosts` = `hosts`,
`affected_users` = `usernames`, `source_entities` = `source_ips`, `related_alerts` =
`incident_alerts` (with the reason for each), `evidence` = the alerts' evidence plus pinned
evidence, `timeline` (built on request), `mitre_techniques` (union of the alerts', with the
rules mapping to each), `analyst_notes`, `response_actions` (the alerts' response steps,
grouped by finding, de-duplicated), `resolution` + `disposition` (confirmed_malicious,
benign_expected, false_positive). Also `first/last_activity_at`, `tactics`, `alert_count`,
`related_incident_id`, `simulated`.

## State machine (`app/incidents/workflow.py`)

| From | Allowed to |
|---|---|
| OPEN | TRIAGED, RESOLVED |
| TRIAGED | INVESTIGATING, RESOLVED |
| INVESTIGATING | CONTAINED, RESOLVED |
| CONTAINED | INVESTIGATING (containment did not hold), RESOLVED |
| RESOLVED | CLOSED, INVESTIGATING (reopen: reason required) |
| CLOSED | nothing: final |

- `RESOLVED` requires a disposition and a resolution summary (the database checks that
  resolved and closed incidents have both, and open ones neither).
- `CLOSED` is final: no status change, rename, note, pin or assignment; everything can still be
  read.
- ANALYST and ADMIN act; VIEWER reads (403 on every action, tested). A change the workflow does
  not allow is 409, missing input 400. Every transition, assignment, note, evidence change,
  manual link or unlink, rename and escalation is written to `incident_activity` (the
  workspace) **and** the audit log, in the same transaction.
- Incidents are assigned to active analysts or admins only.

## Timeline (`GET /api/incidents/{id}/timeline`)

Built on request from stored rows, never hardcoded or copied:
1. the evidence events of all linked alerts, each once, with the rules citing it and its raw
   record (up to 1,024 characters);
2. the linked alerts (at their creation time);
3. the incident's activity (in insertion order: several entries can share a timestamp).

One SQL query merges the three, ordered by (time, kind, key), and pages with a keyset cursor
(tested: paging returns exactly the same entries in the same order). Detection-time and
analyst-time entries are shown differently in the workspace.

## Evidence and notes

- **Pinned evidence**: an analyst pins an event or an alert with a tag (`initial_access`,
  `privilege`, `persistence`, `benign`, `needs_review`) and a comment. Pins are append-only;
  "unpin" is a new row. The current pins are the latest action per target.
- **Notes**: append-only (1 – 10,000 characters). They cannot be edited or deleted; a
  correction is a new note. The audit log records the note's ID, not its text.
- `incident_notes`, `incident_evidence` and `incident_activity` reject UPDATE, DELETE and
  TRUNCATE (database triggers, tested).

## Response recommendations

The `response` guidance of each linked alert, grouped by finding and de-duplicated, with
values already filled from the evidence (host, user, source). **Recommendations only**:
SentinelX never blocks, disables or changes anything on monitored systems.

## Testing

- Pure (`tests/unit/test_correlation_rules.py`): every row of the strength table, both window
  edges, the target account counting as a user, the reason sentences, all 36 status pairs of
  the workflow, and incident risk.
- Integration (`tests/integration/test_incidents.py`): the chain in one batch and in four, the
  timeline order and keyset paging, lone medium alerts, unrelated brute forces, one outside
  source against two hosts, resolved incidents not extended (with the back-link), unlinked
  alerts not re-linked, the window edge on stored alerts, a narrowed window, append-only
  records, closed incidents refusing changes, the sweep, the manual-run backfill, a refused sudo
  not counting as a foothold, a campaign judged on all its sources. Mutation-checked: removing partners, the unlink guard, the
  new-finding link, the sweep, the backfill, the successful-event condition or the evidence-based entities makes a test fail.
- Concurrency (`tests/integration/test_incident_concurrency.py`, own database): a run blocked
  on an incident the analyst resolves opens a new incident instead; two batches of one chain
  at once make one incident. Removing the incident row lock makes a test fail.
- API and UI: `tests/api/test_incidents.py`, `frontend/tests/incidents.test.tsx`.
