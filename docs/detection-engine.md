# Detection engine and alerts

> Status: **DESIGN (Phase 1)**. Engine and library: Phase 6. Alerts, dedup, workflow: Phase 7.
> See [ADR-004](decisions/0004-declarative-rule-engine.md).

## Principles

- Rules are **data** (YAML shipped in `backend/app/detection/library/`), validated by a Pydantic
  schema. A small set of **evaluator kinds** (Python) interprets them. There are no per-rule
  `if/else` blocks.
- Evaluators are pure functions: `evaluate(rule, events, now) -> list[Detection]`. Each can be
  tested with a list of hand-built events and no database.
- Rule configuration can **never execute code**. There is no `eval`, templating engine or
  user-supplied regex (see "Safe condition language").
- Every detection carries its evidence (event IDs and the computed facts). The explanation is
  generated from those facts, never from fixed prose.

## Rule definition

```yaml
id: AUTH-001
name: Repeated SSH authentication failures
description: Many failed SSH logons for one account on one host from one source.
category: authentication
kind: threshold                  # single | threshold | distinct | sequence | new_value
severity: medium                 # low | medium | high | critical
confidence: medium               # low | medium | high
enabled: true
match:                           # safe condition language
  all:
    - {field: event_category, op: eq, value: authentication}
    - {field: event_action,   op: eq, value: logon}
    - {field: event_outcome,  op: eq, value: failure}
    - {field: service,        op: eq, value: sshd}
group_by: [source_ip, host, username]
threshold: 5
time_window: 5m
dedup_window: 1h
tunable:                         # the only fields an admin may change, with bounds
  threshold:   {min: 2, max: 1000}
  time_window: {min: 1m, max: 24h}
  severity: true
  confidence: true
  enabled: true
  exclusions: true               # allowlist of source CIDRs / usernames / hosts
mitre:
  - technique: T1110.001
    reason: >-
      Repeated password attempts against a single account from one source is the pattern
      ATT&CK describes as Password Guessing.
explanation: >-
  $count failed SSH logons for "$username" on $host from $source_ip ($source_ip_scope)
  within $span; this rule alerts at $threshold within $time_window.
investigation:
  - Check whether $source_ip has any successful logon on $host (pivot to hunt).
  - Check whether "$username" is a real account and who owns it.
  - Look for the same source against other hosts in the same period.
response:
  - If the source is external and unexpected, follow your blocking procedure at the perimeter.
  - Confirm the account uses key-based authentication or a strong password policy.
```

`explanation` uses `string.Template` (`$name` substitution only, no attribute or index access),
and values come only from the computed fact dictionary. Log-derived values are rendered as text
and never as HTML.

## Safe condition language

`{field, op, value}` predicates combined with `all` / `any` / `not`, nesting depth ≤ 3.

- **Fields**: an allowlist of normalized columns plus `attributes.<key>` (string compare only).
  Unknown fields fail validation when the rule loads.
- **Operators**: `eq`, `ne`, `in`, `not_in`, `contains`, `startswith`, `endswith` (all
  case-insensitive for text), `cidr` (IP in network), `exists`, `gt`/`gte`/`lt`/`lte`
  (numbers), and `matches` (regex).
- `matches` is allowed **only in rules shipped in the repository**, and it is not a tunable
  field. Patterns are compiled at load time, reviewed for nested quantifiers, and tested against
  long adversarial inputs. Inputs are capped at 8 KB. If admins are ever allowed to write
  patterns, the engine must switch to a linear-time engine (`google-re2`) first. This is
  recorded as a condition in ADR-004.
- The same language compiles to SQL (used for candidate prefiltering and for hunting) and
  evaluates in Python (used by evaluators). Tests check that the two agree on the same fixture
  events.

## Evaluator kinds

All windows use **event time**. Boundaries are inclusive: events exactly `time_window` apart
count as inside. Ordering is `(timestamp, id)` so ties are deterministic.

| Kind | Semantics | Used by |
|---|---|---|
| `single` | Every matching event is a detection | PRIV-001, PROC-001 |
| `threshold` | ≥ `threshold` matching events for the same `group_by` key within any `time_window`-long interval (sliding window, two pointers) | AUTH-001 |
| `distinct` | ≥ `threshold` **distinct values** of `distinct_field` for the same key within the window | AUTH-003, NET-001 |
| `sequence` | Ordered `steps` (each with its own `match` and `min_count`) for the same key, all within `time_window`, each step at or after the previous step's last counted event; optional `max_gap` between steps | AUTH-002, ACCT-001 |
| `new_value` | A matching event whose derived value (e.g. `source_ip` → /24) was not seen for the same key in the prior `lookback`, and the key has ≥ `min_history` prior events | AUTH-004 |

Temporal detection ("failures then success") is a two-step `sequence`. A **cross-rule** chain
(failures → success → privilege activity → new admin account) is not a single rule. It is
built by the correlation engine from separate alerts; see [correlation.md](correlation.md).
This keeps each rule small and independently testable, and it lets the incident show which
stage fired.

### One detection per burst

For `threshold`/`distinct`, when a key first reaches the threshold the evaluator emits one
detection. Events that keep arriving within `time_window` of the previous one extend the same
burst and become evidence, instead of producing a new detection on every event.

### How the engine picks events

For a batch spanning `[t_min, t_max]`, each rule loads candidate events in
`[t_min − time_window, t_max + time_window]` whose normalized fields match the rule's match
condition compiled to SQL, ordered by key and time. This is a bounded, indexed query per rule.
Rules whose match cannot touch the batch's categories are skipped without a query. `new_value`
also loads each key's history set for the lookback with one grouped query per batch, not one
query per event.

## Initial library (8 rules)

These cover a small, realistic slice of Linux/Windows authentication and privilege activity.
They are **not** enterprise detection coverage. The ATT&CK IDs below were checked on
attack.mitre.org on 2026-09-25 (ATT&CK v19.2); see [mitre.md](mitre.md).

| ID | Name | Kind | Key logic (defaults, tunable) | Sev / Conf | ATT&CK |
|---|---|---|---|---|---|
| AUTH-001 | Repeated SSH authentication failures | threshold | ≥ 5 sshd logon failures, same source+host+user, 5 min | medium / medium | T1110.001 |
| AUTH-002 | Successful authentication after repeated failures | sequence | ≥ 3 failures then a success, same source+user+host, ≤ 10 min, success ≤ 5 min after last failure. Any auth source (SSH, Windows 4625/4624, app) | high / medium | T1110, T1078 |
| AUTH-003 | One source attempting many accounts | distinct | ≥ 5 distinct usernames with failed logons from one source, 10 min (across hosts) | medium / medium | T1110.003 |
| PRIV-001 | Suspicious privilege escalation indicator | single | Linux: `sudo` that starts an interactive root shell (`sudo su`, `sudo -i`, `sudo -s`, `sudo bash/sh`), or `user NOT in sudoers` | medium / low (root shell) · medium / medium (not in sudoers) | T1548.003 |
| ACCT-001 | Privileged account created | sequence | `user_created` then `group_member_added` to a privileged group (`sudo`, `wheel`, `admin`, `Administrators`) for the same target user + host, ≤ 60 min. Linux and Windows (4720 → 4732) | high / high | T1136.001, T1098.007 |
| AUTH-004 | Logon from an unusual source | new_value | Successful logon whose source /24 (IPv4) or /64 (IPv6) was not seen for that user in 14 days; user has ≥ 5 prior successful logons | low / low | T1078 |
| PROC-001 | Suspicious command line | single | Named indicators, each with its own mapping: PowerShell `-EncodedCommand`/`-enc` (T1059.001, T1027.010); download-and-pipe-to-shell `curl\|wget … \| sh` (T1059.004, T1105); `certutil -urlcache` download (T1105); `/dev/tcp/` interactive-shell pattern (T1059.004) | high / medium | per indicator |
| NET-001 | Connections to many ports/hosts | distinct | One internal source → ≥ 20 distinct `destination_ip:port` pairs in 60 s (network events) | medium / medium | T1046 |

Known weaknesses, documented per rule in the YAML and in the UI:
- AUTH-001 counts SSH only; Windows failures feed AUTH-002/003.
- AUTH-004 flags VPN or DHCP address changes. An IP is not a location.
- PROC-001 is pattern matching and easy to evade with obfuscation.
- NET-001 thresholds depend on the environment (vulnerability scanners and monitoring
  systems must be allowlisted).

## Detection → alert (Phase 7)

### Deduplication

`dedup_key = sha256(rule_id ‖ group_by values)`.

1. If an **active** alert (`NEW`, `TRIAGED`, `IN_PROGRESS`) with that key exists and its
   `last_event_at` is within `dedup_window` of the new detection's first event, the detection
   **extends** it. New evidence is linked, `event_count` and `last_event_at` are updated,
   `occurrence_count += 1`, and the priority is recomputed.
2. Otherwise a new alert is created. If a closed alert (`RESOLVED`/`FALSE_POSITIVE`) exists
   for the key, the new alert shows it as `previous_alert_id`, so analysts see recurrence.
   Closed alerts are **never reopened** by the engine, which respects the analyst's decision.
3. Evidence links are unique on `(alert_id, event_id)`, which makes re-running detection a
   no-op.

Evidence stored per alert is capped at the first 50 plus the last 50 events. `event_count`
stays exact and the full set is reachable through a hunt on the alert's key and time span.

### Alert record

`id, rule_id, rule_version, title, severity, confidence, status, priority_score,
priority_band, priority_breakdown, dedup_key, group_values, source_ip, destination_ip, host,
username, target_username, asset_id, identity_id, first_event_at, last_event_at, event_count,
occurrence_count, explanation (what / why / facts), investigation_steps, response_steps,
mitre (snapshot of technique ID, name, tactics, reason), created_at, updated_at, triaged_at,
resolved_at, resolved_by, disposition, resolution_note, previous_alert_id, simulated`.

Title, explanation and guidance are **snapshotted** at creation, so later rule edits do not
rewrite history. The alert records the `rule_version` it came from.

### Workflow

```
NEW → TRIAGED → IN_PROGRESS → RESOLVED (disposition: confirmed_malicious | benign_expected)
  └──────┴──────────┴──────→ FALSE_POSITIVE (reason required)
RESOLVED / FALSE_POSITIVE → TRIAGED   (reopen; reason required)
```

- Only ANALYST or ADMIN can change status. Every change is audited with old status → new
  status, and the actor and timestamp are stored.
- These fields feed per-rule false-positive counts and time-to-resolve (Phase 11/12).
- There is no machine-learning feedback: false-positive rates are shown to people who tune
  rules. They do not tune anything automatically.

### Priority

A documented, versioned **SentinelX priority score** (0–100) with bands. See
[risk-model.md](risk-model.md). It is project-specific and not an industry standard.

## Rule management (Phase 6 storage, Phase 12 UI depth)

- The effective rule is the **library definition** (from YAML, which owns the logic) plus
  **admin overrides** (only the fields listed in `tunable`, validated against their bounds).
- Every change creates a `detection_rule_versions` row: full effective definition,
  `version`, `changed_by`, `change_reason` (required), and source (`library` or `admin`).
  Every change is also audited.
- The library is seeded at startup and with `cli seed-rules`. A changed YAML creates a new
  library version and keeps existing overrides. An override that is no longer valid is dropped
  and the drop is audited. The app refuses to start if a YAML file fails validation or
  references an unknown field, evaluator kind or ATT&CK technique.
- **Exclusions** (allowlists) are part of overrides. They are the first form of alert
  suppression; time-boxed suppression rules are a Phase 12 evaluation.

## Testing the engine

Table-driven unit tests per evaluator and per rule (full list in [testing.md](testing.md)).
Examples:
- 4 failures → no alert; 5 → alert.
- 5 failures spread over 5 min 1 s → no alert; exactly 5 min → alert.
- A success 4 min after failures → AUTH-002; the same success 3 h later → no AUTH-002.
- Events out of order in one batch → same result as in order.
- Split across two batches → same result as one batch.
- Re-running a batch → no new alert, no duplicate evidence.
- A benign scenario → zero alerts.

Every rule has at least one positive and one negative fixture, and a **library test** fails if
a rule is added without them.
