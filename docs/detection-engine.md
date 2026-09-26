# Detection engine and alerts

> Status: engine, rule storage and the 9-rule library **IMPLEMENTED and TESTED (Phase 6)**.
> Each run is stored (`detection_runs`) and its detections become **alerts** (dedup, evidence,
> priority, workflow: **IMPLEMENTED and TESTED, Phase 7**, [ADR-0011](decisions/0011-alert-deduplication.md)).
> See [ADR-004](decisions/0004-declarative-rule-engine.md).

## Principles

- Rules are **data** (YAML shipped in `backend/app/detection/library/`), validated by a Pydantic
  schema. A small set of **evaluator kinds** (Python) interprets them. There are no per-rule
  `if/else` blocks.
- Evaluators are pure functions: `evaluate(rule, events, history=None) -> list[Match]`
  (`app/detection/evaluate.py`), turned into a `Detection` with its explanation by
  `explain.build`. Each can be tested with a list of hand-built events and no database.
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

`{field, op, value}` predicates combined with `all` / `any` / `not`, at most 4 levels deep
(a predicate counts as one level). Code: `app/detection/conditions.py`.

- **Fields**: an allowlist of normalized columns plus `attributes.<key>`. Unknown fields fail
  validation when the rule loads. Derived fields (`target_account`, `destination`) can be used
  for grouping and distinct counting, not in conditions.
- **Operators**: `eq`, `ne`, `in`, `not_in`, `contains`, `startswith`, `endswith` (text;
  case-insensitive for **ASCII letters only**, see below), `cidr` (IP in network), `exists`, `gt`/`gte`/`lt`/`lte`
  (numbers), and `matches` (regex).
- `matches` is allowed **only in rules shipped in the repository**, and it is not a tunable
  field. Patterns are compiled at load time, reviewed for nested quantifiers, and tested against
  long adversarial inputs. Inputs are capped at 8 KB. If admins are ever allowed to write
  patterns, the engine must switch to a linear-time engine (`google-re2`) first. This is
  recorded as a condition in ADR-004.
- The same language evaluates in Python (**authoritative**) and compiles to a SQL
  **prefilter** that only narrows the rows the engine reads. The prefilter may select more rows
  than Python accepts, never fewer. An operator SQL cannot express exactly becomes `TRUE`
  there: `matches`, equality on numbers and booleans, and text operators on attribute values
  that are not JSON strings. `not` is only compiled when everything under it is exact
  (the negation of a superset is not a superset).
- **Why ASCII-only case folding.** Python's `casefold()` and PostgreSQL's `lower()` disagree
  (`lower('İ')` is `i` in the en_US locale, and `ß` becomes `ss` only in Python). They also
  turn look-alikes into ASCII: `ſvc` casefolds to `svc`, and the Kelvin sign to `k`, so a
  crafted username could have matched an exclusion (allowlist) entry and hidden its activity.
  `fold()` lowers A–Z only, and SQL does the same with `translate()`, whatever the locale.
  Exclusions use the same `fold()`.
- **Indexes.** `translate(column)` would hide a column from its index. Columns stored without
  ASCII capitals (`LOWERCASE_COLUMNS`: controlled vocabularies, and names the normalizer
  lowercases) are compared directly, which is equally exact, so the `(event_category,
  event_action, timestamp)` index fits the prefilter. A test checks that the normalizer
  never stores a capital in those columns, and another that the prefilter's SQL compares
  them directly.
- **NULL.** In SQL, `username = 'root'` is NULL (not FALSE) when the username is missing, and
  `NOT NULL` is NULL, which would drop the row. Python says the negation is true. The compiled
  `not` is `NOT COALESCE(inner, FALSE)`.
- `tests/integration/test_condition_sql.py` stores events with awkward values (mixed case,
  non-ASCII letters, LIKE wildcards, empty and missing values, JSON numbers such as `1e-07`,
  booleans, IPv6) and checks over 500 conditions: SQL ⊇ Python for every one, and SQL = Python
  wherever the condition is marked exact. Mutation checks confirmed that removing the COALESCE,
  going back to `casefold()`, or dropping the JSON-string guard each makes it fail.

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

### How the engine runs (`app/detection/engine.py`)

The engine is **stateless** ([ADR-0008](decisions/0008-synchronous-bounded-pipeline.md)): nothing is kept in memory between runs,
so a restart loses nothing and late or out-of-order events are seen.

1. After an ingest batch commits, `run_for_batch` runs every enabled rule over the batch's
   event-time span `[t_min, t_max]`. `POST /api/detections/run` (ADMIN, at most 31 days, audited)
   and `cli run-detection` run the same code over a chosen range.
2. Runs are serialized with a transaction-level PostgreSQL advisory lock. Ingestion itself
   stays concurrent.
3. Per rule: load the candidate events in `[t_min − window, t_max + window]` (window =
   `time_window` or `max_gap`), filtered by the SQL prefilter and ordered by `(timestamp, id)`.
   A `new_value` rule also loads the history before `t_min − window` over `lookback`.
4. **Candidate cap.** If a rule has more than 20,000 candidates it is **not** evaluated on a
   truncated set, which could hide or invent a detection. It is reported as
   `too_many_candidates`.
5. **Error isolation.** A rule that raises is recorded as `evaluation_error` (fixed code, no
   message from the data) and the other rules still run. The run is then
   `COMPLETED_WITH_ERRORS` and the batch `PROCESSED_WITH_ERRORS`.
6. **Batch scoping.** A batch run keeps only detections that contain at least one event from
   that batch. Re-reading overlapping windows therefore does not report the same activity with
   every later batch, while activity split across batches is still found (the failures in one
   batch, the success in the next: AUTH-002 fires with the second batch, evidence from both).
7. The run (per-rule outcome, every detection with explanation and evidence IDs), rule
   statistics (`match_count`, `error_count`, `last_run_at`, `last_match_at`) and the batch
   status and `detection_count` are written in **one transaction**.
8. If the whole run fails after the records were stored, the records stay (already committed)
   and the batch is marked `DETECTION_FAILED`. Detection can be re-run over its range; results
   are deterministic, so a re-run gives the same detections.

Not implemented (designed earlier): skipping rules whose match cannot touch the batch's event
categories without a query, and one grouped history query per batch. Each rule does its own
bounded query today; measured on the demo data, a run of all 9 rules takes about 70 ms.

## Library (9 rules)

The brief's 8 initial rules, plus AUTH-005, added in Phase 6 to close the distributed
brute-force gap AUTH-001 leaves (see the weaknesses below). They cover a small, realistic
slice of Linux/Windows authentication and privilege activity. They are **not** enterprise
detection coverage. The ATT&CK IDs below were checked on
attack.mitre.org on 2026-09-25 (ATT&CK v19.2); see [mitre.md](mitre.md).

| ID | Name | Kind | Key logic (defaults, tunable) | Sev / Conf | ATT&CK |
|---|---|---|---|---|---|
| AUTH-001 | Repeated SSH authentication failures | threshold | ≥ 5 sshd logon failures, same source+host+user, 5 min | medium / medium | T1110.001 |
| AUTH-002 | Successful authentication after repeated failures | sequence | ≥ 3 failures then a success, same source+user+host, ≤ 10 min, success ≤ 5 min after last failure. Any auth source (SSH, Windows 4625/4624, app) | high / medium | T1110, T1078 |
| AUTH-003 | One source attempting many accounts | distinct | ≥ 5 distinct usernames with failed logons from one source, 10 min (across hosts) | medium / medium | T1110.003 |
| PRIV-001 | Suspicious privilege escalation indicator | single | Linux: `sudo` that starts an interactive root shell (`sudo su`, `sudo -i`, `sudo -s`, `sudo bash/sh`), or `user NOT in sudoers` | medium / low (root shell) · medium / medium (not in sudoers) | T1548.003 |
| ACCT-001 | Privileged account created | sequence | `user_created` then `group_member_added` to a privileged group (`sudo`, `wheel`, `admin`, `Administrators`) for the same target user + host, ≤ 60 min. Linux and Windows (4720 → 4732) | high / high | T1136.001, T1098.007 |
| AUTH-005 | One account attacked from many sources | distinct | ≥ 5 distinct source IPs with failed logons for one existing account (invalid names excluded), 10 min (across hosts) | medium / medium | T1110.001 |
| AUTH-004 | Logon from an unusual source | new_value | Successful logon whose source /24 (IPv4) or /64 (IPv6) was not seen for that user in 14 days; user has ≥ 5 prior successful logons | low / low | T1078 |
| PROC-001 | Suspicious command line | single | Named indicators, each with its own mapping: encoded PowerShell, either `-EncodedCommand` in any accepted spelling (prefixes, `/`, en/em dash, `:`) or, whatever the program is called, a UTF-16LE base64 blob (T1059.001, T1027.010); downloaded content run by a shell: `curl\|wget … \| sh`, `bash <(curl …)`, `sh -c "$(curl …)"`, or download then `sh file` in the same command (T1059.004, T1105); `certutil -urlcache` download (T1105); `/dev/tcp/` interactive-shell pattern (T1059.004) | high / medium | per indicator |
| NET-001 | Connections to many ports/hosts | distinct | One internal source → ≥ 20 distinct `destination_ip:port` pairs in 60 s (network events) | medium / medium | T1046 |

Known weaknesses, documented per rule in the YAML (and in the UI from Phase 9). Some are
false positives (noise), some are misses (gaps):
- **Threshold "just under" zone.** AUTH-001 fires at 5 failures per source+host+user in
  5 min, so a slower attack stays below it. AUTH-001 counts SSH only; Windows failures feed
  AUTH-002/003/005.
- **Distributed attacks** (few attempts from each of many sources) evade per-source rules.
  AUTH-005 covers one account attacked from many sources. On internet-facing SSH it fires for
  `root` routinely (background scanning); that is a finding about the host's configuration,
  not an incident each time.
- **AUTH-004** is noisy on VPN or DHCP address changes (an IP is not a location), and misses
  an attacker coming from the same NAT or cloud range as the user, or an account with fewer
  than 5 earlier logons (not judged, to avoid noise on new accounts).
- **PROC-001 is pattern matching.** Since Phase 6 it also catches a renamed PowerShell (by the
  shape of the encoded payload), other flag spellings, and download-then-run in one command
  line. It still misses obfuscation it has no pattern for, other download tools, and a
  download and its execution in **two separate commands** (linking those is correlation's
  job, Phase 8).
- **Data sources limit every rule.** Linux command lines come from sudo logging only
  (commands run without sudo need auditd/execve logging, not ingested); Windows PROC-001
  needs event 4688 with command-line auditing enabled.
- NET-001 thresholds depend on the environment (vulnerability scanners and monitoring
  systems must be allowlisted), and a slow scan stays under them.

## Detection → alert (Phase 7)

Code: `app/alerts/` (`dedup.py` and `workflow.py` pure; `service.py` the only writer of
alerts; `queries.py`). Alerts are created **in the detection run's transaction**, under its
advisory lock, so a run and its alerts are stored together or not at all. If alerting fails,
the run fails and the batch is `DETECTION_FAILED` (the records stay; tested).

### Deduplication ([ADR-0011](decisions/0011-alert-deduplication.md))

`dedup_key = sha256(rule ID ‖ indicator ‖ grouped values as JSON)`. The indicator separates
findings of one rule that are different activity (PRIV-001's root shell and refused sudo).

1. A detection whose evidence is **already linked to an alert with the same key** (open or
   closed) changes nothing. Re-running detection is a no-op, including after an analyst closed
   the alert (a closed alert is never re-created by a re-run).
2. With new evidence, the **open** alert for the key (`NEW`, `TRIAGED`, `IN_PROGRESS`) is
   extended: the new evidence is linked, times and counts follow the linked evidence, the
   explanation, facts and guidance follow the latest detection, the detection is added to the
   alert's `history`, and the priority is recomputed.
3. With no open alert, a new alert is created. It points to the latest closed alert for the key
   (`previous_alert_id`), so recurrence is visible. The engine **never reopens** a closed
   alert: that is the analyst's decision.
4. "One open alert per key" is a database guarantee: a partial unique index
   `alerts(dedup_key) WHERE status IN ('NEW','TRIAGED','IN_PROGRESS')` (tested).

The Phase 1 design's per-rule `dedup_window` was dropped: with one open alert per key it had
no remaining job (ADR-0011).

Evidence: a detection lists its first 50 and last 50 events; an alert links up to 1,000
distinct events. `event_count` is the number linked; `evidence_truncated` says when more
matched than are linked (the count is then a lower bound, and the UI says so).

### Alert record (`alerts`, `alert_events`)

The brief's fields (§8) and where they are: `alert_id` = `id`, `rule_id`, `title` (rule name,
indicator and grouped values), `description` (what the rule looks for), `severity`,
`confidence`, `status`, `created_at`, `updated_at`, `source_ip`, `destination_ip`, `host`,
`username`, `event_count`, evidence = `alert_events` (and `GET /api/alerts/{id}/events`, with
raw records), `detection_reason` = `explanation` + `facts`, `mitre_techniques` = `mitre`
(snapshot: ID, name, tactics, reason, ATT&CK version), `recommended_actions` = `response`
(plus `investigation`). Also: priority score, band, breakdown and model version; the asset
and identity from the inventory; first/last event time; `peak_count`; `detection_count` and
`history` (each merged detection); `previous_alert_id`; `simulated`; triage and resolution
times and actors; `disposition`; `status_note`.

### Workflow (`app/alerts/workflow.py`)

| From | Allowed to |
|---|---|
| NEW | TRIAGED, IN_PROGRESS, FALSE_POSITIVE |
| TRIAGED | IN_PROGRESS, RESOLVED, FALSE_POSITIVE |
| IN_PROGRESS | TRIAGED (put back), RESOLVED, FALSE_POSITIVE |
| RESOLVED, FALSE_POSITIVE | TRIAGED (reopen) |

- RESOLVED needs a disposition: `confirmed_malicious` or `benign_expected` (brief §45:
  confirmed / resolved). FALSE_POSITIVE and reopening need a reason. NEW cannot go straight
  to RESOLVED: closing an alert as handled means someone looked at it first.
- A change the workflow does not allow is `409`; a missing disposition or reason is `400`.
  Reopening is refused (`409`, naming the newer alert) when newer activity already has its
  own open alert.
- Only ANALYST or ADMIN can change status (VIEWER: `403`). Every change is audited
  (`ALERT_STATUS_CHANGED`: from, to, disposition, reason, actor, client IP) in the same
  transaction, and the alert keeps `triaged_at` (first time), `resolved_at`, `resolved_by`,
  `status_changed_at/by` and the latest note. The alert page's status history is read from
  the audit log, the one record of who did what.
- The alert row is locked (`SELECT … FOR UPDATE`) during a change, and the engine locks an open
  alert before extending it, so an analyst closing an alert and a run extending it cannot
  interleave; two runs are serialized by the detection advisory lock. Tested with real
  concurrent transactions (`tests/integration/test_alert_concurrency.py`, in a throwaway
  database): a run blocked on an alert the analyst closes opens a new alert instead of
  extending the closed one; an analyst blocked on a run's extension keeps it; two batches of
  the same activity at once make one alert. Removing either lock makes a test fail.
- These fields feed per-rule false-positive counts and time-to-resolve (shown in Phase 11).
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
- The library is loaded and validated when the app starts (`create_app`: a broken library
  stops startup with a message naming the file), and seeded into the database by
  `cli seed-rules`, which the container runs after migrations. A changed YAML creates a new
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
- Events out of order (shuffled) → same result as in order.
- Split across two batches → the sequence is still found, with evidence from both batches.
- Re-running detection over the same range → the same detections (rule, group, evidence).
  Turning repeats into one alert is Phase 7 deduplication.
- A benign scenario → zero detections.
- Every demo scenario triggers exactly its expected rules: in unit tests (parsed in memory),
  in integration tests (ingested into PostgreSQL), and live on the Compose stack.

A **library test** fails if a rule is added that no demo scenario triggers (AUTH-004 is the
documented exception: it needs 14 days of history and has its own database test). The benign
scenario is the shared negative fixture, and each rule has its own negative unit cases.
