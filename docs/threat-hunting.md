# Threat hunting

> Status: **DESIGN**. Built in Phase 10. Nothing here is implemented yet, except the
> `pg_trgm` extension, which the Phase 2 baseline migration already creates so text search
> cannot fail on a database that lacks it.

Detection rules answer questions someone thought of in advance. Hunting is the analyst asking
new ones against the stored events: "show every successful logon from this source in the last
24 hours", "which hosts ran `certutil` this week?". A hunt queries the real `events` table,
never a sample or a cache.

## Why a structured query, not a query language

| Option | For | Against |
|---|---|---|
| Raw SQL from the analyst | Unlimited power | Injection by design, can read any table (users, tokens), unbounded cost |
| A text query language (KQL/SPL-like) with our own parser | Familiar to SOC analysts | A parser and its security surface to build and test; overkill for the fields we have |
| **Structured query (JSON)** built by the UI | Every field and operator is allowlisted; compiles to parameterized SQL; same shape as detection-rule conditions | Less expressive; complex questions need templates |

Decision: a **structured query**. A text syntax can be added later as a thin layer that
produces the same structure, so nothing below would change.

## Query model

```json
{
  "time_range": {"from": "2026-09-24T00:00:00Z", "to": "2026-09-25T00:00:00Z"},
  "filters": [
    {"field": "source_ip", "op": "eq", "value": "203.0.113.45"},
    {"field": "event_category", "op": "eq", "value": "authentication"},
    {"field": "event_outcome", "op": "eq", "value": "success"}
  ],
  "sort": {"field": "timestamp", "direction": "desc"},
  "limit": 100,
  "cursor": null
}
```

Rules, all enforced by Pydantic validation before any SQL is built:

- **The time range is required** and spans at most 31 days. Every query then uses the
  time-leading indexes and has bounded cost. This also matches the planned monthly
  partitioning.
- **Fields**: an allowlist of normalized `events` columns, plus `attributes.<key>` (text
  comparison only). Raw records are shown on event detail but cannot be searched. They are
  unnormalized, attacker-controlled text; searching normalized fields keeps queries indexed.
- **Operators**: the same vocabulary as detection conditions (`eq`, `ne`, `in`, `not_in`,
  `contains`, `startswith`, `endswith`, `cidr`, `exists`, `gt`/`gte`/`lt`/`lte`). There is
  **no regex**: user-supplied patterns are a ReDoS risk
  ([ADR-0004](decisions/0004-declarative-rule-engine.md)). Filters combine with AND; OR
  within a field is `in`.
- **Limits**: at most 20 filters, `in` lists of at most 100 values, values of at most 512
  characters, page size of at most 200.
- **Joined context**: optional filters on whether an event is evidence in an alert, and on
  that alert's rule, severity or status. This covers the brief's "severity / detection /
  status" hunting fields without mixing alert data into `events`.

## Execution

- `hunting/compiler.py` turns the validated structure into a SQLAlchemy expression over the
  allowlisted columns. Values are always bound parameters; there is no string-built SQL. The
  same compiler serves detection-rule prefiltering, and tests check that the SQL and Python
  evaluations of a condition agree on shared fixtures.
- **Keyset pagination** on `(timestamp, id)`: an opaque cursor returns the next page in
  constant time, however deep the analyst pages. There is no `OFFSET` scan over millions of
  rows.
- **Statement timeout**: hunts run with `SET LOCAL statement_timeout` (5 s by default). A
  pathological query fails with a clear error instead of starving ingestion.
- **Count**: the exact total is computed only up to a cap (for example "10,000+"), because
  counting a whole month of events on every page is wasted work.
- **Text search** (`contains` on `command_line`, `message`) uses the `pg_trgm` GIN indexes, so
  `ILIKE '%certutil%'` stays indexed. It is substring matching, not relevance ranking (see
  "Limits" below).

## Hunt templates

Some questions are not a flat filter. Templates are **reviewed SQL written in the codebase**,
with typed parameters and the same time-range bound. They are never user-supplied SQL.
Initial set:

| Template | Question | Technique |
|---|---|---|
| `success_after_failures` | Successful logons within N minutes after ≥ K failures for the same user/source | Window functions (`LAG` / counted `RANGE` window) |
| `first_seen_source_for_user` | Logons from a source network not seen for that user in the prior D days | Anti-join against a lookback |
| `rare_process_on_host` | Processes seen on fewer than N hosts in the range | `GROUP BY` + `HAVING` |
| `one_source_many_accounts` | Sources with failed logons against ≥ K distinct accounts | `COUNT(DISTINCT)` |

The first two mirror detection rules AUTH-002 and AUTH-004 on purpose. An analyst can see
what a rule would have caught over a period, with different thresholds, before tuning the
rule.

## Pivoting and saved hunts

- **Pivots**: every entity shown in the UI (IP, user, host, process, rule) has a menu that
  opens a hunt pre-filtered on that value, over the time range of the alert or incident being
  viewed. The whole hunt lives in the URL query string, so it can be bookmarked, shared with
  a colleague, or linked from an incident note.
- **Saved hunts**: `saved_hunts(owner, name, definition, shared)`. The definition is validated
  again on load, so a saved hunt that references a field removed in a later version fails
  cleanly. Private by default. Shared hunts are readable by every signed-in user and editable
  only by their owner (an object-level rule, tested separately from the role matrix).

## Access and audit

- VIEWER and above may hunt: it is read-only. ANALYST and above may save hunts.
- Hunts are **not** written to the audit log one by one. That would flood it, and reading
  is not a security-relevant change. Creating, sharing and deleting saved hunts is audited.
  The request log keeps a trace of every hunt call without the filter values (query strings
  are never logged, see `core/middleware.py`).

## Tests planned (Phase 10)

- The compiler rejects unknown fields and operators, oversized lists and missing time ranges.
- Injection-shaped values (`' OR 1=1 --`, `%`, `_`, backslashes) match literally.
- Keyset pages are stable and gap-free while new events arrive between page loads.
- Each template matches a fixture built with the demo generator, and returns nothing on the
  benign scenario.
- The statement timeout produces a 503-style error with a clear message.

## Limits (honest)

- Substring search, not full-text relevance. No stemming, no phrase ranking, no fuzzy
  matching beyond trigram similarity.
- No cross-source joins beyond the fixed templates. No statistics language, no charts over
  arbitrary aggregations.
- The 31-day window is a deliberate cost bound. Longer investigations run several hunts.
- A search engine (OpenSearch) would lift the first two limits. The trigger for adding one is
  documented in [architecture.md](architecture.md#scale-limits-honest), not planned.
