# Threat hunting

> Status: **IMPLEMENTED and TESTED** (Phase 10). Code: `backend/app/hunting/` (query
> compiler, templates, service), `backend/app/api/hunt.py`, `frontend/src/pages/HuntPage.tsx`.
> Where the build differs from the Phase 1 design, this page says so.

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
  "time_range": {"last": "24h"},
  "filters": [
    {"field": "source_ip", "op": "eq", "value": "203.0.113.45"},
    {"field": "event_category", "op": "eq", "value": "authentication"},
    {"field": "event_action", "op": "eq", "value": "logon"},
    {"field": "event_outcome", "op": "eq", "value": "success"}
  ],
  "alert": {"rule_ids": ["AUTH-002"], "severities": ["high"], "statuses": ["NEW"]},
  "sort": "newest",
  "limit": 50,
  "cursor": null
}
```

Rules, all enforced by Pydantic validation before any SQL is built (`hunting/query.py`):

- **The time range is required** and spans at most 31 days: `{"from", "to"}` (with a time
  zone) or `{"last": "15m" | "24h" | "7d"}`. The relative form was added in the build so a
  saved hunt always looks at recent data.
- **Fields**: the same allowlist as detection conditions (every normalized `events` column),
  plus `attributes.<key>`. `GET /api/hunt/fields` lists them with their operators for the
  query builder. Raw records are shown on event pages but cannot be searched: they are
  unnormalized, attacker-controlled text.
- **Operators** depend on the field type:

  | Field type | Operators |
  |---|---|
  | text (and `attributes.<key>`) | `eq`, `ne`, `in`, `not_in`, `contains`, `startswith`, `endswith`, `exists` |
  | IP address | `eq`, `ne`, `in`, `not_in`, `cidr`, `exists` |
  | port | `eq`, `ne`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `exists` |
  | `identity_privileged` | `eq`, `ne`, `exists` |

  There is **no regex** (a ReDoS risk, [ADR-0004](decisions/0004-declarative-rule-engine.md)),
  and no substring operators on IP addresses. Filters combine with AND; OR within a field is
  `in`. Text comparisons ignore the case of ASCII letters only, exactly as rule conditions do.
- **Values** are typed: IP addresses must be addresses (`cidr`: a network), ports 0–65535,
  `identity_privileged` true/false. An attribute value compares as its JSON text (the number
  5 reads `"5"`, `true` reads `"true"`).
- **Limits**: at most 20 filters, `in` lists of at most 100 values, values of at most 512
  characters, page size of at most 200.
- **Alert filters** (`alert`): whether an event is evidence in any alert (`in_alert`), and
  the rule, severity or status of the alerts citing it. This covers the brief's "severity /
  detection / status" hunting fields without copying alert data into `events`.

## Execution

- **Exact SQL.** A detection rule's SQL is only a prefilter (it may select more rows; Python
  decides). A hunt has no second pass, so its SQL must be the answer. The compiler reuses the
  condition language's SQL wherever `conditions.is_exact()` says it is exact, compiles the
  few cases the condition language leaves to Python (equality on ports and on
  `identity_privileged`, attribute values), and refuses the operators SQL cannot evaluate
  exactly. A test checks, row for row, that the SQL selects exactly what the Python condition
  accepts, for every allowed operator, on stored events chosen to break naive
  implementations. Values are always bound parameters; there is no string-built SQL.
- **Keyset pagination** on `(timestamp, id)`, newest or oldest first: an opaque cursor
  returns the next page in constant time, however deep the analyst pages, and pages do not
  repeat or skip rows while new events arrive (tested).
- **Statement timeout**: each hunt runs with `SET LOCAL statement_timeout` (5 s by default,
  `HUNT_TIMEOUT_MS`), reset afterwards. A query that runs too long is cancelled and the API
  answers 503 with code `hunt_timeout` and a message to narrow the hunt.
- **Count**: matches are counted up to 10,000; beyond, the answer says `total_capped`
  ("10,000+"). Counting a whole month of events on every page is wasted work.
- **Text search** (`contains`, `startswith`, `endswith` on `command_line` and `message`) uses
  `pg_trgm` GIN indexes. They index the ASCII-folded expression the compiler writes,
  `translate(column, 'A..Z', 'a..z')` (migration 0008). The Phase 4 indexes were on the raw
  columns and were never used, by hunts or by rule prefilters; an old test checked them with
  an `ILIKE` query the application never sends. A test now checks the query the compiler
  actually writes. It is substring matching, not relevance ranking (see "Limits").

## Hunt templates

Some questions are not a flat filter. Templates (`hunting/templates.py`) are **SQL written
and reviewed in the codebase**, literal text with typed parameters bound as parameters,
inside the same time-range bound. They are never user-supplied SQL.

| Template | Question | Parameters (default) | Technique |
|---|---|---|---|
| `success_after_failures` | Successful logons preceded, for the same account and source, by at least N failed logons within M minutes (mirrors AUTH-002) | `min_failures` 1–1000 (3), `within_minutes` 1–1440 (10) | T1110 |
| `first_seen_source_for_user` | Successful logons from a network (/24, /64 for IPv6) the account did not log on from in the previous D days, for accounts with at least H earlier logons (mirrors AUTH-004) | `lookback_days` 1–90 (14), `min_history` 0–1000 (5) | T1078 |
| `rare_process_on_host` | Processes seen on at most N hosts in the period | `max_hosts` 1–100 (1) | T1059 |
| `one_source_many_accounts` | Sources with failed logons against at least K distinct accounts (password spraying) | `min_accounts` 2–10,000 (5) | T1110.003 |

The first two mirror detection rules on purpose: an analyst can see what a rule would have
found over a period, with other thresholds, before tuning the rule. The design named window
functions for the first one; the build uses a `LATERAL` count per successful logon, which
reads more simply and uses the same indexes. A template returns at most 200 rows
(`truncated` when there were more). Each template is tested against its demo scenario and
returns nothing on benign activity (six working days on two hosts).

## Pivoting and saved hunts

- **The hunt lives in the URL**: `/hunt?q=<definition>`, where the definition has the same
  JSON shape as a saved hunt (`{"kind": "query", "query": {...}}` or
  `{"kind": "template", "template_id", "params", "time_range"}`). A hunt can be bookmarked,
  shared, or linked from an incident note.
- **Pivots**: every host, account, source address and process in hunt results opens a menu:
  narrow the hunt to the value, exclude it, or start a new hunt on it. Alert, incident,
  event, asset and identity pages have "Hunt this …" links, scoped to the activity being
  viewed (an hour either side of the alert's evidence, the incident's activity or the event;
  the last 7 days for assets and identities).
- **Saved hunts** (`saved_hunts`): a name (unique per owner), an optional description, the
  definition and a `shared` flag. Private by default. Shared hunts are readable by every
  signed-in user and changed or deleted only by their owner (403 for others; a private hunt
  is 404 to others, so its existence is not confirmed). The definition is stored with only
  what the analyst set and validated again whenever it is loaded: a hunt saved by an older
  version that no longer validates is listed as not runnable, with the reason, instead of
  failing or running something different.

## Access and audit

- VIEWER and above may hunt: it only reads. ANALYST and above may save hunts.
- Hunts are **not** written to the audit log one by one. That would flood it, and reading is
  not a security-relevant change. Saving, changing (including sharing) and deleting a saved
  hunt are audited (`HUNT_SAVED`, `HUNT_UPDATED` with the changed field names,
  `HUNT_DELETED`) with the name, kind and sharing, never the filter values. The request log
  keeps a trace of every hunt call without the body.

## Tests

`tests/unit/test_hunt_query.py`, `tests/integration/test_hunt_sql.py`,
`tests/api/test_hunt.py`, `frontend/tests/hunt.test.tsx`:

- Validation refuses unknown fields and operators, regex, substring operators on IPs,
  wrongly typed values, oversized lists and filter counts, missing or too long time ranges,
  naive datetimes, and contradictory alert filters.
- SQL and Python agree row for row for every allowed operator; injection-shaped values
  (`' OR 1=1 --`, `%`, `_`, backslashes) match literally; attribute values compare as their
  JSON text; substring search can use the trigram indexes, and every index the migrations
  build matches its model definition (PostgreSQL renders both; Alembic's own comparison
  does not look at index expressions).
- The brief's example question on ingested data; keyset pages stable and gap-free while
  events arrive (both orders); the capped count; alert filters.
- Every template against its scenario and against benign activity; parameter bounds and
  types (422, values never echoed).
- The statement timeout: a slow hunt answers 503 `hunt_timeout`, and the timeout does not
  outlive the hunt.
- Saved hunts: private until shared, owner-only changes, viewers cannot save, unique names
  (409), definitions validated, old definitions flagged, audit entries without filter
  values.
- Mutation-checked: dropping the NULL case of a compiled `ne`, and an off-by-one in the
  cursor condition, each fail a test.

## Limits (honest)

- Substring search, not full-text relevance. No stemming, no phrase ranking, no fuzzy
  matching beyond trigram similarity.
- No cross-source joins beyond the fixed templates. No statistics language, no charts over
  arbitrary aggregations.
- The 31-day window is a deliberate cost bound. Longer investigations run several hunts.
- The count stops at 10,000 and templates at 200 rows.
- A search engine (OpenSearch) would lift the first two limits. The trigger for adding one is
  documented in [architecture.md](architecture.md#scale-limits-honest), not planned.
