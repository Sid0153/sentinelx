# Event model, parsing and enrichment

> Status: **Implemented and tested.** Model and storage (Phase 4): `NormalizedEvent`
> (`app/events/schema.py`) and the event store (`app/events/store.py`). Ingestion (Phase 5):
> five parsers (`app/ingestion/parsers/`), shared normalization, enrichment, and batches with
> per-record outcomes (`app/ingestion/service.py`). See [ADR-003](decisions/0003-normalized-event-schema.md) and
> [ADR-0010](decisions/0010-evidence-storage.md).

## Raw and normalized are stored separately

Security logs are evidence, so the original record is never modified.

- `raw_events`: **exactly the bytes received** (`bytea`; text input is stored as its UTF-8
  bytes), the source, when it was received, a SHA-256 fingerprint, and the parse outcome.
  This row is written for **every** record, including records that fail to parse. A malformed
  record is still evidence that something sent it, and bytes that are not valid text (NUL,
  invalid UTF-8) are kept as they are. For display only, the UI decodes them with replacement
  characters.
- `events`: the normalized, enriched representation. Each row points to its `raw_events` row
  (unique: one normalized event per raw record). Text in it cannot contain NUL: a NUL becomes
  U+FFFD, and a NUL or other control character in a user name is rejected.

Both tables are append-only through database triggers that reject `UPDATE`, `DELETE` and
`TRUNCATE`, the same as `audit_logs`. The demo reset (Phase 16) will be designed without
weakening this, for example by recreating the demo database.

`log_sources` holds each configured origin: its name, `source_type` (which parser), a default
host and a time zone for formats that lack them. `ingestion_batches` records each ingest
request (who, which channel, and how many records ended in each outcome), and every raw record
points to its batch.

## Canonical form (enforced by `NormalizedEvent` and database checks)

- The timestamp **must** carry a time zone and is stored in UTC. A naive timestamp is
  rejected: deciding the zone is the parser's job, from the log source's configuration.
- `event_action` must belong to the category's controlled vocabulary (`ACTIONS` in
  `schema.py`); rules match on these words, so a parser cannot invent synonyms.
- Hostnames are lowercase RFC 1123 labels (plus `_`, for NetBIOS names) without a trailing
  dot. IPs are in canonical text
  form, and IPv4-mapped IPv6 becomes plain IPv4. User names are lowercased and cannot contain
  control characters.
- `attributes` holds at most 50 flat `snake_case` keys with scalar values of at most 1,024
  characters. Unknown top-level fields are rejected (`extra="forbid"`), and events are
  immutable once built.
- The database repeats the essential rules as `CHECK` constraints (categories, outcomes,
  action format, port ranges, lowercase host and user, size limits), so a bug that bypasses
  the model cannot store an invalid event either.

## Normalized fields

The field names follow the spirit of the Elastic Common Schema (ECS) (category / action /
outcome), but the schema stays flat and small. We are not adopting full ECS or OCSF: both are
large, and most of their fields would stay empty here. Keeping names close to ECS makes a
later mapping mechanical.

Typed, indexed columns are used for anything a rule, hunt or index needs. Everything else
source-specific goes into `attributes` (JSONB).

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | SentinelX event ID |
| `raw_event_id` | UUID FK | Original record |
| `source_id` | FK | Log source that received it (e.g. `web-01 auth.log`) |
| `source_type` | enum | Parser used: `linux_auth`, `windows_security`, `http_access`, `app_json`, `generic_json` |
| `timestamp` | timestamptz (ms) | **Event time** from the record |
| `ingested_at` | timestamptz | Receive time |
| `host` | text | Lowercased hostname where the event happened (target host) |
| `host_ip` | inet | If the record has it |
| `event_category` | enum | `authentication`, `iam`, `privilege`, `process`, `network`, `web`, `application` |
| `event_action` | text (controlled vocabulary) | e.g. `logon`, `logoff`, `user_created`, `group_member_added`, `sudo`, `process_started`, `connection`, `http_request` |
| `event_outcome` | enum | `success`, `failure`, `unknown` |
| `username` | text | **Actor**, normalized (see below) |
| `user_domain` | text | `CORP` from `CORP\alice`; null for local |
| `target_username` | text | Subject of the action when it differs from the actor: the created user, the user added to a group, the sudo target user |
| `source_ip`, `source_port` | inet, int | Where the action came from |
| `destination_ip`, `destination_port` | inet, int | Where it went (network, HTTP) |
| `protocol` | text | `ssh`, `tcp`, `udp`, `http`, `rdp`... |
| `service` | text | Emitting program: `sshd`, `sudo`, `useradd`, `nginx`, `Microsoft-Windows-Security-Auditing` |
| `process_name`, `parent_process_name` | text | Basename, lowercased |
| `command_line` | text | Truncated to 8 KB for storage and matching; `attributes.command_truncated=true` when cut |
| `session_id` | text | sshd PID/session, Windows LogonId, app session |
| `message` | text | Short human summary produced by the parser |
| `attributes` | JSONB | Source-specific: Windows `event_id`, `logon_type`, `group_name`, HTTP `method`/`path`/`status`/`user_agent`, etc. |
| **Enrichment** | | |
| `source_ip_scope` | enum | `internal`, `external`, `loopback`, `link_local`, `unknown` (see below) |
| `asset_id` | FK null | Asset matched on `host` (then on `host_ip`) |
| `asset_criticality` | enum null | **Snapshot** at ingest time |
| `identity_id` | FK null | Identity matched on normalized `username` |
| `identity_privileged` | bool null | **Snapshot** at ingest time |
| `simulated` | bool | True for demo-generator events; shown in the UI |

Fields from the brief that were left out on purpose:
- `event_type`, `status` and `action` collapse into `event_category` / `event_action` /
  `event_outcome`, which avoids three overlapping fields.
- `hostname` would duplicate `host`.
- `user_id` is `identity_id`.
- `metadata` is `attributes`.
- `raw_event` lives in `raw_events`.

### Normalization rules (implemented in `ingestion/normalize.py` and each parser)

- Usernames: trimmed, lowercased. `DOMAIN\user` and `user@domain` are split into `username` +
  `user_domain` (Windows supplies the domain in a separate field). Windows machine accounts
  (`HOST$`) are kept and marked `attributes.account_kind = machine`. Placeholders (`-`,
  empty) become null. The original value stays in the raw record.
- Hostnames: lowercased, trailing dot removed, stored as received (short name or FQDN).
  Underscores are accepted because Windows NetBIOS names use them. Asset matching tries the
  exact value, then the first label.
- IPs are parsed with `ipaddress`. An invalid value or a placeholder in an optional field
  becomes null, never a crash. IPv4-mapped IPv6 is unmapped.
- Timestamps become UTC. **Syslog RFC 3164 has no year and no zone.** The zone comes from the
  log source. The year comes from the receive time, and a line more than a day in the future
  is moved to the previous year (a December line received in January). RFC 3339 syslog, ISO
  8601 JSON times and PowerShell 5's `/Date(ms)/` carry their own zone. A naive ISO timestamp
  in a JSON record fails the record: guessing its zone would falsify evidence.

## Record outcomes

Every record ends in exactly one outcome, stored on its raw record with a short fixed reason
code (never text copied from the record):

| Outcome | Meaning | Examples |
|---|---|---|
| `PARSED` | Became a normalized event | sshd `Failed password`, Windows 4625 |
| `SKIPPED` | Understood, deliberately not normalized | sshd `Connection closed … [preauth]`; `Invalid user …` (the `Failed password` line that follows carries the attempt, so counting both would double-count); cron; Windows event IDs that are not modelled |
| `FAILED` | Not understood | `unrecognized_format`, `invalid_json`, `not_utf8`, `invalid_timestamp`, `unknown_event_type`, `invalid_field`, `parser_error` |

A parser bug never aborts a batch: the record fails with `parser_error`, and the log names only
the exception type (its message could contain text from the record).

## Supported source formats (implemented, Phase 5)

All sample and demo data is synthetic. Parsers accept a documented subset of each format.

| Source type | Input | Produces |
|---|---|---|
| `linux_auth` | auth.log lines, RFC 3164 or RFC 3339 timestamps | **sshd**: `Failed`/`Accepted` for password, publickey and keyboard-interactive (including `invalid user`) → logon failure/success with `auth_method` and `invalid_user`; session closed → logoff. **sudo**: command → `privilege/sudo` (actor, target user, command, tty, cwd); `NOT in sudoers`, `N incorrect password attempts`, `command not allowed` → failure with `failure_reason`. **su**: success, or failure for `FAILED SU`. **useradd/usermod/gpasswd/userdel/passwd**: `user_created` (uid, shell), `group_member_added` (group_name, plus the actor for gpasswd), `user_deleted`, `password_changed`. Other programs → SKIPPED |
| `windows_security` | One JSON object per event: `EventID`, `TimeCreated`, `Computer`, `EventRecordID`, `EventData{...}` | 4624/4625 logon (logon type and name, auth package, status/sub-status; RDP gives protocol `rdp`), 4634 logoff, 4672 special privileges, 4688 process start (process and parent names, command line, path), 4720 user created, 4732 member added to a group. 4720 and 4732 both carry `target_sid`, because 4732 usually has no member name for local accounts. Other IDs → SKIPPED |
| `http_access` | nginx/Apache combined (or common) format | `web/http_request`: method, path and query (stored separately), version, status, bytes, referrer, user agent. 2xx/3xx → success; 4xx/5xx → failure. Garbage request lines (TLS bytes sent to an HTTP port) are kept as events with `request_line`. The host is the source's `default_host` |
| `app_json` | JSON lines `{"ts", "event", "user", "target_user"?, "ip"?, "host"?, "app"?, "role"?, "detail"?, "session"?}` | Event names `login_success`, `login_failure`, `logout`, `password_change`, `user_created`, `role_changed`, `config_changed`, `admin_action`, `access_denied`. An unknown name FAILS the record: the application and SentinelX disagree about the contract, and someone should notice |
| `generic_json` | JSON in SentinelX's own field names | Anything the normalized model accepts (used for process and network telemetry). A `source_type` in the record is ignored. A sender's own `event_id` is dropped from the event but stays in the raw record, and so in the fingerprint |

Robustness, tested on every parser:
- random bytes never crash a parser;
- every regular expression is anchored, with bounded, non-overlapping repetition, and hostile
  60 KB lines are handled in well under half a second (no catastrophic backtracking);
- deeply nested JSON fails as `invalid_json`;
- markup in fields is stored as inert text.

XML Windows events are not supported. Supporting them would need a hardened XML
parser (`defusedxml`), which we add only if a real XML source is connected.

## Duplicate strategy

`fingerprint = sha256(source_id ‖ 0x1F ‖ raw bytes)` with a unique index (the separator
cannot occur in a UUID, so different (source, record) pairs cannot produce the same input).
- Re-sending the same record from the same source is a **no-op**, counted as `duplicates` in
  the batch report. Retries and re-uploaded files are therefore safe.
- The same text from two different sources is not a duplicate. They are different
  observations.
- Known limitation: two byte-identical lines from one source are collapsed. For sshd this is
  rare because each line carries the client port and PID. For Windows the `EventRecordID`
  makes records unique. For `generic_json` the sender can include its own `event_id`, which is
  part of the raw text.
- Duplicates are detected before parsing, both against stored records and within the batch,
  so resending a whole file costs one indexed lookup per record. Measured once on this laptop
  through nginx: 5,000 duplicate lines in 0.06 s. That is one measurement, not a benchmark.

## Enrichment (implemented, Phase 5: `ingestion/enrich.py`)

Deterministic, explainable, and computed from data SentinelX holds. There is **no external
threat intelligence** (NOT IMPLEMENTED, and it will not be pretended).

- `source_ip_scope`: addresses in `INTERNAL_NETWORKS` (default: RFC 1918 and `fc00::/7`) →
  `internal`; loopback; link-local; everything else → `external`. The RFC 5737 documentation
  ranges used by demo data count as `external` so scenarios behave like real ones. That choice
  is documented and labelled.
- Asset and identity lookups use an in-memory snapshot of the whole inventory, loaded **once
  per batch**, which avoids N+1 queries. A short name that belongs to two assets is not used
  for matching (it is ambiguous). The snapshot suits inventories of thousands of assets; a much
  larger inventory would instead query per batch for the hosts it contains.
- Identities match on the actor (`username`) only. The target of an action (for example, the
  account created) is not enriched yet; the risk model will look it up when it needs it.
- Criticality and privilege are **snapshots**. They show what was known when the event
  arrived. Risk scoring of new alerts uses the **current** asset and identity values and
  records the values it used in the risk breakdown. Both behaviours are documented, so an
  analyst can see when context changed.
- Unknown host or user: the FK stays null. Risk treats an unknown asset as `medium`
  criticality and says so in the breakdown.
