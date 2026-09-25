# Event model, parsing and enrichment

> Status: **Model and storage implemented and tested (Phase 4):** `NormalizedEvent`
> (`app/events/schema.py`), the `log_sources` / `raw_events` / `events` tables, and the event
> store functions (`app/events/store.py`). Parsers, normalization of source formats and
> enrichment: Phase 5. See [ADR-003](decisions/0003-normalized-event-schema.md) and
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
host and a time zone for formats that lack them. It is created in Phase 4 because every
event must name its source; its API and the ingestion batches arrive in Phase 5.

## Canonical form (enforced by `NormalizedEvent` and database checks)

- The timestamp **must** carry a time zone and is stored in UTC. A naive timestamp is
  rejected: deciding the zone is the parser's job, from the log source's configuration.
- `event_action` must belong to the category's controlled vocabulary (`ACTIONS` in
  `schema.py`); rules match on these words, so a parser cannot invent synonyms.
- Hostnames are lowercase RFC 1123 labels without a trailing dot. IPs are in canonical text
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

### Normalization rules

- Usernames: trimmed, lowercased. `DOMAIN\user` and `user@domain` are split into `username` +
  `user_domain`. Windows machine accounts (`HOST$`) and `-` are kept, with
  `attributes.account_kind`. The original value stays in the raw record.
- Hostnames: lowercased, trailing dot removed. Short name vs FQDN: stored as received. Asset
  matching tries the exact value, then the first label.
- IPs are parsed with `ipaddress`. Invalid values become null plus a parse warning, never a
  crash. IPv4-mapped IPv6 is unmapped.
- Timestamps become UTC. **Syslog RFC 3164 has no year and no zone.** The year and timezone come
  from the log-source configuration. The year is inferred relative to the receive time, and a
  December line received in January goes to the previous year. The high-precision rsyslog
  format (RFC 3339) is also accepted and needs no inference.

## Supported source formats (initial)

All sample and demo data is synthetic. Parsers accept a documented subset of each format, and
anything outside it becomes a `FAILED` raw event with a reason.

| Source type | Input | Produces |
|---|---|---|
| `linux_auth` | auth.log lines (RFC 3164 or RFC 3339 timestamp) | sshd `Failed password`, `Accepted password/publickey`, `Invalid user`, `Connection closed ... [preauth]`; `sudo` commands and `NOT in sudoers` / `incorrect password attempts`; `su`; `useradd new user`, `usermod`/`gpasswd` group additions |
| `windows_security` | JSON objects shaped like `Get-WinEvent \| ConvertTo-Json` / Winlogbeat subset: `EventID`, `TimeCreated`, `Computer`, `EventData{...}` | 4624, 4625 (logon success/failure), 4634 (logoff), 4672 (special privileges), 4688 (process creation with command line), 4720 (user created), 4732 (member added to local group) |
| `http_access` | nginx/Apache combined log format | `web/http_request` with method, path, status, bytes, user agent; status 401/403 → outcome `failure` |
| `app_json` | JSON lines from an application: `{"ts","level","event","user","ip","outcome",...}` with documented event names | login, logout, admin actions → `authentication` / `iam` / `application` |
| `generic_json` | JSON already in SentinelX field names (validated by Pydantic) | Anything, including `process` and `network` events (used for PROC-001 / NET-001 sample data and future shippers) |

XML Windows events are not supported at first. Supporting them would need a hardened XML
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
  part of the raw text. Documented in the batch report semantics.

## Enrichment

Deterministic, explainable, and computed from data SentinelX holds. There is **no external
threat intelligence** (NOT IMPLEMENTED, and it will not be pretended).

- `source_ip_scope`: RFC 1918 + configured `INTERNAL_NETWORKS` → `internal`; loopback;
  link-local; everything else → `external`. The RFC 5737 documentation ranges used by demo data
  count as `external` so scenarios behave like real ones. That choice is documented and
  labelled.
- Asset and identity lookups use an in-memory snapshot loaded **once per batch**, which avoids
  N+1 queries.
- Criticality and privilege are **snapshots**. They show what was known when the event
  arrived. Risk scoring of new alerts uses the **current** asset and identity values and
  records the values it used in the risk breakdown. Both behaviours are documented, so an
  analyst can see when context changed.
- Unknown host or user: the FK stays null. Risk treats an unknown asset as `medium`
  criticality and says so in the breakdown.
