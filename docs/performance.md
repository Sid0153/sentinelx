# Performance

> Status: **measured in Phase 14.** Every number on this page comes from one recorded run of
> `backend/benchmarks/run.py` on the machine described below; the raw results are in
> [benchmarks/](benchmarks/). Nothing is estimated or extrapolated. Numbers from another
> machine, another PostgreSQL configuration or another workload will differ.

## What was measured

| Question | How |
|---|---|
| How fast does the full pipeline take in records? | 1,000,000 synthetic records sent in batches of 1,000 through `ingestion.service.ingest`, exactly as an API request is processed: parse, normalize, enrich, store, detect (all nine rules), alert, correlate. Each batch in its own session, one after another. |
| Does detection slow down as the tables grow? | Per batch, the store time and detection time the pipeline logs itself, grouped by how many events were already stored. |
| How fast are the pages' reads on that data? | 20 API reads through the FastAPI app in-process (validation, authentication, serialization included; no network, no nginx), each called 20 times after 2 warm-up calls: median, 95th percentile, maximum. |
| What does the database do for them? | Every SQL statement of each read is counted and run again under `EXPLAIN (ANALYZE, BUFFERS)`; the most expensive one by PostgreSQL's own execution time is reported with its plan. |

### The workload

`backend/benchmarks/workload.py`, seeded (same arguments, same records) and tested
(`tests/unit/test_benchmark_workload.py`): every record parses, ordinary activity alone
triggers no rule, every injected attack is detected.

- A fictional environment: 300 Linux servers (200 registered as assets), 150 Windows
  workstations, 120 accounts (all registered as identities, every tenth privileged), each
  account logging on from its own internal /24.
- Ordinary activity, 80 % Linux auth.log and 20 % Windows Security JSON: key-based SSH logons,
  session ends, routine sudo, rare mistyped passwords, cron sessions (skipped as not security
  relevant), Windows logons, logoffs and ordinary process starts.
- One of the demo attack scenarios every 10,000 records, in turn (brute force, brute force
  with success, password spray, distributed brute force, privilege escalation, privileged
  account creation, the multi-stage attack, an encoded PowerShell command).
- Spread over the 7 days before the run, sent in time order.

This is a **dense** workload: 120 accounts each logging on every few minutes, day and night.
That matters for AUTH-004 (below), whose cost follows the accounts' history.

### How to read the numbers

- PostgreSQL runs in Docker Desktop on Windows (WSL 2) with the image's default settings
  (`shared_buffers` 128 MB). The client connects through the published port over TLS; one
  `SELECT 1` round trip is reported, because a read of N statements pays it N times.
- In-process API timing leaves out HTTP, nginx and the browser. It includes Python work that
  production also does.
- One run. Medians are stable between repeated calls of the same read; the load phase was
  run once, so its figures carry the noise of one run on a laptop.

## Results

Run on 2026-10-02 (`docs/benchmarks/20261002-0836-results.json`, per-batch figures in
`20261002-0836-batches.json`), on the working tree on top of commit `cf05fe3` with all the
Phase 14 changes. Earlier runs on the same workload are kept for comparison (below).

**Machine.** Intel Core i7-13700HX (18 logical CPUs), 15.7 GB RAM, Windows 11. Docker Desktop
29.8 (WSL 2; 18 CPUs and 7.6 GB visible to containers). PostgreSQL 16.15 (the Compose image,
default settings: `shared_buffers` 128 MB, `work_mem` 4 MB), connection over TLS, `SELECT 1`
round trip 0.68 ms. Python 3.12.10.

### Load: 1,001,572 records through the full pipeline

| | |
|---|---|
| Records / events stored | 1,001,572 / 921,106 (the rest skipped as not security relevant; none failed) |
| Batches | 2,000 (1,000 Linux of ~800 records, 1,000 Windows of ~200), all `PROCESSED`, no rule errors |
| Attacks injected / detections / alerts / incidents | 100 / 173 / 149 / 61 |
| Wall time | 1,405 s: **712.7 records/s, 655.4 events/s** on average, one batch at a time |
| Batch wall time | median 691.5 ms, p95 1,034.8 ms, max 1,427.5 ms |
| Database size afterwards | 1.3 GB |

Medians per batch, by fifth of the load (about 184,000 events stored per fifth), store /
detection / total:

| Fifth | Linux batch (800 records) | Windows batch (200) | AUTH-004 alone (median per run) |
|---|---|---|---|
| 1 (0 to 184 k events stored) | 556 / 261 / 833 ms | 159 / 288 / 470 ms | 127 ms |
| 2 | 564 / 318 / 904 ms | 159 / 332 / 511 ms | 174 ms |
| 3 | 518 / 268 / 806 ms | 147 / 284 / 456 ms | 137 ms |
| 4 | 575 / 316 / 921 ms | 164 / 346 / 528 ms | 174 ms |
| 5 (to 921 k) | 575 / 291 / 885 ms | 164 / 320 / 492 ms | 140 ms |

What this shows:

- **Neither storing nor detection slows down as the tables grow**, up to 921,000 events.
  Storing costs about 0.65–0.8 ms per record (duplicate check, raw record, normalized event,
  enrichment, the summary triggers, the commit); a detection run of all nine rules about
  0.3 s whatever the batch size, of which AUTH-004 is about half.
- Throughput is for one batch at a time: detection runs are serialized by design (an advisory
  lock, ADR-0008), so more concurrent senders would not multiply it.

### How the numbers got here (same workload, three versions)

| Version | Throughput | Detection per run, first to last fifth | AUTH-004 |
|---|---|---|---|
| Phase 13 code (`benchmarks/before-auth004-fix.csv`; stopped after 244 batches) | not measured to the end | rising from about 0.1 s to as much as 2.7 s within the first 56,000 events | **failed on every batch from about 40,000 events** (`too_many_candidates`) |
| History counted in SQL (`20261002-0736-*`) | 335 records/s | 0.43 s to 1.41 s | 227 ms to 1,249 ms, no failures |
| Plus per-day summaries (`20261002-0836-*`, current) | **712.7 records/s** | 0.28 s to 0.31 s (flat) | 127–174 ms in every fifth (flat), no failures |

1. **AUTH-004 stopped working at volume.** It loaded every earlier logon of the 14-day
   lookback as full rows; past the engine's candidate cap (20,000) it failed with
   `too_many_candidates` on every batch, so logons from new networks were no longer detected.
2. **First fix:** the history is read for the run's accounts only and counted in SQL per
   (account, address); only the band at the old edge of the lookback, where an event is inside
   the lookback of some candidates and not others, is read row by row. It worked at every size
   but still read the accounts' whole 14 days on every run.
3. **Per-day summaries:** a trigger on `events` keeps `logon_success_daily` (successful logons
   per account, address and UTC day) equal to the stored rows (migration 0014). Whole days of
   the lookback come from there; only the partial days at both ends are counted from events.
   The work no longer depends on the length of the lookback.

All three are exact. An integration test compares the history with reading every earlier
event, event by event, on randomized data across day boundaries and the edge band, and it
fails if the summary rows or the edge band are mishandled (both mutation-checked). Both full
runs produced the same 173 detections, 149 alerts and 61 incidents from the same seeded data.

### Reads on the loaded data (20 calls each after 2 warm-ups)

| Read | Median | p95 | SQL statements | DB time, all statements | Most expensive statement (PostgreSQL time: plan) | Median before daily summaries |
|---|---|---|---|---|---|---|
| Dashboard summary | 66.5 ms | 166.1 ms | 17 | 45.63 ms | 44.4 ms: Aggregate, Index Only Scan events (ix_events_host_ts) | 126.9 ms |
| Dashboard trends, 14 days | 15.6 ms | 22.0 ms | 5 | 7.77 ms | 7.53 ms: Aggregate, Index Only Scan events (ix_events_timestamp_id) | 135.0 ms |
| Event explorer, last 24 h | 8.1 ms | 13.3 ms | 2 | 0.08 ms | 0.04 ms: Index Scan users (pk_users) | 8.9 ms |
| Event explorer, 7 days, one account | 7.7 ms | 12.7 ms | 2 | 0.11 ms | 0.08 ms: Limit, Incremental Sort, Index Scan events (ix_events_username_ts) | 10.9 ms |
| Event explorer, 7 days, one host | 8.6 ms | 25.6 ms | 2 | 0.13 ms | 0.09 ms: Limit, Incremental Sort, Index Scan events (ix_events_host_ts) | 7.6 ms |
| Alert queue | 13.8 ms | 30.7 ms | 3 | 0.33 ms | 0.23 ms: Limit, Sort, Seq Scan alerts | 13.0 ms |
| Alerts grouped by host | 16.6 ms | 56.7 ms | 3 | 0.37 ms | 0.19 ms: Limit, Sort, Aggregate | 13.2 ms |
| Incident queue | 27.2 ms | 50.8 ms | 3 | 0.22 ms | 0.12 ms: Limit, Sort, Seq Scan incidents | 9.0 ms |
| Busiest incident | 14.3 ms | 16.1 ms | 8 | 0.33 ms | 0.07 ms: Sort, Nested Loop, Seq Scan incident_alerts | 18.2 ms |
| Busiest incident timeline | 16.3 ms | 22.5 ms | 7 | 0.72 ms | 0.32 ms: Limit, Sort, Append | 15.8 ms |
| Busiest alert evidence | 15.1 ms | 40.1 ms | 4 | 1.74 ms | 1.54 ms: Limit, Sort, Nested Loop | 13.0 ms |
| Assets list | 26.6 ms | 43.2 ms | 4 | 5.93 ms | 5.77 ms: Values Scan, Aggregate, Seq Scan alerts | 20.9 ms |
| Identities list | 16.7 ms | 21.0 ms | 4 | 3.22 ms | 3.08 ms: Values Scan, Aggregate, Seq Scan alerts | 33.1 ms |
| Hunt: 7 days, outside /24 | 11.0 ms | 13.0 ms | 5 | 0.38 ms | 0.25 ms: Limit, Sort, Bitmap Heap Scan events | 11.4 ms |
| Hunt: 7 days, command line contains | 22.6 ms | 51.8 ms | 5 | 4.78 ms | 2.64 ms: Aggregate, Limit, Bitmap Heap Scan events | 13.5 ms |
| Hunt: 7 days, host and failures | 21.9 ms | 37.8 ms | 5 | 2.93 ms | 1.57 ms: Limit, Sort, Bitmap Heap Scan events | 14.9 ms |
| Hunt template: success after failures, 7 days | 1103.7 ms | 1153.7 ms | 4 | 1197.59 ms | 1197.52 ms: Limit, Nested Loop, Index Scan events (ix_events_timestamp_id) | 1106.6 ms |
| Detection metrics, 30 days | 8.8 ms | 10.7 ms | 3 | 0.29 ms | 0.22 ms: Aggregate, Sort, Seq Scan alerts | 9.2 ms |
| ATT&CK coverage, 30 days | 9.7 ms | 17.2 ms | 3 | 1.01 ms | 0.92 ms: Aggregate, Sort, Hash Join | 9.0 ms |
| Audit log | 13.6 ms | 27.3 ms | 3 | 0.13 ms | 0.06 ms: Limit, Incremental Sort, Index Scan audit_logs (ix_audit_logs_occurred_at) | 7.7 ms |

What this shows:

- **Paged lists, detail pages, the explorer and ad-hoc hunts have medians of 8–27 ms** with
  921,000 events: every plan is an index scan or works on the small alert and incident tables
  (149 and 61 rows, where a sequential scan is the cheapest plan). Differences of a few
  milliseconds between the two runs are noise on a laptop; the database part of these reads
  stays under 6 ms.
- **The dashboard reads per-day counts** (`event_daily_counts`, kept by triggers like the
  logon summary) instead of counting every event: the 14-day trend went from 135 ms to 16 ms,
  the summary from 127 ms to 67 ms. What the summary still counts from events is the distinct
  hosts of the last 24 hours, a question per-day counts cannot answer.
- **The "success after failures" template takes 1.1 s** for 7 days: it walks the successful
  logons newest first (455,442 in the range) looking back for failures, and only 38 qualify,
  so it cannot stop early. That is within the hunt statement timeout (5 s). Three alternatives
  were measured on this data (all returned identical rows in four parameter combinations) and
  rejected, because each was faster only when matches are rare and far slower when they are
  common: driving from the failures with a join (996 ms vs 1,192 ms; but 1,057 ms vs 4 ms),
  with a per-failure lateral lookup (878 ms vs 1,628 ms; but 1,031 ms vs 4 ms), and either one
  with a partial index on failed logons. Answering this question means examining every failure
  or every success in the range; on this unusually dense data that takes about a second.

### Limits these numbers point to

- One detection run at a time (by design): on this machine about 700 records per second with
  full detection. A deployment that needs more would batch more records per run or move
  detection off the request path.
- Each summary answers one question (successful logons per account and address; records per
  day). A new `new_value` rule asking something else counts from events as in the first fix:
  correct, but its cost follows its history.
- Single-node PostgreSQL with default memory settings; no partitioning yet (the `events` table
  is designed for monthly partitions, `database-schema.md`).

## Reproducing

From `backend/`, against a database whose name ends in `_bench` (the script refuses any other;
it creates or, with `--fresh`, drops and recreates it, and needs a role that may create
databases):

```bash
python -m benchmarks.run --fresh --records 1000000 --out ../docs/benchmarks --database-url "postgresql+psycopg://USER:PASSWORD@127.0.0.1:5433/sentinelx_bench"
```

Never point it at the application's or the tests' database.
