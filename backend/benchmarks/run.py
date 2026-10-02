"""Controlled benchmark (Phase 14): ingest a seeded synthetic workload through the real
pipeline, then time the API's reads on the loaded data and explain their slowest SQL.

    cd backend
    python -m benchmarks.run --records 500000 --out ../docs/benchmarks \\
        --database-url postgresql+psycopg://USER:PASS@127.0.0.1:5433/sentinelx_bench

Safety: the database name must end in `_bench`; the script creates it (or, with --fresh, drops
and recreates it) and migrates it. It never touches another database. The connecting role
needs CREATEDB (the Compose owner role has it).

What is measured, and how (docs/performance.md explains how to read it):
- Load: every batch goes through `ingestion.service.ingest` exactly as an API request does
  (parse, normalize, enrich, store, detect, alert, correlate) in its own session. Per batch:
  wall time, and the store and detection times the pipeline itself logs.
- Reads: each endpoint is called through the FastAPI app in-process (validation, auth,
  serialization included; no network or proxy), after warm-up runs. Every SQL statement is
  counted and timed; the slowest one is run once more under EXPLAIN (ANALYZE, BUFFERS).
Nothing is estimated: every number in the output comes from this run.
"""

import argparse
import json
import logging
import os
import platform
import random
import secrets
import statistics
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import URL, Connection, make_url

WARMUP = 2
RUNS = 20


# ---------- setup ----------


def bench_url(raw: str) -> URL:
    url = make_url(raw)
    if not (url.database or "").endswith("_bench"):
        sys.exit(
            "Refusing to run: the database name must end in _bench (it is dropped and filled)."
        )
    return url


def prepare_database(url: URL, fresh: bool) -> None:
    maintenance = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with maintenance.connect() as conn:
        exists = conn.scalar(
            text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": url.database}
        )
        if exists and fresh:
            conn.execute(text(f'DROP DATABASE "{url.database}" WITH (FORCE)'))
            exists = False
        if not exists:
            conn.execute(text(f'CREATE DATABASE "{url.database}"'))
    maintenance.dispose()


def configure_environment(url: URL) -> None:
    """The app reads its settings from the environment; point everything at the bench DB."""
    rendered = url.render_as_string(hide_password=False)
    os.environ.update(
        DATABASE_URL=rendered,
        MIGRATION_DATABASE_URL=rendered,
        SECRET_KEY=secrets.token_urlsafe(48),
        APP_ENV="development",
        LOG_LEVEL="WARNING",
        LOG_FORMAT="json",
        CORS_ORIGINS="http://localhost",
    )
    os.environ.pop("APP_DB_USER", None)
    os.environ.pop("APP_DB_PASSWORD", None)


# ---------- measurement helpers ----------


class PipelineTimes(logging.Handler):
    """Captures the timings the pipeline logs for each batch (store, detection)."""

    def __init__(self) -> None:
        super().__init__(logging.INFO)
        self.store_ms: float | None = None
        self.detect_ms: float | None = None

    def emit(self, record: logging.LogRecord) -> None:
        fields = getattr(record, "fields", {})
        if record.getMessage() == "ingest.batch_stored":
            self.store_ms = fields.get("duration_ms")
        elif record.getMessage() == "detection.run_completed":
            self.detect_ms = fields.get("duration_ms")


@dataclass
class StatementLog:
    statements: list[tuple[str, Any, float]] = field(default_factory=list)  # sql, params, ms


@contextmanager
def capture(engine: Any) -> Iterator[StatementLog]:
    log = StatementLog()

    def before(conn: Connection, cursor: Any, statement: str, params: Any, *_: Any) -> None:
        conn.info.setdefault("bench_start", []).append(time.perf_counter())

    def after(conn: Connection, cursor: Any, statement: str, params: Any, *_: Any) -> None:
        started = conn.info["bench_start"].pop()
        log.statements.append((statement, params, (time.perf_counter() - started) * 1000))

    event.listen(engine, "before_cursor_execute", before)
    event.listen(engine, "after_cursor_execute", after)
    try:
        yield log
    finally:
        event.remove(engine, "before_cursor_execute", before)
        event.remove(engine, "after_cursor_execute", after)


def percentile(values: list[float], share: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(share * (len(ordered) - 1))))
    return ordered[index]


def plan_summary(node: dict[str, Any], found: list[str]) -> list[str]:
    """Node types of a JSON plan, with the relation (and index) each scan reads."""
    label = node["Node Type"]
    if "Relation Name" in node:
        label += f" {node['Relation Name']}"
    if "Index Name" in node:
        label += f" ({node['Index Name']})"
    found.append(label)
    for child in node.get("Plans", []):
        plan_summary(child, found)
    return found


# ---------- phases ----------


def load(args: argparse.Namespace, end: datetime) -> dict[str, Any]:
    from app.core.config import get_settings
    from app.database.session import get_session_factory
    from app.ingestion.service import IngestRequest, ingest
    from app.models.event import BatchChannel, LogSource
    from app.models.user import User
    from benchmarks.workload import Workload

    settings = get_settings()
    factory = get_session_factory()
    times = PipelineTimes()
    for name in ("app.ingestion.service", "app.detection.engine"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.addHandler(times)
        logger.propagate = False

    with factory() as db:
        admin = db.query(User).filter(User.email == "bench@example.com").one()
        sources = {s.source_type: s.id for s in db.query(LogSource).all()}

    workload = Workload(
        seed=args.seed,
        records=args.records,
        batch_size=args.batch_size,
        start=end - timedelta(days=args.days),
        end=end,
        attack_every=args.attack_every,
    )
    batches: list[dict[str, Any]] = []
    started = time.perf_counter()
    for index, batch in enumerate(workload.batches()):
        times.store_ms = times.detect_ms = None
        with factory() as db:
            source = db.get(LogSource, sources[batch.source_type])
            user = db.get(User, admin.id)
            if source is None or user is None:
                raise RuntimeError("bench source or admin missing")
            t0 = time.perf_counter()
            stored = ingest(
                db,
                IngestRequest(
                    source,
                    [r.encode() for r in batch.records],
                    BatchChannel.API,
                    user,
                    simulated=True,
                ),
                settings,
            )
            wall = (time.perf_counter() - t0) * 1000
            batches.append(
                {
                    "index": index,
                    "source_type": str(batch.source_type),
                    "records": stored.received_count,
                    "parsed": stored.parsed_count,
                    "wall_ms": round(wall, 1),
                    "store_ms": times.store_ms,
                    "detect_ms": times.detect_ms,
                    "detections": stored.detection_count,
                    "alerts_created": stored.alerts_created or 0,
                    "incidents_created": stored.incidents_created or 0,
                    "attacks": batch.attacks,
                    "status": str(stored.status),
                }
            )
        if index % 50 == 0:
            done = sum(b["records"] for b in batches)
            print(f"  batch {index}: {done:,} records, {wall:.0f} ms", flush=True)
    elapsed = time.perf_counter() - started
    return {"elapsed_s": round(elapsed, 1), "batches": batches}


def summarize_load(result: dict[str, Any]) -> dict[str, Any]:
    batches = result["batches"]
    records = sum(b["records"] for b in batches)
    events = sum(b["parsed"] for b in batches)
    failed = [b for b in batches if b["status"] != "PROCESSED"]
    tenth = max(1, len(batches) // 10)
    deciles = []
    for start in range(0, len(batches), tenth):
        part = batches[start : start + tenth]
        per_k = [b["wall_ms"] / b["records"] * 1000 for b in part]
        deciles.append(
            {
                "batches": f"{start}-{start + len(part) - 1}",
                "events_before": sum(b["parsed"] for b in batches[:start]),
                "median_wall_ms_per_1000": round(statistics.median(per_k), 1),
                "median_store_ms": round(
                    statistics.median(float(b["store_ms"] or 0) for b in part), 1
                ),
                "median_detect_ms": round(
                    statistics.median(float(b["detect_ms"] or 0) for b in part), 1
                ),
            }
        )
    return {
        "records": records,
        "events": events,
        "batches": len(batches),
        "batches_not_completed": len(failed),
        "elapsed_s": result["elapsed_s"],
        "records_per_s": round(records / result["elapsed_s"], 1),
        "events_per_s": round(events / result["elapsed_s"], 1),
        "batch_wall_ms": {
            "median": round(statistics.median(b["wall_ms"] for b in batches), 1),
            "p95": round(percentile([b["wall_ms"] for b in batches], 0.95), 1),
            "max": round(max(b["wall_ms"] for b in batches), 1),
        },
        "detections": sum(b["detections"] for b in batches),
        "alerts_created": sum(b["alerts_created"] for b in batches),
        "incidents_created": sum(b["incidents_created"] for b in batches),
        "attacks_injected": sum(len(b["attacks"]) for b in batches),
        "by_progress": deciles,
    }


def reads(end: datetime) -> list[dict[str, Any]]:
    from fastapi.testclient import TestClient
    from sqlalchemy import func, select

    from app.auth.tokens import create_access_token
    from app.core.config import get_settings
    from app.database.session import get_engine, get_session_factory
    from app.main import create_app
    from app.models.alert import Alert
    from app.models.incident import Incident
    from app.models.user import User

    engine = get_engine()
    with get_session_factory()() as db:
        admin = db.query(User).filter(User.email == "bench@example.com").one()
        incident = db.scalar(select(Incident).order_by(Incident.alert_count.desc()).limit(1))
        alert = db.scalar(select(Alert).order_by(Alert.event_count.desc()).limit(1))
        busiest_host = db.scalar(
            select(Alert.host).group_by(Alert.host).order_by(func.count().desc()).limit(1)
        )
    token = create_access_token(admin.id, get_settings().secret_key, timedelta(hours=2))
    headers = {"Authorization": f"Bearer {token}"}
    stamp = "%Y-%m-%dT%H:%M:%SZ"  # no "+00:00": a "+" in a URL means a space
    week = {"from": (end - timedelta(days=7)).strftime(stamp), "to": end.strftime(stamp)}

    endpoints: list[tuple[str, str, str, Any]] = [
        ("Dashboard summary", "GET", "/api/dashboard/summary", None),
        ("Dashboard trends, 14 days", "GET", "/api/dashboard/trends?days=14", None),
        ("Event explorer, last 24 h", "GET", "/api/events?limit=50", None),
        (
            "Event explorer, 7 days, one account",
            "GET",
            f"/api/events?limit=50&username=user007&from={week['from']}&to={week['to']}",
            None,
        ),
        (
            "Event explorer, 7 days, one host",
            "GET",
            f"/api/events?limit=50&host=srv-007&from={week['from']}&to={week['to']}",
            None,
        ),
        ("Alert queue", "GET", "/api/alerts?limit=50", None),
        ("Alerts grouped by host", "GET", "/api/alerts/groups?by=host", None),
        ("Incident queue", "GET", "/api/incidents?limit=50", None),
        ("Busiest incident", "GET", f"/api/incidents/{incident.id}" if incident else "", None),
        (
            "Busiest incident timeline",
            "GET",
            f"/api/incidents/{incident.id}/timeline?limit=100" if incident else "",
            None,
        ),
        (
            "Busiest alert evidence",
            "GET",
            f"/api/alerts/{alert.id}/events?limit=50" if alert else "",
            None,
        ),
        ("Assets list", "GET", "/api/assets?limit=50", None),
        ("Identities list", "GET", "/api/identities?limit=50", None),
        (
            "Hunt: 7 days, outside /24",
            "POST",
            "/api/hunt/query",
            {
                "time_range": {"last": "7d"},
                "filters": [{"field": "source_ip", "op": "cidr", "value": "203.0.113.0/24"}],
            },
        ),
        (
            "Hunt: 7 days, command line contains",
            "POST",
            "/api/hunt/query",
            {
                "time_range": {"last": "7d"},
                "filters": [{"field": "command_line", "op": "contains", "value": "powershell"}],
            },
        ),
        (
            "Hunt: 7 days, host and failures",
            "POST",
            "/api/hunt/query",
            {
                "time_range": {"last": "7d"},
                "filters": [
                    {"field": "host", "op": "eq", "value": busiest_host or "srv-007"},
                    {"field": "event_outcome", "op": "eq", "value": "failure"},
                ],
            },
        ),
        (
            "Hunt template: success after failures, 7 days",
            "POST",
            "/api/hunt/templates/success_after_failures/run",
            {"params": {}, "time_range": {"last": "7d"}},
        ),
        ("Detection metrics, 30 days", "GET", "/api/detections/metrics?days=30", None),
        ("ATT&CK coverage, 30 days", "GET", "/api/mitre/coverage?days=30", None),
        ("Audit log", "GET", "/api/audit?limit=50", None),
    ]

    results = []
    with TestClient(create_app()) as client:
        for label, method, path, body in endpoints:
            if not path:
                continue
            for _ in range(WARMUP):
                response = client.request(method, path, json=body, headers=headers)
                if response.status_code != 200:
                    raise RuntimeError(f"{label}: {response.status_code} {response.text[:300]}")
            timings: list[float] = []
            counts: list[int] = []
            last: list[tuple[str, Any, float]] = []
            for _ in range(RUNS):
                with capture(engine) as log:
                    t0 = time.perf_counter()
                    client.request(method, path, json=body, headers=headers)
                    timings.append((time.perf_counter() - t0) * 1000)
                counts.append(len(log.statements))
                last = log.statements
            # Server-side cost of the last run's statements: every read is explained, and the
            # most expensive one (by PostgreSQL's own execution time) is reported.
            plans = [explain(engine, sql, params) for sql, params, _ in last]
            explained = [p for p in plans if p is not None]
            slowest = max(explained, key=lambda p: p["execution_ms"], default=None)
            results.append(
                {
                    "endpoint": label,
                    "request": f"{method} {path.split('?')[0]}",
                    "median_ms": round(statistics.median(timings), 1),
                    "p95_ms": round(percentile(timings, 0.95), 1),
                    "max_ms": round(max(timings), 1),
                    "statements": max(counts),
                    "db_execution_ms": round(sum(p["execution_ms"] for p in explained), 2),
                    "plan": slowest and {**slowest, "text": explain_text(engine, slowest)},
                }
            )
            print(f"  {label}: median {results[-1]['median_ms']} ms", flush=True)
    return results


def explain(engine: Any, sql: str, params: Any) -> dict[str, Any] | None:
    """EXPLAIN (ANALYZE, BUFFERS) of a read statement. Statements that are not a plain read
    (SET LOCAL for the hunt timeout) are not explained."""
    if not sql.lstrip().upper().startswith(("SELECT", "WITH")):
        return None
    with engine.connect() as conn:
        raw = conn.exec_driver_sql(
            f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {sql}", params
        ).scalar()
        conn.rollback()
    plan = raw[0] if isinstance(raw, list) else json.loads(raw)[0]
    return {
        "execution_ms": round(plan["Execution Time"], 2),
        "planning_ms": round(plan["Planning Time"], 2),
        "nodes": plan_summary(plan["Plan"], []),
        "sql": sql,
        "params": params,
    }


def explain_text(engine: Any, plan: dict[str, Any]) -> str:
    """The readable plan of an explained statement (quoted in docs/performance.md)."""
    with engine.connect() as conn:
        rows = conn.exec_driver_sql(f"EXPLAIN (ANALYZE, BUFFERS) {plan['sql']}", plan["params"])
        text_plan = "\n".join(rows.scalars())
        conn.rollback()
    return text_plan


def environment(url: URL) -> dict[str, Any]:
    from app.database.session import get_engine

    def run(command: list[str]) -> str:
        try:
            return subprocess.run(  # noqa: S603  (fixed commands, no input)
                command, capture_output=True, text=True, timeout=30, check=False
            ).stdout.strip()
        except OSError:
            return ""

    info: dict[str, Any] = {
        "when": datetime.now(UTC).isoformat(timespec="seconds"),
        "commit": run(["git", "rev-parse", "--short", "HEAD"]),
        "os": platform.platform(),
        "python": platform.python_version(),
        "cpu": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "memory_gb": _memory_gb(),
        "docker": run(
            [
                "docker",
                "info",
                "--format",
                "{{.ServerVersion}} | {{.OperatingSystem}} | {{.NCPU}} CPUs | {{.MemTotal}} bytes",
            ]
        ),
    }
    if sys.platform == "win32":
        info["cpu"] = (
            run(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).Name"])
            or info["cpu"]
        )
    with get_engine().connect() as conn:
        info["postgres"] = conn.scalar(text("SELECT version()"))
        trips = []
        for _ in range(50):  # the client-to-database round trip, for reading the read times
            t0 = time.perf_counter()
            conn.execute(text("SELECT 1"))
            trips.append((time.perf_counter() - t0) * 1000)
        info["select_1_round_trip_ms"] = round(statistics.median(trips), 2)
        info["postgres_settings"] = {
            name: conn.scalar(text(f"SHOW {name}"))
            for name in (
                "shared_buffers",
                "work_mem",
                "effective_cache_size",
                "max_connections",
                "ssl",
            )
        }
        info["connection_ssl"] = conn.scalar(
            text("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
        )
        info["table_rows"] = {
            table: conn.scalar(text(f"SELECT count(*) FROM {table}"))  # noqa: S608  (constants)
            for table in (
                "raw_events",
                "events",
                "alerts",
                "alert_events",
                "incidents",
                "audit_logs",
            )
        }
        info["database_size"] = conn.scalar(
            text("SELECT pg_size_pretty(pg_database_size(current_database()))")
        )
    info["database"] = url.database
    return info


def _memory_gb() -> float | None:
    if sys.platform == "win32":
        import ctypes

        class Status(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_ulong),
                ("load", ctypes.c_ulong),
                ("total", ctypes.c_ulonglong),
                ("available", ctypes.c_ulonglong),
                ("total_page", ctypes.c_ulonglong),
                ("available_page", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("available_virtual", ctypes.c_ulonglong),
                ("available_extended", ctypes.c_ulonglong),
            ]

        status = Status()
        status.length = ctypes.sizeof(Status)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
        return round(float(status.total) / 2**30, 1)
    try:
        with open("/proc/meminfo", encoding="ascii") as f:
            return round(int(f.readline().split()[1]) / 2**20, 1)
    except OSError:
        return None


def setup_inventory() -> None:
    """The bench admin, two log sources, and an inventory matching the workload's world."""
    from app.context import service as context
    from app.database.session import get_session_factory
    from app.detection.library import get_library
    from app.detection.storage import seed
    from app.ingestion.sources import create_source
    from app.models.user import Role, User
    from app.schemas.context import AssetCreate, IdentityCreate
    from app.schemas.ingestion import SourceCreate
    from app.users.service import create_user
    from benchmarks.workload import make_world

    with get_session_factory()() as db:
        seed(db, get_library())
        db.commit()
        created = create_user(db, "bench@example.com", secrets.token_urlsafe(24), Role.ADMIN)
        admin = db.get(User, created.id)
        if admin is None:
            raise RuntimeError("bench admin missing")
        for name, kind in (("bench linux", "linux_auth"), ("bench windows", "windows_security")):
            create_source(
                db, SourceCreate.model_validate({"name": name, "source_type": kind}), admin
            )
        world = make_world(random.Random(0))  # noqa: S311  (names only)
        criticality = ["low", "medium", "high", "critical"]
        for index, host in enumerate(world.linux_hosts[:200]):
            context.create_asset(
                db,
                AssetCreate.model_validate(
                    {
                        "hostname": host,
                        "asset_type": "server",
                        "environment": "production",
                        "criticality": criticality[index % 4],
                    }
                ),
                admin,
            )
        for index, user in enumerate(world.users):
            level = "privileged" if index % 10 == 0 else "standard"
            identity = IdentityCreate.model_validate({"username": user, "privilege_level": level})
            context.create_identity(db, identity, admin)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--database-url", required=True, help="owner URL of a database named *_bench"
    )
    parser.add_argument("--records", type=int, default=200_000)
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument("--days", type=int, default=7, help="time span of the data, ending now")
    parser.add_argument("--attack-every", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=14)
    parser.add_argument("--fresh", action="store_true", help="drop and recreate the database first")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    url = bench_url(args.database_url)
    prepare_database(url, args.fresh)
    configure_environment(url)

    from alembic import command

    from app.core.config import get_settings
    from app.database.migrations import alembic_config

    get_settings.cache_clear()
    command.upgrade(alembic_config(), "head")
    setup_inventory()

    end = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=1)
    print(f"Loading {args.records:,} records in batches of {args.batch_size} ...", flush=True)
    loaded = load(args, end)
    load_summary = summarize_load(loaded)
    print(f"Loaded: {load_summary['records_per_s']} records/s. Timing reads ...", flush=True)
    read_results = reads(end)

    report = {
        "environment": environment(url),
        "parameters": {k: str(v) for k, v in vars(args).items() if k != "database_url"},
        "load": load_summary,
        "reads": read_results,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    (args.out / f"{stamp}-results.json").write_text(json.dumps(report, indent=2, default=str))
    (args.out / f"{stamp}-batches.json").write_text(json.dumps(loaded["batches"]))
    print(f"Wrote {args.out / f'{stamp}-results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
