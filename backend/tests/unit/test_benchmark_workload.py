"""The benchmark's workload measures what it claims (docs/performance.md): it is repeatable,
every record goes through the parsers without failing, ordinary activity triggers nothing by
itself, and every injected attack is detected."""

from collections import Counter
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from app.events.schema import NormalizedEvent, SourceType
from app.ingestion.parsers import ParseContext, ParseFailure, parse_record
from benchmarks.workload import ATTACKS, LINUX, Workload
from tests.detection_helpers import events_from_lines, run_library

START = datetime(2026, 9, 1, tzinfo=UTC)
CONTEXT = ParseContext(received_at=START + timedelta(days=1), timezone=ZoneInfo("UTC"))


def workload(records: int, attack_every: int) -> Workload:
    return Workload(
        seed=14,
        records=records,
        batch_size=500,
        start=START,
        end=START + timedelta(hours=6),
        attack_every=attack_every,
    )


def test_the_same_seed_gives_the_same_records() -> None:
    first = [b.records for b in workload(2000, 1000).batches()]
    second = [b.records for b in workload(2000, 1000).batches()]
    assert first == second
    assert sum(len(r) for r in first) > 2000  # the ordinary records plus two attacks


def test_every_record_parses_and_most_become_events() -> None:
    outcomes: Counter[str] = Counter()
    for batch in workload(3000, 10**9).batches():
        for line in batch.records:
            result = parse_record(batch.source_type, line.encode(), CONTEXT)
            assert not isinstance(result, ParseFailure), (line, result)
            outcomes["event" if isinstance(result, NormalizedEvent) else "skipped"] += 1
    assert outcomes["event"] / sum(outcomes.values()) > 0.85


def test_ordinary_activity_alone_triggers_no_rule() -> None:
    by_source: dict[SourceType, list[str]] = {}
    for batch in workload(6000, 10**9).batches():
        by_source.setdefault(batch.source_type, []).extend(batch.records)
    for source_type, lines in by_source.items():
        found = run_library(events_from_lines(source_type, lines))
        assert found == {}, (source_type, {k: len(v) for k, v in found.items()})


def test_injected_attacks_are_detected() -> None:
    batches = list(workload(4000, 500).batches())
    injected = [name for b in batches for name in b.attacks]
    assert injected == ATTACKS  # one of each, in turn
    linux = [line for b in batches if b.source_type == LINUX for line in b.records]
    windows = [line for b in batches if b.source_type != LINUX for line in b.records]
    found = set(run_library(events_from_lines(LINUX, linux)))
    found |= set(run_library(events_from_lines(batches[1].source_type, windows)))
    assert {"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-005", "PRIV-001", "ACCT-001"} <= found
    assert "PROC-001" in found
