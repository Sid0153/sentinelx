"""Correlation under real concurrency (own database, forced interleaving: see
tests/integration/test_alert_concurrency.py)."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.demo.scenarios import generate
from app.incidents import service
from app.ingestion.service import IngestRequest, ingest
from app.models.event import BatchChannel, LogSource
from app.models.incident import Incident, IncidentDisposition, IncidentStatus
from app.models.user import Role, User
from tests.concurrency import WAIT_SECONDS, Factory, Pause, Worker, wait_until_blocked
from tests.helpers import make_user

pytestmark = pytest.mark.integration

START = (datetime.now(UTC) - timedelta(hours=1)).replace(microsecond=0)


def send(factory: Factory, lines: list[str]) -> None:
    with factory() as db:
        source = LogSource(name=f"src-{uuid.uuid4().hex[:8]}", source_type="linux_auth")
        db.add(source)
        db.commit()
        request = IngestRequest(
            source, [line.encode() for line in lines], BatchChannel.API, None, False
        )
        ingest(db, request, get_settings())


def incidents_on(factory: Factory, host: str) -> list[Incident]:
    with factory() as db:
        return list(
            db.scalars(
                select(Incident).where(Incident.hosts.contains([host])).order_by(Incident.number)
            )
        )


def success(host: str, source_ip: str, start: datetime) -> list[str]:
    return generate("brute_force_success", start, host=host, user="deploy", source_ip=source_ip)


def test_a_run_waiting_on_an_incident_the_analyst_resolves_does_not_extend_it(
    scratch: Factory,
) -> None:
    """The analyst holds the incident (row lock) and resolves it. The run that wanted to link a
    new alert to it waits, then sees it resolved: it opens a new incident pointing back."""
    host = f"inc-a-{uuid.uuid4().hex[:6]}"
    send(scratch, success(host, "203.0.113.45", START))
    (first,) = incidents_on(scratch, host)
    with scratch() as setup:
        analyst_id = make_user(setup, Role.ANALYST).id

    with scratch() as db:
        db.scalars(select(Incident).where(Incident.id == first.id).with_for_update()).one()
        later = success(host, "203.0.113.46", START + timedelta(minutes=5))
        run = Worker(lambda: send(scratch, later))
        run.start()
        wait_until_blocked(scratch)
        actor = db.get(User, analyst_id)
        assert actor is not None
        service.transition(
            db,
            first.id,
            IncidentStatus.RESOLVED,
            IncidentDisposition.CONFIRMED_MALICIOUS,
            "Account locked",
            None,
            actor,
        )
    run.finish()

    old, new = incidents_on(scratch, host)
    assert old.id == first.id and old.status == IncidentStatus.RESOLVED
    assert old.alert_count == first.alert_count  # not extended after it was resolved
    assert new.status == IncidentStatus.OPEN and new.related_incident_id == old.id


def test_two_batches_of_one_chain_at_once_make_one_incident(scratch: Factory, pause: Pause) -> None:
    host = f"inc-b-{uuid.uuid4().hex[:6]}"
    lines = generate("multi_stage_attack", START, host=host)
    half = next(i for i, line in enumerate(lines) if "COMMAND=/bin/bash" in line)

    pause.arm()  # the first run creates its alerts, then stops before correlating and committing
    one = Worker(lambda: send(scratch, lines[:half]))
    one.start()
    assert pause.reached.wait(WAIT_SECONDS)
    two = Worker(lambda: send(scratch, lines[half:]))
    two.start()
    wait_until_blocked(scratch)  # the second run waits for the detection lock
    pause.release.set()
    one.finish()
    two.finish()

    (incident,) = incidents_on(scratch, host)
    assert incident.alert_count == 4
