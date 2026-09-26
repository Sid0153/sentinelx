import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.client_ip import parse_networks
from app.events.schema import Criticality, EventCategory, IpScope, NormalizedEvent, SourceType
from app.ingestion.enrich import AssetRef, IdentityRef, Snapshot, enrich, ip_scope

INTERNAL = parse_networks("10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7")
WEB = AssetRef(uuid.uuid4(), Criticality.CRITICAL)
DB = AssetRef(uuid.uuid4(), Criticality.HIGH)
ALICE = IdentityRef(uuid.uuid4(), privileged=True)


def event(**fields: Any) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 9, 25, tzinfo=UTC),
        source_type=SourceType.LINUX_AUTH,
        event_category=EventCategory.AUTHENTICATION,
        event_action="logon",
        **fields,
    )


SNAPSHOT = Snapshot(
    internal_networks=INTERNAL,
    assets_by_host={"web-01.corp.example": WEB, "db-01": DB},
    assets_by_short_name={"web-01": WEB, "db-01": DB},
    assets_by_ip={"10.0.1.30": DB},
    identities={"alice": ALICE},
)


@pytest.mark.parametrize(
    ("ip", "scope"),
    [
        ("10.0.2.42", IpScope.INTERNAL),
        ("192.168.1.10", IpScope.INTERNAL),
        ("172.31.0.1", IpScope.INTERNAL),
        ("fd12::1", IpScope.INTERNAL),
        ("127.0.0.1", IpScope.LOOPBACK),
        ("::1", IpScope.LOOPBACK),
        ("169.254.10.1", IpScope.LINK_LOCAL),
        ("203.0.113.45", IpScope.EXTERNAL),  # documentation range: treated like the internet
        ("8.8.8.8", IpScope.EXTERNAL),
        ("172.32.0.1", IpScope.EXTERNAL),  # just outside 172.16.0.0/12
    ],
)
def test_ip_scope(ip: str, scope: IpScope) -> None:
    assert ip_scope(ip, INTERNAL) == scope


def test_no_ip_means_no_scope() -> None:
    assert ip_scope(None, INTERNAL) is None


def test_asset_matches_exact_name_then_short_name_then_ip() -> None:
    assert enrich(event(host="web-01.corp.example"), SNAPSHOT).asset_id == WEB.id
    assert enrich(event(host="web-01"), SNAPSHOT).asset_id == WEB.id  # inventory has the FQDN
    assert enrich(event(host="db-01.corp.example"), SNAPSHOT).asset_id == DB.id  # log has FQDN
    assert enrich(event(host_ip="10.0.1.30"), SNAPSHOT).asset_id == DB.id
    assert enrich(event(host="unknown-99"), SNAPSHOT).asset_id is None


def test_enrichment_snapshot_values() -> None:
    result = enrich(event(host="web-01", username="alice", source_ip="203.0.113.45"), SNAPSHOT)
    assert result.asset_criticality == Criticality.CRITICAL
    assert (result.identity_id, result.identity_privileged) == (ALICE.id, True)
    assert result.source_ip_scope == IpScope.EXTERNAL


def test_unknown_user_and_host_stay_empty() -> None:
    result = enrich(event(username="mallory"), SNAPSHOT)
    assert (result.identity_id, result.identity_privileged, result.asset_id) == (None, None, None)
