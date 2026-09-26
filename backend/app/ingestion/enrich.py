"""Enrichment: the context SentinelX already holds, attached to each event at ingest time.

Deterministic and explainable (docs/event-model.md):
- source_ip_scope: loopback, link-local, internal (a configured network) or external.
- asset: matched on the event's host (exact name, then its first label), then its host_ip.
- identity: matched on the normalized username.

Criticality and privilege are copied onto the event as snapshots. There is no external threat
intelligence here, and none is pretended.

The inventory is loaded once per batch (`load_snapshot`); `enrich` is then a pure lookup, so a
batch of 5,000 events does not issue 15,000 queries.
"""

import ipaddress
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.client_ip import Network
from app.events.schema import Criticality, IpScope, NormalizedEvent
from app.events.store import Enrichment
from app.models.context import Asset, Identity, PrivilegeLevel


@dataclass(frozen=True)
class AssetRef:
    id: uuid.UUID
    criticality: Criticality


@dataclass(frozen=True)
class IdentityRef:
    id: uuid.UUID
    privileged: bool


@dataclass(frozen=True)
class Snapshot:
    internal_networks: tuple[Network, ...]
    assets_by_host: dict[str, AssetRef] = field(default_factory=dict)
    # Short names ("web-01" for "web-01.corp.example") that belong to exactly one asset.
    assets_by_short_name: dict[str, AssetRef] = field(default_factory=dict)
    assets_by_ip: dict[str, AssetRef] = field(default_factory=dict)
    identities: dict[str, IdentityRef] = field(default_factory=dict)


def load_snapshot(db: Session, internal_networks: tuple[Network, ...]) -> Snapshot:
    by_host: dict[str, AssetRef] = {}
    short_names: dict[str, list[AssetRef]] = {}
    by_ip: dict[str, AssetRef] = {}
    for asset in db.scalars(select(Asset)):
        ref = AssetRef(asset.id, Criticality(asset.criticality))
        by_host[asset.hostname] = ref
        short_names.setdefault(asset.hostname.split(".", 1)[0], []).append(ref)
        for ip in asset.ip_addresses:
            by_ip.setdefault(str(ip), ref)  # an address listed twice: the first asset wins
    identities = {
        identity.username: IdentityRef(
            identity.id, identity.privilege_level == PrivilegeLevel.PRIVILEGED
        )
        for identity in db.scalars(select(Identity))
    }
    return Snapshot(
        internal_networks=internal_networks,
        assets_by_host=by_host,
        assets_by_short_name={
            name: refs[0] for name, refs in short_names.items() if len(refs) == 1
        },
        assets_by_ip=by_ip,
        identities=identities,
    )


def ip_scope(value: str | None, internal: tuple[Network, ...]) -> IpScope | None:
    if value is None:
        return None
    ip = ipaddress.ip_address(value)
    if ip.is_loopback:
        return IpScope.LOOPBACK
    if ip.is_link_local:
        return IpScope.LINK_LOCAL
    if any(ip.version == net.version and ip in net for net in internal):
        return IpScope.INTERNAL
    return IpScope.EXTERNAL


def _asset_for(event: NormalizedEvent, snapshot: Snapshot) -> AssetRef | None:
    if event.host:
        if found := snapshot.assets_by_host.get(event.host):
            return found
        # "web-01.corp.example" in a log, "web-01" in the inventory (or the other way round).
        short = event.host.split(".", 1)[0]
        if found := snapshot.assets_by_host.get(short) or snapshot.assets_by_short_name.get(short):
            return found
    if event.host_ip:
        return snapshot.assets_by_ip.get(event.host_ip)
    return None


def enrich(event: NormalizedEvent, snapshot: Snapshot) -> Enrichment:
    asset = _asset_for(event, snapshot)
    identity = snapshot.identities.get(event.username) if event.username else None
    return Enrichment(
        source_ip_scope=ip_scope(event.source_ip, snapshot.internal_networks),
        asset_id=asset.id if asset else None,
        asset_criticality=asset.criticality if asset else None,
        identity_id=identity.id if identity else None,
        identity_privileged=identity.privileged if identity else None,
    )
