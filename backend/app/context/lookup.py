"""The inventory behind the hosts and accounts an alert or incident involves (brief §16-18):
what the analyst needs next to the score, such as how critical the host is, who owns it, and
whether the account is privileged. Matched against the current inventory with the same rules
as enrichment: exact hostname, or the short name ("web-01" for "web-01.corp.example") when
only one asset has it; exact username."""

from collections.abc import Iterable
from dataclasses import dataclass, field

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.context import Asset, Identity


@dataclass
class InventoryContext:
    assets: list[Asset] = field(default_factory=list)
    identities: list[tuple[Identity, list[str]]] = field(default_factory=list)  # with roles
    unknown_hosts: list[str] = field(default_factory=list)
    unknown_accounts: list[str] = field(default_factory=list)


def _short(hostname: str) -> str:
    return hostname.split(".", 1)[0]


def inventory_context(
    db: Session, hosts: Iterable[str], actors: Iterable[str], targets: Iterable[str]
) -> InventoryContext:
    hosts, actors, targets = sorted(set(hosts)), set(actors), set(targets)
    result = InventoryContext()
    if hosts:
        shorts = sorted({_short(h) for h in hosts})
        candidates = list(
            db.scalars(
                select(Asset).where(
                    or_(
                        Asset.hostname.in_(hosts),
                        func.split_part(Asset.hostname, ".", 1).in_(shorts),
                    )
                )
            )
        )
        by_short: dict[str, list[Asset]] = {}
        for candidate in candidates:
            by_short.setdefault(_short(candidate.hostname), []).append(candidate)
        matched: dict[str, Asset] = {}
        for host in hosts:
            exact = next((a for a in candidates if a.hostname == host), None)
            short = by_short.get(_short(host), [])
            asset = exact or (short[0] if len(short) == 1 else None)
            if asset is None:
                result.unknown_hosts.append(host)
            else:
                matched[str(asset.id)] = asset
        result.assets = sorted(matched.values(), key=lambda a: a.hostname)
    accounts = sorted(actors | targets)
    if accounts:
        found = {
            i.username: i
            for i in db.scalars(select(Identity).where(Identity.username.in_(accounts)))
        }
        for username in accounts:
            identity = found.get(username)
            if identity is None:
                result.unknown_accounts.append(username)
                continue
            roles = [
                r for r, names in (("actor", actors), ("target", targets)) if username in names
            ]
            result.identities.append((identity, roles))
    return result
