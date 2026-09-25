"""Which address a request came from, for rate limits and the audit log.

Proxies append to X-Forwarded-For, so its left part is whatever the client chose to send.
Entries are therefore read from the right, and only while they were written by one of our own
proxies ("rightmost untrusted"):

1. If the direct peer is not a trusted proxy, it is the client. Its headers mean nothing.
   This covers requests that bypass nginx, e.g. straight to the backend port.
2. Otherwise walk X-Forwarded-For from the right: every address inside a trusted network is
   another proxy hop; the first one outside is the client. Entries further left are never
   read, so forged ones cannot matter.

Docker Compose gives nginx a fixed address and TRUSTED_PROXIES names exactly that address,
not the whole network: the host's port mapping also arrives from inside the network (the
bridge gateway), and it must not be trusted.
"""

import ipaddress
from ipaddress import IPv4Network, IPv6Network

from starlette.datastructures import Headers

Network = IPv4Network | IPv6Network


def parse_networks(value: str) -> tuple[Network, ...]:
    """'172.28.0.10/32, fd00::/8' -> networks. Raises ValueError on bad input."""
    return tuple(
        ipaddress.ip_network(token, strict=True)
        for token in (part.strip() for part in value.split(","))
        if token
    )


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _is_trusted(address: str, networks: tuple[Network, ...]) -> bool:
    ip = ipaddress.ip_address(address)
    return any(ip.version == network.version and ip in network for network in networks)


def _forwarded_for(headers: Headers) -> list[str]:
    return [
        entry.strip()
        for line in headers.getlist("x-forwarded-for")
        for entry in line.split(",")
        if entry.strip()
    ]


def resolve_client_ip(
    peer: str | None, headers: Headers, trusted_networks: tuple[Network, ...]
) -> str | None:
    """The client address, or the direct peer if nothing trustworthy says otherwise."""
    peer_ip = _valid_ip(peer) if peer else None
    if peer_ip is None or not trusted_networks or not _is_trusted(peer_ip, trusted_networks):
        return peer
    closest = peer_ip
    for entry in reversed(_forwarded_for(headers)):
        address = _valid_ip(entry)
        if address is None:
            # Our proxies write valid addresses, so this was written by the client: the
            # closest address to its right is the best we know.
            return closest
        if not _is_trusted(address, trusted_networks):
            return address
        closest = address
    return closest  # every hop is a proxy (a request from inside the proxy network)
