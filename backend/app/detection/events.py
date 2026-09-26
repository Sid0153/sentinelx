"""The view of an event that detection works on: plain, immutable data.

Evaluators receive these, never ORM objects or database sessions, so every rule can be tested
with hand-built events and no database (docs/detection-engine.md).

Derived fields combine or reinterpret stored fields for grouping and counting:
- `target_account`: the account acted upon. Windows names it by SID in both 4720 (created)
  and 4732 (added to a group, where the name is usually "-"); Linux by name. Using the SID
  when present links the two Windows events; the name is the fallback.
- `destination`: "ip:port", so NET-001 can count distinct destinations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

DERIVED_FIELDS = frozenset({"target_account", "destination"})


@dataclass(frozen=True)
class DetectionEvent:
    id: str
    timestamp: datetime
    source_type: str
    event_category: str
    event_action: str
    event_outcome: str
    host: str | None = None
    host_ip: str | None = None
    username: str | None = None
    user_domain: str | None = None
    target_username: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    service: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    command_line: str | None = None
    session_id: str | None = None
    message: str | None = None
    source_ip_scope: str | None = None
    asset_criticality: str | None = None
    identity_privileged: bool | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    batch_id: str | None = None  # which ingest batch brought it (to scope batch runs)

    def get(self, name: str) -> Any:
        if name.startswith("attributes."):
            return self.attributes.get(name.split(".", 1)[1])
        if name == "target_account":
            return self.attributes.get("target_sid") or self.target_username
        if name == "destination":
            if self.destination_ip is None:
                return None
            port = self.destination_port
            return self.destination_ip if port is None else f"{self.destination_ip}:{port}"
        return getattr(self, name)


def sort_key(event: DetectionEvent) -> tuple[datetime, str]:
    """Events are ordered by (time, id): ties are broken the same way every time."""
    return event.timestamp, event.id
