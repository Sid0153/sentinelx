"""What makes two detections "the same activity" (pure).

The deduplication key is the rule, the indicator (for rules with several, such as PRIV-001:
a root shell and a refused sudo are different findings) and the rule's grouped values. The
same brute force from the same source against the same account on the same host has one
key, however many runs and batches report it.
"""

import hashlib
import json
from typing import Any

SEPARATOR = "\x1f"


def dedup_key(rule_id: str, indicator: str | None, group: dict[str, Any]) -> str:
    values = json.dumps({k: str(v) for k, v in sorted(group.items())}, sort_keys=True)
    material = SEPARATOR.join((rule_id, indicator or "", values))
    return hashlib.sha256(material.encode()).hexdigest()


def title(rule_name: str, indicator_name: str | None, group: dict[str, Any]) -> str:
    """`Repeated SSH authentication failures (203.0.113.45, web-01, root)`"""
    name = f"{rule_name}: {indicator_name}" if indicator_name else rule_name
    values = ", ".join(str(v) for v in group.values())
    text = f"{name} ({values})" if values else name
    return text[:300]
