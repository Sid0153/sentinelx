"""End-to-end check of ingestion against a running stack (through nginx).

    python3 scripts/ingest_smoke.py http://127.0.0.1:8081 admin@example.com ADMIN_PASSWORD

Creates a log source, sends a small mixed batch as text/plain, resends it, and reads the
batch report, the failed records and the events. Standard library only; every check prints one
line and the first failure exits non-zero. All records are synthetic (RFC 5737 addresses).
"""

import json
import sys
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any


def check(condition: bool, label: str, detail: object = "") -> None:
    print(f"{'ok  ' if condition else 'FAIL'} {label}" + (f" ({detail})" if detail else ""))
    if not condition:
        sys.exit(1)


class Client:
    def __init__(self, base: str) -> None:
        if not base.startswith(("http://", "https://")):
            sys.exit("The base URL must start with http:// or https://")
        self.base = base.rstrip("/")
        self.token: str | None = None

    def call(
        self, method: str, path: str, body: bytes | None = None, content_type: str | None = None
    ) -> tuple[int, Any]:
        # The scheme was checked in __init__ (http/https only), so no file: or custom URLs.
        request = urllib.request.Request(self.base + path, data=body, method=method)  # noqa: S310
        request.add_header("Accept", "application/json")
        if content_type:
            request.add_header("Content-Type", content_type)
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read()
            return error.code, json.loads(raw) if raw else None

    def json(self, method: str, path: str, payload: object) -> tuple[int, Any]:
        return self.call(method, path, json.dumps(payload).encode(), "application/json")


def main(base: str, email: str, password: str) -> None:
    client = Client(base)
    status, body = client.json("POST", "/api/auth/login", {"email": email, "password": password})
    check(status == 200, "sign in as admin", status)
    client.token = body["access_token"]

    name = f"smoke-{uuid.uuid4().hex[:8]}"
    status, source = client.json(
        "POST", "/api/sources", {"name": name, "source_type": "linux_auth"}
    )
    check(status == 201, "create a linux_auth source", status)

    now = datetime.now(UTC).replace(microsecond=0)
    lines = [
        f"{(now - timedelta(seconds=30)).isoformat()} web-01 sshd[1]: Failed password for root "
        "from 203.0.113.45 port 50412 ssh2",
        f"{(now - timedelta(seconds=20)).isoformat()} web-01 sshd[2]: Accepted publickey for "
        "alice from 10.0.2.42 port 52000 ssh2",
        f"{(now - timedelta(seconds=10)).isoformat()} web-01 sshd[1]: Connection closed by "
        "203.0.113.45 port 50412 [preauth]",
        "<script>alert(1)</script> not a syslog line",
    ]
    body_bytes = ("\r\n".join(lines) + "\r\n").encode()
    path = f"/api/ingest/{source['id']}"
    status, batch = client.call("POST", path, body_bytes, "text/plain")
    check(status == 201, "ingest a mixed batch as text/plain", status)
    counts = (batch["parsed_count"], batch["skipped_count"], batch["failed_count"])
    check(counts == (2, 1, 1), "parsed / skipped / failed counted per record", counts)

    status, again = client.call("POST", path, body_bytes, "text/plain")
    check(status == 201 and again["duplicate_count"] == 4, "resending stores nothing new")

    status, failed = client.call(
        "GET", f"/api/ingest/batches/{batch['id']}/records?parse_status=FAILED"
    )
    check(
        status == 200 and failed["items"][0]["parse_detail"] == "unrecognized_format",
        "failed record is kept with its reason",
    )
    check(failed["items"][0]["text"] == lines[3], "raw record is returned as text, unchanged")

    status, events = client.call("GET", f"/api/events?source_id={source['id']}")
    check(status == 200 and len(events["items"]) == 2, "events API returns the parsed events")
    scopes = {e["username"]: e["source_ip_scope"] for e in events["items"]}
    check(scopes == {"root": "external", "alice": "internal"}, "source IPs are classified", scopes)

    status, detail = client.call("GET", f"/api/events/{events['items'][0]['id']}")
    check(status == 200 and detail["raw"]["parse_status"] == "PARSED", "event detail has its raw")

    # Detection (Phase 6): the rules were seeded at startup and ran after the batch.
    check(batch["status"] == "PROCESSED", "detection ran after the batch", batch["status"])
    status, rules = client.call("GET", "/api/detections")
    check(status == 200 and len(rules) == 9, "the rule library is loaded", len(rules))
    window = {"from": (now - timedelta(hours=1)).isoformat(), "to": now.isoformat()}
    status, run = client.json("POST", "/api/detections/run", window)
    check(status == 201 and run["status"] == "COMPLETED", "a manual detection run completes")
    status, runs = client.call("GET", "/api/detections/runs?trigger=manual")
    check(status == 200 and runs["items"][0]["id"] == run["id"], "the run is listed")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
