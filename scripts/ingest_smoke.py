"""End-to-end check of ingestion against a running stack (through nginx).

    python3 scripts/ingest_smoke.py http://127.0.0.1:8081 admin@example.com ADMIN_PASSWORD

Creates a log source, sends a small mixed batch as text/plain, resends it, and reads the
batch report, the failed records and the events. Standard library only; every check prints one
line and the first failure exits non-zero. All records are synthetic (RFC 5737 addresses).
"""

import json
import secrets
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

    # Alerts (Phase 7): a brute force on a host of its own, so reruns never share an alert. The
    # outside address differs per run too: the same outside source is one campaign, and a rerun
    # would rightly join the previous run's incident.
    host = f"smoke-{uuid.uuid4().hex[:8]}"
    attacker = f"192.0.2.{secrets.randbelow(254) + 1}"  # a documentation range demos rarely use
    account = f"smoke{secrets.token_hex(3)}"  # nor the account: many sources against one account
    # within minutes is a distributed attack (AUTH-005), and would tie the runs together
    attack = [
        f"{(now - timedelta(seconds=60 - i * 5)).isoformat()} {host} sshd[{2000 + i}]: "
        f"Failed password for {account} from {attacker} port {51000 + i} ssh2"
        for i in range(6)
    ]
    status, batch = client.call("POST", path, "\n".join(attack).encode(), "text/plain")
    check(status == 201 and batch["alerts_created"] == 1, "a brute force creates one alert")
    status, alerts = client.call("GET", f"/api/alerts?host={host}")
    check(status == 200 and alerts["total"] == 1, "the alert is in the queue")
    alert = alerts["items"][0]
    check(alert["rule_id"] == "AUTH-001" and alert["event_count"] == 6, "with its evidence")
    status, again = client.call("POST", path, "\n".join(attack).encode(), "text/plain")
    status, alerts = client.call("GET", f"/api/alerts?host={host}")
    check(alerts["total"] == 1, "resending the same records creates no second alert")
    status, moved = client.json(
        "POST", f"/api/alerts/{alert['id']}/transition", {"status": "TRIAGED"}
    )
    check(status == 200 and moved["status"] == "TRIAGED", "an alert can be triaged")
    check(moved["activity"][-1]["to_status"] == "TRIAGED", "and the change is recorded")

    # Incidents (Phase 8): the same brute force ending in a successful logon is high severity
    # and opens an incident, which the earlier failures join.
    logon = (
        f"{(now - timedelta(seconds=25)).isoformat()} {host} sshd[2100]: "
        f"Accepted password for {account} from {attacker} port 51099 ssh2"
    )
    status, batch = client.call("POST", path, logon.encode(), "text/plain")
    # In a fresh database (CI) this opens an incident. In a busy one the same outside source
    # may already be in an open incident: joining it as the same campaign is also correct.
    correlated = batch["incidents_created"] + batch["incidents_updated"]
    check(status == 201 and correlated == 1, "a successful logon is correlated into an incident")
    status, incidents = client.call("GET", f"/api/incidents?host={host}")
    check(status == 200 and incidents["total"] == 1, "the incident is in the queue")
    incident_id = incidents["items"][0]["id"]
    status, incident = client.call("GET", f"/api/incidents/{incident_id}")
    rules = sorted(a["alert"]["rule_id"] for a in incident["alerts"] if a["alert"]["host"] == host)
    check(
        rules == ["AUTH-001", "AUTH-002"], "the brute force and the logon are one incident", rules
    )
    check(all(a["reason"] for a in incident["alerts"]), "every link says why")
    status, timeline = client.call("GET", f"/api/incidents/{incident_id}/timeline")
    check(status == 200 and len(timeline["items"]) >= 7, "the timeline is rebuilt from events")
    status, note = client.json(
        "POST", f"/api/incidents/{incident_id}/notes", {"body": "Smoke test note."}
    )
    check(status == 201, "an analyst note is added")
    target = "TRIAGED" if incident["status"] == "OPEN" else "RESOLVED"
    body = {"status": target}
    if target == "RESOLVED":
        body.update(disposition="benign_expected", resolution="Smoke test (simulated records)")
    status, moved = client.json("POST", f"/api/incidents/{incident_id}/transition", body)
    check(status == 200 and moved["status"] == target, f"the incident can be moved to {target}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
