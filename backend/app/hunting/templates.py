"""Hunt templates: questions a flat filter cannot ask (docs/threat-hunting.md).

Each template is SQL written and reviewed here, with typed parameters bound as parameters,
inside the same time-range bound as every hunt. Analysts choose a template and fill in its
numbers; they never send SQL. Two templates mirror detection rules on purpose (AUTH-002,
AUTH-004): an analyst can see what a rule would have found over a period with other
thresholds before tuning the rule.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import TextClause, text
from sqlalchemy.orm import Session

MAX_ROWS = 200

# Every query below is literal SQL (no string building); parameters are bound (`:name`).
# A logon is what the detection rules call one (AUTH-002/004): category authentication,
# action logon. A "network" is AUTH-004's: /24 for IPv4, /64 for IPv6.


class SuccessAfterFailures(BaseModel):
    model_config = ConfigDict(extra="forbid")
    min_failures: int = Field(default=3, ge=1, le=1000, description="Failed logons before it")
    within_minutes: int = Field(default=10, ge=1, le=1440, description="Looking back from it")


class NewSourceForUser(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lookback_days: int = Field(default=14, ge=1, le=90, description="History to compare with")
    min_history: int = Field(
        default=5, ge=0, le=1000, description="Earlier logons the account needs to be judged"
    )


class RareProcess(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_hosts: int = Field(default=1, ge=1, le=100, description="Seen on at most this many hosts")


class OneSourceManyAccounts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    min_accounts: int = Field(default=5, ge=2, le=10_000, description="Distinct accounts tried")


@dataclass(frozen=True)
class Column:
    key: str
    label: str
    kind: str = "text"  # text | time | number | ip | host | user | process | event | list


@dataclass(frozen=True)
class Template:
    id: str
    name: str
    question: str
    technique: str
    mirrors_rule: str | None
    params: type[BaseModel]
    columns: tuple[Column, ...]
    sql: TextClause


SUCCESS_AFTER_FAILURES = Template(
    id="success_after_failures",
    name="Successful logon after repeated failures",
    question=(
        "Successful logons preceded, for the same account and source, by at least N failed "
        "logons within M minutes."
    ),
    technique="T1110",
    mirrors_rule="AUTH-002",
    params=SuccessAfterFailures,
    columns=(
        Column("timestamp", "Successful logon", "time"),
        Column("username", "Account", "user"),
        Column("source_ip", "Source", "ip"),
        Column("host", "Host", "host"),
        Column("failures", "Failures before", "number"),
        Column("first_failure_at", "First failure", "time"),
        Column("event_id", "Event", "event"),
    ),
    sql=text("""
        SELECT s.id AS event_id, s.timestamp, s.host, s.username,
               host(s.source_ip) AS source_ip, f.failures, f.first_failure_at
        FROM events AS s
        CROSS JOIN LATERAL (
            SELECT count(*) AS failures, min(e.timestamp) AS first_failure_at
            FROM events AS e
            WHERE e.event_category = 'authentication'
              AND e.event_action = 'logon'
              AND e.event_outcome = 'failure'
              AND e.username = s.username
              AND e.source_ip = s.source_ip
              AND e.timestamp >= s.timestamp - make_interval(mins => :within_minutes)
              AND e.timestamp < s.timestamp
        ) AS f
        WHERE s.timestamp BETWEEN :start AND :end
          AND s.event_category = 'authentication'
          AND s.event_action = 'logon'
          AND s.event_outcome = 'success'
          AND s.username IS NOT NULL AND s.source_ip IS NOT NULL
          AND f.failures >= :min_failures
        ORDER BY s.timestamp DESC, s.id DESC
        LIMIT :limit
    """),
)

NEW_SOURCE_FOR_USER = Template(
    id="first_seen_source_for_user",
    name="Logon from a network new for the account",
    question=(
        "Successful logons from a source network (/24, /64 for IPv6) the account did not log "
        "on from in the previous D days, for accounts with at least H earlier logons."
    ),
    technique="T1078",
    mirrors_rule="AUTH-004",
    params=NewSourceForUser,
    columns=(
        Column("timestamp", "Logon", "time"),
        Column("username", "Account", "user"),
        Column("source_ip", "Source", "ip"),
        Column("network", "New network"),
        Column("host", "Host", "host"),
        Column("history", "Earlier logons", "number"),
        Column("event_id", "Event", "event"),
    ),
    sql=text("""
        SELECT * FROM (
            SELECT DISTINCT ON (s.username, sn.net)
                   s.id AS event_id, s.timestamp, s.host, s.username,
                   host(s.source_ip) AS source_ip, sn.net::text AS network, h.history
            FROM events AS s
            CROSS JOIN LATERAL (
                SELECT network(set_masklen(
                    s.source_ip, CASE family(s.source_ip) WHEN 4 THEN 24 ELSE 64 END
                )) AS net
            ) AS sn
            CROSS JOIN LATERAL (
                SELECT count(*) AS history,
                       count(*) FILTER (WHERE network(set_masklen(
                           p.source_ip, CASE family(p.source_ip) WHEN 4 THEN 24 ELSE 64 END
                       )) = sn.net) AS same_network
                FROM events AS p
                WHERE p.event_category = 'authentication'
                  AND p.event_action = 'logon'
                  AND p.event_outcome = 'success'
                  AND p.username = s.username
                  AND p.source_ip IS NOT NULL
                  AND p.timestamp >= s.timestamp - make_interval(days => :lookback_days)
                  AND p.timestamp < s.timestamp
            ) AS h
            WHERE s.timestamp BETWEEN :start AND :end
              AND s.event_category = 'authentication'
              AND s.event_action = 'logon'
              AND s.event_outcome = 'success'
              AND s.username IS NOT NULL AND s.source_ip IS NOT NULL
              AND h.same_network = 0
              AND h.history >= :min_history
            ORDER BY s.username, sn.net, s.timestamp, s.id
        ) AS first_logons
        ORDER BY timestamp DESC, event_id DESC
        LIMIT :limit
    """),
)

RARE_PROCESS = Template(
    id="rare_process_on_host",
    name="Rare process",
    question="Processes seen on at most N hosts in the period.",
    technique="T1059",
    mirrors_rule=None,
    params=RareProcess,
    columns=(
        Column("process_name", "Process", "process"),
        Column("hosts", "Hosts", "list"),
        Column("executions", "Executions", "number"),
        Column("first_seen", "First seen", "time"),
        Column("last_seen", "Last seen", "time"),
    ),
    sql=text("""
        SELECT process_name,
               (array_agg(DISTINCT host) FILTER (WHERE host IS NOT NULL))[1:10] AS hosts,
               count(*) AS executions, min(timestamp) AS first_seen, max(timestamp) AS last_seen
        FROM events
        WHERE timestamp BETWEEN :start AND :end
          AND process_name IS NOT NULL
        GROUP BY process_name
        HAVING count(DISTINCT host) <= :max_hosts
        ORDER BY count(DISTINCT host), count(*), process_name
        LIMIT :limit
    """),
)

ONE_SOURCE_MANY_ACCOUNTS = Template(
    id="one_source_many_accounts",
    name="One source, many accounts",
    question="Sources with failed logons against at least K distinct accounts (password spraying).",
    technique="T1110.003",
    mirrors_rule=None,
    params=OneSourceManyAccounts,
    columns=(
        Column("source_ip", "Source", "ip"),
        Column("accounts", "Accounts", "number"),
        Column("sample_accounts", "Some of them", "list"),
        Column("failures", "Failures", "number"),
        Column("first_seen", "First seen", "time"),
        Column("last_seen", "Last seen", "time"),
    ),
    sql=text("""
        SELECT host(source_ip) AS source_ip, count(DISTINCT username) AS accounts,
               (array_agg(DISTINCT username))[1:10] AS sample_accounts,
               count(*) AS failures, min(timestamp) AS first_seen, max(timestamp) AS last_seen
        FROM events
        WHERE timestamp BETWEEN :start AND :end
          AND event_category = 'authentication'
          AND event_action = 'logon'
          AND event_outcome = 'failure'
          AND source_ip IS NOT NULL AND username IS NOT NULL
        GROUP BY source_ip
        HAVING count(DISTINCT username) >= :min_accounts
        ORDER BY count(DISTINCT username) DESC, count(*) DESC, source_ip
        LIMIT :limit
    """),
)

TEMPLATES: dict[str, Template] = {
    t.id: t
    for t in (SUCCESS_AFTER_FAILURES, NEW_SOURCE_FOR_USER, RARE_PROCESS, ONE_SOURCE_MANY_ACCOUNTS)
}


def run(
    db: Session, template: Template, params: BaseModel, start: datetime, end: datetime
) -> tuple[list[dict[str, Any]], bool]:
    """Rows (at most MAX_ROWS) and whether there were more."""
    values = {**params.model_dump(), "start": start, "end": end, "limit": MAX_ROWS + 1}
    rows = [dict(row) for row in db.execute(template.sql, values).mappings()]
    return rows[:MAX_ROWS], len(rows) > MAX_ROWS
