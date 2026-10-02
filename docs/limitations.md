# Limitations

What SentinelX does not do, and where it would fail. Each item links to the document with
the detail. The project's rule: a technically honest limitation is better than a fake
capability.

## Scope

- **A lab-scale SOC platform, not a SIEM.** One host, one PostgreSQL instance, one backend
  process. Measured: 713 records/s through the full pipeline on a laptop, flat up to 1
  million records ([performance.md](performance.md)). Enterprise ingest rates (tens of
  thousands of events per second) would need the changes in
  [future-architecture.md](future-architecture.md).
- **Five log formats**: Linux auth.log, Windows Security events as JSON, nginx/Apache access
  logs, application JSON and generic JSON ([event-model.md](event-model.md)). No syslog
  receiver, no Windows Event Forwarding, no cloud audit logs, EDR or identity-provider logs.
  Each new source needs a parser, fixtures and tests.
- **Nine detection rules mapping to 12 ATT&CK techniques** (v19.2). The coverage view says
  "implemented coverage" on purpose: it shows what the rules see, not what an attacker can
  do unseen ([mitre.md](mitre.md)).
- **Every attack in the project is simulated.** Records are generated, labelled SIMULATED
  and sent through the real pipeline ([demo.md](demo.md), ADR-0006). SentinelX has not been
  run against a real environment's logs.
- **No machine learning, no anomaly detection** beyond the rule-based "new value" rule
  (AUTH-004), and no threat-intelligence feeds.

## Detection

Per-rule weaknesses are in [detection-engine.md](detection-engine.md) and each rule's YAML:
- Thresholds have a "just under" zone: a slow brute force or a slow port scan stays below
  them.
- Distributed attacks evade the per-source rules. AUTH-005 covers one account attacked from
  many sources, not many accounts attacked from many sources.
- AUTH-004 is noisy on VPN and DHCP changes (an address is not a location) and does not judge
  accounts with fewer than 5 earlier logons.
- PROC-001 is pattern matching: unknown obfuscation and download-then-run split over two
  commands get through.
- Rules only see what the logs carry: Linux commands run without sudo are invisible without
  auditd, and Windows command lines need 4688 with command-line auditing.

## Correlation

- Alerts join an incident when they share a host and an account, a host and a source, an
  outside address, or follow access on the same host. Lateral movement chains across hosts
  are **not** correlated: that needs session linkage the current sources do not carry, and
  guessing would create false links ([ADR-0013](decisions/0013-advanced-detection-engineering.md)).
- Incidents are never merged automatically; an analyst links alerts by hand
  ([correlation.md](correlation.md)).
- A lone low or medium alert does not open an incident by design, so a slow multi-stage attack
  whose stages are more than the correlation window (2 hours by default) apart is several
  alerts until an analyst connects them.

## Threat hunting

- Structured queries over the event store, not a query language: substring and trigram
  matching, no full-text relevance, no aggregation language, at most 31 days per hunt, counts
  stop at 10,000 ([threat-hunting.md](threat-hunting.md)).
- The "success after failures" template takes about 1.1 s over 7 days at 1 million records.
  The other hunts measured take 11–23 ms ([performance.md](performance.md)).

## Data and operations

- **No retention policy.** Events and the audit log grow until an operator acts. Monthly
  partitioning and a retention job are designed but not built
  ([database-schema.md](database-schema.md#growth-plan-documented-not-built)).
- **One host.** No high availability. Recovery is a restore from a backup on another host;
  the backups are snapshots, so data since the last backup is lost
  ([deployment.md](deployment.md), [ADR-0014](decisions/0014-single-host-compose-deployment.md)).
- **Detection runs one at a time** (an advisory lock), so throughput does not grow with more
  senders.
- **Ingestion is synchronous.** A sender waits for its batch to be stored and detected. A
  burst larger than the API can absorb is refused (rate limits, 413), not queued.
- **The demo reset takes the site down** for about 40 s, and it replaces the whole database
  ([ADR-0015](decisions/0015-demo-environment-reset.md)).

## Security

Residual risks are listed with their reasons in [security.md](security.md#residual-risks-accepted-documented):
- The database owner can disable the append-only triggers. The audit hash chain makes a
  rewrite detectable against an anchor kept elsewhere, not impossible.
- A compromised log source can lie about the hosts it is allowed to speak for.
- Raw logs are stored as received, including any sensitive data they contain (masking would
  alter evidence). Raw text is readable by analysts and admins, not viewers.
- Two-factor sign-in is optional per user, and there is no WebAuthn and no self-service
  password reset.

## Product

- No notifications (mail, chat, webhooks) when an alert or incident is created.
- No case management beyond incidents: no tickets, SLAs or integrations with external tools.
- No multi-tenancy. One organisation per deployment.
- The demo is loaded and reset from the command line, not from the UI.
- Log sources and their ingest keys are managed with the CLI or the API, not the UI.
- The frontend uses React 18 and Tailwind 3; the newer majors are upgrade work (no known
  vulnerability).
