# ADR-0012: Correlation links new kinds of finding on the same host; stages are findings, not tactics

**Status.** Accepted (Phase 8). Refines [ADR-0009](0009-entity-based-incident-correlation.md);
[correlation.md](../correlation.md) describes the result.

**Context.** ADR-0009 links alerts to incidents by shared entities: host and user, host and
source, or an outside source. Building it on real log formats showed two problems.

1. The brief's own example chain (brute force, successful logon, privilege event, new privileged
   account) did not become one incident. The account-creation records (`useradd`, `usermod`,
   Windows 4720/4732) name the new account but not who created it, so the ACCT-001 alert shares
   only the host with the rest of the chain: a WEAK link under ADR-0009.
2. ATT&CK tactics were planned as the measure of "attack stages", both for linking and for the
   incident risk's chain bonus. But one technique can span several tactics: T1078 (Valid
   Accounts) is listed under Stealth, Persistence, Privilege Escalation and Initial Access. A
   single successful-logon alert would already look like a four-stage chain, and after it any
   Persistence or Privilege Escalation finding would look like a stage the incident already had.

**Options.**
- (a) Keep host-only links WEAK and accept that the chain splits.
- (b) Link on the host alone within a short window (merges unrelated alerts on busy hosts).
- (c) Link on the host within a short "sequence" window only when the incident already shows
  **access** on that host (a foothold: a finding mapped to Initial Access or Privilege
  Escalation whose evidence includes a successful event) and the alert is a **new kind of
  finding** (an ATT&CK technique the incident does not have yet) starting at or after that
  access. Measure stages for risk by distinct kinds of finding (rule and indicator), not by
  tactics.

**Decision.** (c).
- New link row: *same host where the incident shows access + a technique the incident does
  not have + starting at or after that access + within the sequence window (default 30 min,
  admin-tunable 5–240 min)* → MEDIUM. Without a foothold on the host, or before it, sharing a
  host stays WEAK: two unrelated findings on a busy host are not merged, and neither are two
  brute forces from different sources (same technique). A refused sudo is not a foothold.
  (A first version linked any new technique on the host in either direction, without the
  access condition; it was tightened before release because it over-merged on busy hosts.)
- The incident risk's chain bonus counts distinct kinds of finding (+5 each beyond the first,
  at most +15). Risk model version 2.
- Also decided while building: the alert that opens an incident is recorded with strength
  `ORIGIN` (it was not linked by overlap); an alert unlinked by an analyst is never linked back
  to that incident by the engine; a low or medium alert opens an incident only together with a
  partner it links to STRONG or MEDIUM (ADR-0009 required the partner to come from a different
  rule; with (c) a same-rule partner can only link through an outside source across hosts,
  which is the campaign case the design wanted to catch).

**Consequences.**
- The brief's chain is one incident, whether its records arrive in one batch or four (tested).
- A finding that follows a foothold on a host within 30 minutes is linked even if an unrelated
  person caused it. The link says why ("On web-01, after the access the incident shows there
  …: a new kind of finding (T1136.001), 93 s apart"), and an analyst can unlink it; the engine
  then leaves it alone.
- Correlation also re-examines standalone alerts: every changed incident is swept for open
  alerts that now belong with it, and manual detection runs correlate the standalone alerts in
  their range (backfill).
- Tactics are still stored and shown on incidents; they no longer drive linking or risk.
