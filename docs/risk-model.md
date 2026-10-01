# Priority and risk model

> Status: alert priority **IMPLEMENTED and TESTED (Phase 7)**, `app/risk/priority.py`, model
> version 1; incident risk **IMPLEMENTED and TESTED (Phase 8)**, model version 2; target
> accounts, inventory context display and rescoring **IMPLEMENTED and TESTED (Phase 11)**,
> model version 3.
> See [ADR-005](decisions/0005-explainable-risk-model.md).

This is a **SentinelX-specific** scoring model. It is **not** an industry-standard score (not
CVSS, not a vendor risk score). Its only purpose is to order the queue in a way an analyst can
check by hand. Weights live in one module, and changing any weight bumps `RISK_MODEL_VERSION`,
which is stored with every score.

## Alert priority (0–100)

| Factor | Values → points | Source |
|---|---|---|
| Severity | low 10 · medium 25 · high 40 · critical 55 | Rule (possibly overridden) |
| Confidence | low 0 · medium 8 · high 15 | Rule |
| Asset criticality | low 0 · medium 5 · high 10 · critical 15 · **unknown asset 5** | Current inventory: the assets the evidence events were enriched with, plus any asset their hosts or addresses match now (same rules as enrichment); the most critical one |
| Privileged identity involved | +10 if the actor **or a target account** is privileged; once per alert, the actor named first | Current inventory: identities recorded on the evidence events, plus any matching their usernames (actors) or target usernames (the account a sudo shell runs as, a created account) now. Target accounts are matched at scoring time: enrichment records the actor only |
| Evidence volume | +5 if the largest evidence count of one detection is ≥ 2 × the rule's threshold (distinct rules count distinct values) | Alert (`peak_count`), threshold/distinct rules only |

The score is capped at 100. Bands: **critical ≥ 75**, **high 50–74**, **medium 25–49**,
**low < 25**.

The stored `priority_breakdown` lists every factor with its input value and points. For
example: `severity high +40 · confidence medium +8 · asset web-01 critical +15 · identity deploy
privileged +10 = 73 (high)`, or for a target account `identity root privileged (target account)
+10`. The UI shows it as-is.

The priority always reflects the **current** inventory:
- it is computed when an alert is created and recomputed when a detection extends it;
- when an admin creates an asset or identity, or changes an asset's criticality or addresses
  or an identity's privilege level, the open alerts whose evidence involves it are
  recomputed in the same transaction as the audited change (the audit entry records how many
  changed: `open_alerts_reprioritized`). This includes assets added after the events were
  stored: events never change, so the alert matches their hosts and users against the
  inventory itself.
- open incidents follow: when an alert is scored again, the open incidents it belongs to are
  recomputed in the same transaction (before Phase 11 they kept the old risk; found while
  building the context view, now tested);
- after a model change, `cli rescore` (run at container start) scores every open alert and
  open incident made by an older model again, so the queue is never ordered by two models;
- Closed alerts (resolved, false positive) keep the priority they had when they were handled.

Tested: raising criticality, an asset added later (short host name match), an identity made
privileged, closed alerts and unrelated assets untouched, changes that cannot affect priority
not recomputing; removing the recompute or the host lookup makes a test fail.

## Incident risk (0–100)

`risk = min(100, max(alert priority) + chain bonus + breadth bonus)`

- **Chain bonus**: +5 for each distinct **kind of finding** (rule and indicator) beyond the
  first, up to +15. A brute force, a successful logon, a root shell and a new admin account
  are worse than four alerts of one kind. Tactics were the Phase 1 plan, but one technique can
  span several (T1078 is listed under four), so a single alert would already have scored as a
  chain (ADR-0012).
- **Breadth bonus**: +5 if more than one host is affected, +5 if a privileged identity is
  involved in any alert (only if the top alert did not already count it).

Recomputed whenever an incident's alerts change (a link, an unlink, an extended alert). The
brief's chain on web-01 scores the highest alert plus +15 (tested); every factor, the cap and
the no-double-counting rule are pinned by unit tests.

The same bands and the same breakdown display apply.

## Inputs the brief lists (§9, §16), and how each is used

| Input | Used | How |
|---|---|---|
| Severity | Yes | Points per level (rule, or an admin's override) |
| Confidence | Yes | Points per level |
| Asset criticality | Yes | The most critical asset among the evidence, current inventory |
| Number of events | Yes | +5 when the evidence reaches twice the rule's threshold |
| Affected identities | Yes | A privileged actor or target account; on incidents also one in any alert |
| Correlation strength | Indirectly | Decides whether an alert joins an incident at all (strong or medium links, [correlation.md](correlation.md)); the incident's risk then counts its kinds of finding and breadth. Link strength adds no points: a weak link does not join |
| Authentication context | Indirectly | Through the rules: a success after failures is its own rule (AUTH-002, high severity) |
| Detection category | No | Severity already says how serious a rule's finding is; a category bonus would count the same thing twice |

## Context shown with the score

Alert and incident pages show the inventory behind the hosts and accounts involved: each
asset's criticality, type, environment, owner and tags, each identity's privilege level,
department and role (actor or target), and the hosts and accounts that are **not** in the
inventory (with the note that registering them adds their context to the score). Matched
with the same rules as enrichment (`app/context/lookup.py`).

## What it deliberately does not do

- It uses no machine learning and no hidden weights.
- It has no threat-intelligence reputation factor (there is no feed; NOT IMPLEMENTED).
- It does not decay scores over time. Status reflects the analyst's decision instead.

## Tests

Pure unit tests (`tests/unit/test_priority.py`) pin every factor and band edge (24/25, 49/50,
74/75), the cap at 100 and the documented example. A fingerprint of every weight is recorded
per model version: changing a weight without bumping `RISK_MODEL_VERSION` fails the test.
Integration tests check the stored breakdown with and without inventory context.
