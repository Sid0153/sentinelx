# Priority and risk model

> Status: **DESIGN (Phase 1)**. Alert priority: Phase 7. Incident risk and context: Phase 11.
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
| Asset criticality | low 0 · medium 5 · high 10 · critical 15 · **unknown asset 5** | Current asset record |
| Privileged identity involved | +10 if actor or target identity is privileged | Current identity record |
| Evidence volume | +5 if `event_count ≥ 2 × threshold` (threshold/distinct rules only) | Alert |

The score is capped at 100. Bands: **critical ≥ 75**, **high 50–74**, **medium 25–49**,
**low < 25**.

The stored `priority_breakdown` lists every factor with its input value and points. For
example: `severity high +40 · confidence medium +8 · asset web-01 critical +15 · identity deploy
privileged +10 = 73 (high)`. The UI shows it as-is.

## Incident risk (0–100)

`risk = min(100, max(alert priority) + chain bonus + breadth bonus)`

- **Chain bonus**: +5 for each distinct ATT&CK tactic beyond the first across linked alerts,
  up to +15. Credential Access → Privilege Escalation → Persistence is worse than three
  alerts from one tactic.
- **Breadth bonus**: +5 if more than one host is affected, +5 if a privileged identity is
  affected (only if not already counted in the top alert).

The same bands and the same breakdown display apply.

## What it deliberately does not do

- It uses no machine learning and no hidden weights.
- It has no threat-intelligence reputation factor (there is no feed; NOT IMPLEMENTED).
- It does not decay scores over time. Status reflects the analyst's decision instead.

## Tests

Pure unit tests pin every factor and band edge (24/25, 49/50, 74/75). A golden test fails if
weights change without bumping `RISK_MODEL_VERSION`.
