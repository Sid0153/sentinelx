# ADR-0005: Explainable, versioned additive priority model

**Context.** Analysts need a queue order they can trust and check by hand.

**Options.**
- (a) Severity only.
- (b) An opaque or machine-learning score.
- (c) A documented additive score that stores its breakdown per factor.

**Decision.** (c).
- Alerts: severity + confidence + asset criticality + privileged identity + evidence volume.
- Incidents: the highest alert priority plus bonuses for tactic chains and breadth.
- It is called the "SentinelX priority score", never an industry standard.
- The weights live in one module, and `RISK_MODEL_VERSION` is stored with every score.

See [risk-model.md](../risk-model.md).

**Consequences.** Every number on screen can be recomputed by hand. The weights are
judgement calls and are stated openly. Tests pin the band edges, so any weight change is
deliberate.
