# ADR-0004: Declarative rules and a few evaluator kinds

**Context.** Detections must be testable one at a time, tunable by admins and explainable.
Rule configuration must never become a way to run arbitrary code.

**Options.**
- (a) One Python function per rule.
- (b) Sigma rules with a SQL backend.
- (c) Our own YAML schema, interpreted by five evaluator kinds (single, threshold, distinct,
  sequence, new_value) over a safe condition language.

**Decision.** (c). Sigma was considered. It is the right long-term exchange format for
single-event matching, but its correlation extension is newer and it would add a converter
toolchain. Our field and operator vocabulary stays close to Sigma's, so an import path remains
possible (documented future work).

**Consequences.**
- Adding a rule of an existing kind means one YAML file plus fixtures.
- A new pattern type needs a new evaluator, which is reviewed like any other code.
- Regex (`matches`) is allowed only in rules shipped in the repository. **If admins are ever
  allowed to write patterns, switch to a linear-time regex engine first.**
- Admin changes are limited to the declared tunable fields, within bounds, and are versioned
  and audited.
