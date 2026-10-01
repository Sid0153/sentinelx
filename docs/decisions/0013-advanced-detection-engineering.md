# ADR-0013: Advanced detection engineering: what Phase 12 builds, and what it defers

**Status.** Accepted (Phase 12).

**Context.** The brief asks Phase 12 to "evaluate and implement where justified" a detection
testing playground, rule versioning, false-positive tracking, alert suppression, alert
grouping and advanced temporal correlation, and not to implement anything that compromises
stability. Each item is judged on two questions: does it give an analyst or detection
engineer something they cannot do today, and can it be built without changing how stored
evidence, alerts or incidents behave?

**Decisions.**

| Item | Decision | Why |
|---|---|---|
| Detection testing playground (§44) | **Built** | Detection engineers need to see whether, and why, a rule fires before trusting or tuning it. It runs the real parser, enrichment and evaluator on sample lines and stores nothing, so it cannot affect production data. What-if tuning values go through the same bounds check as a real change (`storage.checked_values`), so a trial cannot use a value a real change would refuse |
| Rule versioning | **Extended** | Versions existed (Phase 6: append-only, audited, with the full definition). Missing was comparing them: the rule page now lists the fields that differ between any two versions. No backend change |
| False-positive tracking (§45) | **Already done** | Phases 7 and 11: false positive with a required reason, who and when, audit, per-rule counts, rate and resolution times. Nothing new is justified |
| Alert suppression | **Built (small)** | Exclusions were permanent. Maintenance windows and announced tests need temporary ones. An exclusion may now carry `active_from` / `active_until` (at most 90 days); only events whose own time is inside the window are ignored. It reuses the exclusion validation, rule versioning and audit, and a suppression cannot quietly become permanent |
| Alert grouping | **Built (view only)** | Incidents group *related* alerts and dedup groups *repeats*, but a burst (41 AUTH-005 alerts from a spray) still floods the queue. The queue can be grouped by rule, host, account or source, with the same filters; each group opens the narrowed queue. Nothing is stored or merged, so dedup and correlation are untouched |
| Advanced temporal correlation | **Deferred** | Correlation already uses time windows, sequences with gaps, and multi-stage chains on a host (ADR-0009, ADR-0012). The next step (chains across hosts: lateral movement) changes which alerts form an incident, the most consequential decision the engine makes, and needs evidence the current log sources do not carry (logon type, session linkage between hosts). Doing it without that evidence would create false links. Recorded in the roadmap as future work |

**Consequences.**
- The playground evaluates only the sample: a new-value rule (AUTH-004) builds its history
  from earlier lines of the same sample; batch scoping and alert dedup do not apply. The page
  says so.
- Suppressed events are still stored and searchable (hunting); only the rule ignores them.
  A suppression is visible on the rule page with its window, and expired ones are labelled.
- Grouping is computed on request over the same indexed filters as the queue (at most 100
  groups listed, the count of all groups given).
