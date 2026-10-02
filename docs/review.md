# Final engineering review (Phase 18)

A complete audit of SentinelX as built, against the brief's list: architecture, code quality,
security, database, detection, correlation, API, frontend, testing, Docker, CI, documentation,
UX, performance and failure handling. Each finding says what was checked, what was found, and
what was done. **Fixed** means changed and verified in this phase. **Accepted** means recorded
with a reason, and listed in [limitations.md](limitations.md) where it affects users.

Reviewed at commit `57c0d28` (Phase 17, green in CI) on 2026-10-02.

## How it was checked

| Area | Method |
|---|---|
| Architecture | Read the module layout against [architecture.md](architecture.md); an AST test of the boundaries it states (new: `tests/unit/test_architecture.py`) |
| Code quality | ruff (including the bandit-derived security rules), `ruff format`, mypy strict; searched for TODO / FIXME; file sizes |
| Security | Cookie and session settings, the RBAC and security-review test suites, dependency audits (pip-audit, npm audit), CI pinning, the git-ignore list, the Phase 13 review in [security.md](security.md) |
| Database | Foreign keys without an index, queried from `pg_catalog` on the running database; migrations against models (`test_schema.py`) |
| Detection, correlation | The test suites (each rule on its scenario, real concurrency, SQL prefilter against Python evaluation); the demo environment's expected results |
| API | `docs/api.md` against the OpenAPI document (new docs test); error shape and body limits (`test_security_review.py`) |
| Frontend, UX | An axe-core WCAG 2.0/2.1 A and AA audit of all 16 pages on the running app; how a rendering error is handled |
| Testing | Coverage per module, with the lines not covered read one by one |
| Docker, CI | Compose files, hardening checks in CI, image scanning, how actions and images are pinned |
| Documentation | Every claim of a number traced to a results file; a search for overclaiming words; the docs test from Phase 17 |
| Performance | [performance.md](performance.md): every figure traced to `docs/benchmarks/` |
| Failure handling | Database outage (CI), detection failure and the reconciler, the demo reset's refusal, the frontend on a broken page |

## Findings

| # | Area | Finding | Severity | Outcome |
|---|---|---|---|---|
| 1 | UX, accessibility | **Contrast below WCAG AA on every page.** axe found 2 failing colour pairs: secondary grey text (`#64748b` on `#0f172a`, 3.75:1) and white on the primary button (`#0284c7`, 4.09:1). AA needs 4.5:1. | High (UX) | **Fixed.** Secondary text is one shade lighter (`slate-400`, about 7:1) and the primary button one shade darker (`sky-700`, about 5.9:1). axe now reports 0 violations on all 16 pages. |
| 2 | Accessibility | The trend charts were `role="img"` with focusable bars inside. An image's children are hidden from screen readers, so keyboard users reached bars that announced nothing (axe: nested-interactive). | Medium | **Fixed.** The chart is a labelled `group`; each bar keeps its spoken values. |
| 3 | Accessibility | Two links differed from the text around them only by colour: incident titles in the queue, and "Rule page" in the playground. | Low | **Fixed.** Underlined. |
| 4 | Failure handling | **No error boundary.** A page that throws while rendering, for example on an unexpected response shape, blanked the whole app, navigation included. | Medium | **Fixed.** Each page renders inside an error boundary keyed by its path. A failed page shows a message and a reload button, and other pages keep working. Tested by rendering the dashboard with a malformed response. |
| 5 | Architecture, docs | **Misleading claim.** The docs said the pure cores (parsers, enrichment, conditions, …) "import no SQLAlchemy", and that the boundaries "will be enforced with tests or review". No test enforced them. `conditions.py` builds SQL expressions (`to_sql`) and `enrich.py` loads its inventory with a session. | Medium | **Fixed.** `tests/unit/test_architecture.py` enforces what is true: 25 pure modules import no database or web framework, take enums only from the models, and never read the clock. The two SQL-aware modules hold no session except `load_snapshot`. RawEvent, Event, Alert, Incident and AuditLog are each built in exactly one module. The docs now say this. |
| 6 | CI, supply chain | GitHub Actions (`checkout`, `setup-python`, `setup-node`) were pinned by moving tag (`@v7`), and the gitleaks image by tag. Trivy was already pinned by digest. A re-pointed tag would run different code in CI with the repository's token. | Medium | **Fixed.** Actions are pinned to full commit SHAs, with the release in a comment, and gitleaks to its image digest. Dependabot keeps proposing updates. The workflow token was already read-only (`contents: read`). |
| 7 | Testing | One parser branch had no test: a generic JSON record claiming its own `source_type`. Reading it showed the parser already drops the claim on purpose. | Low | **Fixed.** A test now states the property: a record cannot claim another source's format. |
| 8 | Database | 17 foreign keys have no index. 11 point at `users` (who acted, wrote or resolved); the others are `events.source_id`, `detection_rule_techniques.technique_id`, two self-references (an alert's previous alert, an incident's related incident), and `incident_evidence`'s alert and event. | Low | **Accepted.** No row in a referenced table is ever deleted. Users are deactivated, not deleted. Events are append-only. Alerts, incidents, sources and techniques have no delete path; the only deletes are of link rows. So no foreign-key check ever scans these columns. No query filters on them either: incident evidence is read by `incident_id`, which is indexed. An index would cost writes for nothing measured. |
| 9 | Testing | The lines not covered are race-condition fallbacks (`IntegrityError` when two requests create the same name at once), the request-session dependency (replaced in tests), and some CLI error prints. Overall line coverage is 98 %. | Low | **Accepted.** The races are proven by database constraints, and the real-concurrency tests cover the cases that matter (alerts, incidents). |
| 10 | Code quality | Large frontend pages: the incident workspace is 820 lines and the rule detail page 633. | Low | **Accepted as debt.** They are organised in sections and tested through the whole app. Splitting them now would be churn without a defect to fix. |
| 11 | Dependencies | Frontend majors behind: React 18 (19 out), Tailwind 3 (4), TypeScript 5 (7), jsdom 25 (30). No known vulnerability: npm audit and pip-audit are clean. | Low | **Accepted as debt**, already listed in [limitations.md](limitations.md). Each major is a migration of its own; Dependabot proposes them. |
| 12 | Docker | No `pids_limit` on the containers. | Low | **Accepted.** Every container already runs non-root, read-only, with no capabilities and a memory limit in production. A process limit is a further hardening step, not a gap that is open to exploitation. |
| 13 | Accessibility, CI | The accessibility audit was a one-off run, not a CI check. | Low | **Accepted.** axe needs a real browser for contrast (jsdom cannot compute it). The way to repeat the audit is recorded below. |

## What was checked and found sound

- **Security.** The refresh cookie is `httpOnly`, `SameSite=Strict`, `Secure` in production and scoped to `/api/auth`. Production disables the API docs and refuses unsafe settings (tested in CI's production job). pip-audit (runtime and dev) and npm audit report nothing. Personal and sensitive files (the brief, `portfolio/`, `.env*`, `backups/`) are git-ignored, and gitleaks scans the full history on every push.
- **Overclaiming.** A search of the README, docs and UI text for "production-ready", "real-time", "enterprise", "machine learning", "AI", "guarantee" and similar found only accurate uses ("not a SIEM", "not an industry standard", "a database guarantee" for a unique index).
- **Numbers.** Every performance figure in the docs traces to a results file in `docs/benchmarks/` (713 records/s is the recorded 712.7).
- **Feature coverage.** Every row of [feature-coverage.md](feature-coverage.md) is ✅ except the Phase 19 portfolio package.
- **Failure handling.** CI covers a database outage (503, then recovery). A detection failure keeps the evidence, and the reconciler flags it. The demo reset refuses a database with real records. Restores go into an empty database.

## Repeating the accessibility audit

Run axe-core 4.10 in a real browser against each page of a running stack, signed in, with
the WCAG 2.0/2.1 A and AA rule sets (`axe.run(document, { runOnly: ["wcag2a", "wcag2aa"] })`).
Phase 18 drove headless Chrome over the DevTools protocol, as `scripts/screenshots.mjs`
does, and found 0 violations on all 16 pages after the fixes above.

## Totals after the review

1,427 backend tests (98 % line coverage) and 117 frontend tests, all passing. Findings: 13 in
all, 7 fixed and 6 accepted with reasons. None of high or medium severity remains.
