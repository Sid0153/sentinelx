# Security model, threat model and Phase 13 review

> Status: **reviewed in Phase 13**. Every control below is implemented and tested unless it is
> marked otherwise; the review findings are listed with what was fixed and what was accepted
> as residual risk. Authentication, authorization and audit logging were built in Phase 3;
> later phases added their own controls, each recorded here.

## Authentication (Phase 3)

- Passwords are hashed with **Argon2id** (`argon2-cffi`). Length policy is 12–128
  characters. There is no public registration: the first ADMIN is created by CLI with a hidden
  prompt.
- **Access token**: JWT (HS256, algorithm pinned on decode, `iss`/`exp`/`iat`/`sub`/`typ`
  required), 15 minutes, kept **in JavaScript memory only** (never in localStorage or
  sessionStorage).
- **Refresh token**: 384-bit random value, stored only as a SHA-256 hash, `httpOnly` +
  `SameSite=Strict` cookie scoped to `/api/auth`, `Secure` in production, **rotated on every
  use**. Each revoked token records why (`ROTATED`, `LOGOUT`, `PASSWORD_CHANGED`,
  `DEACTIVATED`, `REUSE_DETECTED`). Only replaying a **rotated** token counts as theft: every
  session of that user is revoked and `REFRESH_TOKEN_REUSED` is audited.
- Concurrent refreshes never send the same cookie twice (one request per tab, Web Locks
  across tabs), so two open tabs are not mistaken for theft.
- The role is read from the database on every request: a demotion or deactivation takes
  effect immediately.
- Login hardening: one generic error for every failure, a dummy hash check for unknown emails
  (no timing difference), lockout after 5 failures for 15 minutes, a per-IP rate limit. Rate
  limits are counted in PostgreSQL (`rate_limit_counters`, sliding window), so they hold across
  restarts and across several backend instances.
- **Two-factor sign-in** (optional per user, Phase 13; `auth/mfa.py`): TOTP (RFC 6238, SHA-1,
  6 digits, 30 s, one step of drift), checked against the RFC 4226 test vectors. Turning it on
  needs a code from the app; turning it off needs the password **and** a code, so a stolen
  access token alone cannot remove it. A code is accepted once (the last used time step is
  stored). Ten recovery codes, shown once, stored as SHA-256 hashes, each usable once. Wrong
  codes count towards the lockout like wrong passwords. **The TOTP secret is not stored**: it
  is derived from `SECRET_KEY` and a per-user salt, so a database leak alone does not reveal
  anyone's codes (rotating `SECRET_KEY` therefore ends every enrolment).
- **Admin password reset** (Phase 13): a random temporary password (about 120 bits), returned
  once and never stored or logged; the account is unlocked and its sessions end. Until the
  user picks a new password, the API refuses everything except `/api/auth/me` and
  `/api/auth/change-password` (403 `password_change_required`), and the web app shows only the
  change form. Two-factor sign-in stays on through a reset: the temporary password alone does
  not open the account. An admin can also turn two-factor sign-in off for someone who lost
  their device and recovery codes. Neither reset works on the admin's own account.
- **Client IP** for rate limits and audit is never the left-most `X-Forwarded-For` entry
  (`core/client_ip.py`): the header is read only when the direct peer is a trusted proxy, and
  then from the right. Compose gives nginx a fixed address and trusts exactly that; CI sends
  forged headers both through nginx and straight to the backend.
- Users are never deleted, only deactivated. Admins cannot change their own role or status.

### Ingest keys for log shippers (Phase 13)

A log shipper should not hold a person's account. An admin issues a **per-source ingest key**
(`POST /api/sources/{id}/ingest-key`, or `cli issue-ingest-key --source NAME`):

- 256 random bits (`sxk_…`), **shown once**; stored only as its SHA-256 hash plus a short
  prefix for people (a random key needs no slow hash: there is nothing to guess).
- Sent as `X-Ingest-Key` to `POST /api/ingest/{source_id}` and valid **for that source only**;
  it can read nothing. Issuing a new key replaces the old one (rotation); `DELETE` revokes it.
- Issuing, rotating and revoking are audited with the prefix only; every refused key is
  audited (`INGEST_REJECTED`, reason `invalid_ingest_key`, no key material). Each batch records
  the prefix of the key that sent it.
- Tested: a key for one source is refused on another, rotation and revocation end the old key
  at once, the key never appears in logs or audit details (also checked in CI).

## Authorization (Phase 3, extended every phase)

- ADMIN: users, roles, rules, settings, sources and ingest keys, audit log, and everything
  ANALYST can do.
- ANALYST: ingest, triage alerts, work incidents, notes, evidence, saved hunts, the detection
  playground.
- VIEWER: read-only across events, alerts, incidents, rules, assets, identities, dashboard,
  hunting (a hunt only reads). The one exception is the viewer's own account: password change
  and sign-out.
- Enforcement happens in FastAPI dependencies (`require_role`); the frontend only hides
  controls ([ADR-007](decisions/0007-backend-authoritative-rbac.md)). The RBAC matrix test
  fails if any route has no declared access rule, and exercises every route for every role.
- Object-level rules: saved hunts (private to their owner unless shared; shared ones are
  read-only for others; a private hunt is 404 to others), ingest keys (bound to one source).

## Audit logging (Phase 3 onward)

Recorded in the same transaction as the change: login, logout, failed login (client IP only;
the submitted email and password are never stored), lockout, token reuse, access denied, user
and role changes, rule changes (from/to values and reason), settings, sources, ingest keys,
refused ingest, manual detection runs, alert and incident actions (a note by ID, never its
text), saved hunts (name and sharing, never the filters), two-factor changes, password
resets (never the temporary password). `audit_logs` is append-only through database triggers,
and the application's database role cannot even ask to change it (below).

**Tamper evidence (Phase 13).** Triggers stop the application; they do not stop the database
owner. So every new entry is also linked into a **hash chain**: a `BEFORE INSERT` trigger
(under an advisory lock, so concurrent writers cannot fork the chain) gives the entry the next
`seq`, the previous entry's hash as `prev_hash`, and `entry_hash` = SHA-256 over its own fields
and `prev_hash`. Changing, deleting or inserting an entry anywhere breaks every later link.
`cli verify-audit` and `GET /api/audit/integrity` (admin; shown on the audit page) recompute
the chain. To catch an owner who rewrites the **whole** chain consistently, the backend writes
an anchor line (`audit.chained`, sequence and hash) to the application log after each commit;
logs shipped elsewhere keep anchors the owner cannot reach, and
`cli verify-audit --anchor SEQ:HASH` checks the database against one. Entries written before the
chain existed are reported as legacy, not covered.

## Phase 13 review

Each area was reviewed with a method that can fail, not a checklist. Findings were fixed
unless listed as residual risk.

| Area | How it was reviewed | Findings | Result |
|---|---|---|---|
| Threat model | Assets, trust boundaries and attack surfaces re-derived from the code as built (below) | The initial model understated the database risk (next row) and still listed built controls as planned | Rewritten here |
| Database security | Which role the application connects as; what that role can do | **The application connected as the database owner, a superuser in the postgres image**: anything that let an attacker run SQL through the app could disable the append-only triggers and rewrite the audit log | **Fixed:** a least-privilege runtime role (below). Tested with `SET ROLE` against every forbidden operation; CI checks the running app's connections |
| Authorization | RBAC matrix (every route × role); a new review test: every state-changing route needs ANALYST+, or is on a short list with a stated reason | None beyond the matrix: the exceptions are sign-in, session renewal, sign-out, own password change, and the two hunt routes that only read | `test_security_review.py` keeps it so |
| Input validation | Walked every request body model in the OpenAPI schema: unknown fields refused, every string bounded | 11 gaps: login and password-change bodies accepted unknown fields; tags, IP lists, the hunt field name, the relative time range and playground lines had validators but no declared maximum length | **Fixed**, and kept as a test over all 50 request models |
| API security | Body sizes, error bodies, headers, docs, CORS, rate limits | **Only nginx limited request bodies**: a body sent straight to the backend (or behind a misconfigured proxy) was read whole into memory, before authentication, on any POST route. Ingest had no per-source rate limit (listed as planned) | **Fixed:** the backend refuses bodies over 1 MiB (the ingest limit for ingest), by declared length and while streaming, with the standard error shape; per-source ingest rate limit (120/min, `INGEST_RATE_LIMIT_PER_MINUTE`), audited when hit. Errors leak no stack or framework detail; docs are off in production; CORS lists explicit origins only (wildcards refused at startup) |
| Logging | Every log call and the proxy log | The backend logs path without query string, IDs and counts only, never bodies or record content; uvicorn's access log is off. **nginx logged full request URIs**, so the event explorer's filters (usernames, addresses) and hunt definitions reached its log | **Fixed:** nginx logs the path only (`$uri`) with the request ID; CI checks a query value never reaches the log |
| Secrets | gitleaks over the full history and the working tree (CI's pinned version and the latest); configuration validators; what is committed | No secret in any committed file. The latest gitleaks rules flag one false positive in a detection test fixture (a sample `curl` command line) | CI moved to gitleaks v8.30.1 (newer rules) with that fixture allowlisted by exact value. Startup refuses weak `SECRET_KEY`s, wildcard CORS, http origins and DEBUG logging in production |
| Dependencies | `pip-audit` (hash-locked Python), `npm audit`, outdated packages, base images | No known vulnerabilities. Outdated: React 19, Tailwind 4, TypeScript 7 (major upgrades, no advisories). Base images pinned by tag, not digest | **Fixed afterwards** (below): every base image pinned by digest; Dependabot proposes image, npm and Actions updates. Frontend majors remain upgrade work. Phase 15: an image scan (Trivy) found 7, 42 and 22 fixable HIGH vulnerabilities in the backend, frontend and database images; base images updated (nginx moved off its unmaintained 1.29 line), OS packages updated at build time, `gosu` removed from the database image (it runs as postgres from the start), and CI now fails on any fixable HIGH or CRITICAL issue |
| Frontend security | XSS sinks, token storage, external links, CSP | No `innerHTML`/`dangerouslySetInnerHTML`; the token lives in memory only; every external link has `rel="noreferrer noopener"`; log content is rendered as text (tests with script payloads). The CSP allowed `style-src 'unsafe-inline'` with no need: the build has no inline styles, and React's style props go through the CSSOM | **Fixed:** `'unsafe-inline'` removed; checked in the browser (no violations on any page) and in CI |

### Residual risks closed after the review

The review first listed eight residual risks. Each was then fixed, or reduced as far as the
software can reduce it; what remains is stated in the next section.

| Risk as first listed | What was done | Status | Verified by |
|---|---|---|---|
| Rate limits per backend instance, reset by a restart | Sliding-window counters in PostgreSQL (`rate_limit_counters`), shared by every instance; probabilistic cleanup | **Fixed** | 3 integration tests (limit per key and scope; counts shared by two limiter instances, as after a restart or with replicas; the window slides); CI's forged-header test still gets 429 on the 11th attempt |
| No MFA, no password reset | TOTP two-factor sign-in with recovery codes; admin password reset with forced change; admin two-factor reset | **Fixed** (self-service reset by email stays out: there is no mail delivery) | 12 API tests (enrolment, replay, lockout, recovery codes, resets, forced change, no secret in audit details); `scripts/security_smoke.py` against the running stack in CI; 9 UI tests; checked in the browser |
| Base images pinned by tag only | Pinned by digest in both Dockerfiles and Compose; `.github/dependabot.yml` for images, Compose, npm and Actions | **Fixed** (Python packages: already hash-locked, updated by `uv pip compile`, scanned by `pip-audit`) | Images rebuilt from the digests; CI |
| Database connection in Compose not encrypted | A one-shot `db-certs` service issues a private CA and a certificate for `db` (CA key discarded); PostgreSQL requires TLS 1.3 for every network connection (`db/pg_hba.conf`: `hostnossl … reject`); the backend uses `sslmode=verify-full` and holds the CA certificate only | **Fixed** | CI: every application connection is `TLSv1.3`, a plaintext connection is refused, the server key is absent from the backend container; locally also a wrong host name is refused |
| HSTS not sent | nginx sends `Strict-Transport-Security: max-age=31536000; includeSubDomains` | **Fixed** (browsers apply it only over HTTPS, which the TLS proxy in front provides) | CI header check |
| The database owner or operator can rewrite the audit log | Hash chain over the audit log, verification by CLI and API, anchors in the application log | **Mitigated**: tampering becomes detectable, not impossible | 10 integration tests: an edited or deleted entry is found at the right `seq`; a writer cannot choose the hashes; concurrent writers keep one chain; removing the newest entries (invisible to the chain alone) is caught by an anchor; CI verifies the chain on the running stack |
| A compromised log source can inject fake events | Per-source host allowlist (`allowed_hosts`): a record naming another host is refused and stored as FAILED (`host_not_allowed`), so a compromised web server cannot speak for the domain controller | **Mitigated**: a source can still lie about itself | API test; the refused record stays visible in the batch report |
| Secrets inside raw logs | Raw record text is shown to analysts and admins only; viewers get the normalized event with the raw text withheld (event detail, batch records, alert evidence, incident timeline) | **Mitigated**: stored as received (masking would alter evidence) | API tests for all four views and both sides; UI shows "withheld" |

### The least-privilege database role

Migrations run as the database owner (`MIGRATION_DATABASE_URL`). At container start,
`cli setup-app-role` (as the owner) creates or updates the application's role
(`APP_DB_USER`, default `sentinelx_app`): login, no superuser, cannot create databases or
roles, owns nothing. It may SELECT, INSERT, UPDATE and DELETE rows on ordinary tables, and
only SELECT and INSERT on the seven append-only tables (`audit_logs`, `raw_events`, `events`,
`detection_rule_versions`, `incident_notes`, `incident_evidence`, `incident_activity`), a layer
under their triggers. It cannot alter or drop tables, truncate, create objects, disable or drop
triggers, or change its own role; tested statement by statement
(`tests/integration/test_app_role.py`). Every write path of the application (sign-in,
ingestion, detection, alerts, incidents, hunts) was run end to end under the role.

## Threat model

### Assets

1. Stored security events and raw records: evidence integrity and confidentiality (they hold
   usernames, internal addresses, and sometimes secrets typed into command lines).
2. Investigation records (alerts, incidents, notes, audit log): their integrity is the point
   of the product.
3. User accounts, sessions and ingest keys.
4. Detection configuration: an attacker who can disable or blunt a rule becomes invisible.
5. Server secrets (`SECRET_KEY`, database passwords).

### Trust boundaries

```
[Log shippers] ─(ingest key, untrusted content)──────► nginx ─► Backend ─(app role)──► PostgreSQL
[Browser (analyst)] ─(session, untrusted input)──────► nginx ─┘    ▲
[Operator: CLI in the container] ─(trusted)───────────────────────┘    (owner role: migrations
                                                                        and role setup only)
```

Log content is attacker-controlled even when the sender is trusted: anyone who can make a
host write a log line (an SSH login with a crafted username) controls text that SentinelX
parses, stores and shows to analysts.

### Attack surfaces

| Surface | Who can reach it | Controls |
|---|---|---|
| `POST /api/auth/login`, `/refresh`, `/logout`; `GET /api/health`, `/ready` | Anyone | Shared rate limit, lockout (wrong codes count), optional two-factor, generic errors, body limit, rotation and reuse detection |
| `POST /api/ingest/{source}` | Analysts, or that source's ingest key | Key bound to one source, per-source rate limit, 5 MB / 5,000 records / 64 KiB per record, parsers that never crash the batch |
| The rest of the API | Signed-in users by role | RBAC matrix, validated bodies (unknown fields refused, bounded strings), 1 MiB bodies |
| The web app | Anyone (signed in to see data) | CSP without inline scripts or styles, text-only rendering, token in memory |
| Detection rules, playground, hunts | Admins (rules), analysts (playground), everyone (hunts) | Rules are data with allowlisted fields and operators; playground stores nothing; hunts compile to parameterized SQL with a statement timeout |
| The database | The backend (app role), operators (owner) | Least-privilege role, append-only triggers, audit hash chain, TLS 1.3 only for network connections, bound to 127.0.0.1 in Compose |
| The CLI | Operators with container access | Trusted by design (it is the server) |

### Threats and mitigations

| Threat | Mitigation | Phase |
|---|---|---|
| Stored XSS through log content | React text rendering only, never HTML; raw records in `<pre>` as text; CSP `default-src 'self'` without inline scripts or styles; tests with script payloads | 5, 9, 13 |
| Log injection / forging (a newline inside a username faking a second line) | One record is one event; control characters (including NUL) in names rejected; JSON lines keep attacker text in one field; the fingerprint covers the whole raw record | 5 |
| Parser crash or resource exhaustion | Every record ends PARSED, SKIPPED or FAILED; random-byte fuzzing of every parser; bounded regexes; size limits read with a cap; fixed failure codes (reports never echo content) | 5, 14 |
| Memory exhaustion through large bodies | The backend refuses bodies over its limits itself, by declared length and while streaming, before authentication | 13 |
| ReDoS through regex conditions | Regex only in repo-shipped rules, compiled at load, 8 KB input cap; hunts have no regex; the playground runs the same rules | 6, 10, 12 |
| Code execution through rule configuration | Rules are data with a strict schema; allowlisted fields and operators; `yaml.safe_load`; no `eval`/`exec`/`pickle` | 6 |
| Detection tampering (disable a rule, raise a threshold, suppress forever) | ADMIN only; tunable fields within per-rule bounds; reason required; append-only versions with a comparison view; audited with from/to values; disabled rules shown on the rule list and in coverage; suppressions limited to 90 days | 6, 9, 11, 12 |
| Detection evasion through look-alike names | Text comparisons and exclusions fold ASCII case only (Unicode folding would map `ſvc` to `svc`) | 6 |
| Fake evidence from an unauthorized sender | Ingest needs an analyst or that source's key; each batch records who or which key sent it; refused requests audited; a source may speak only for its allowed hosts | 5, 13 |
| Flooding the pipeline | Size and record limits, per-source ingest rate limit, alert dedup (one open alert per activity, database-enforced), evidence and history caps | 5, 7, 13 |
| Hiding activity (closing an alert, unlinking evidence, editing a note) | Analysts only; reasons required; every action is activity and audit, both append-only; notes cannot be edited; closed incidents are final | 7, 8 |
| Evidence tampering in the database | Append-only triggers on seven tables; the application's role cannot disable them and has no UPDATE/DELETE grant on those tables; raw records stored as exact bytes; the audit log is hash-chained with anchors in the application log | 3, 4, 8, 13 |
| SQL injection | SQLAlchemy expressions and bound parameters; hunts compile allowlisted fields; templates are literal reviewed SQL; the two f-string statements interpolate only constants and an integer | 10, 13 |
| Expensive queries | Hunts: 31-day ranges, capped counts, statement timeout; detection: candidate cap | 6, 10 |
| Broken access control | RBAC matrix over every route and role; the write rule; object-level checks for saved hunts and ingest keys | 3+, 13 |
| Session theft | In-memory access token, `httpOnly` `SameSite=Strict` rotated refresh cookie with reuse detection, CSP, HSTS | 3, 13 |
| Credential stuffing and stolen passwords | Rate limit shared by all instances, lockout, generic errors, timing-equal failures, optional two-factor sign-in | 3, 13 |
| Sniffing database traffic | TLS 1.3 with a verified certificate; unencrypted connections refused | 13 |
| Secrets leaking through logs or Git | Env-only config; `.env` ignored; gitleaks over the full history in CI; no bodies, query strings or keys in logs (CI checks every secret against all container logs) | 2, 9, 13 |
| Vulnerable dependencies | Hash-locked Python dependencies, `pip-audit` and `npm audit` in CI, few dependencies | 2, 13 |

### Residual risks (accepted, documented)

What is left after the work above. None of these can be removed by code in this repository.

- **The database owner and the operator** can still disable the triggers and change rows.
  The hash chain makes that **detectable**, not impossible: an owner who rewrites the whole
  chain consistently is caught only by comparing it with an anchor kept outside their reach
  (the application log shipped elsewhere). Entries written before the chain existed are not
  covered. The operator also holds `SECRET_KEY`, from which TOTP secrets are derived.
- **A compromised log source** can still lie about the hosts it is allowed to speak for. The
  allowlist limits the blast radius; it cannot tell whether the host told the truth.
- **Sensitive data inside raw logs** is stored as received and readable by analysts and
  admins. Masking would alter evidence.
- **Two-factor sign-in is optional** per user (no policy to require it for admins yet). The
  two-step answer (`mfa_required`) confirms that a password was right; rate limits and the
  lockout bound how often that can be tried. TOTP codes can be phished in real time like any
  one-time code; WebAuthn would not be. No self-service password reset (no mail delivery).
- **Rotating `SECRET_KEY` ends every two-factor enrolment** (the secrets derive from it):
  users set it up again; an admin can reset anyone locked out.
- **Database TLS uses a private CA made on the host**, valid 825 days and reissued
  automatically within 30 days of expiry. A managed database brings its own certificate:
  point `sslrootcert` at its CA and keep `sslmode=verify-full`. The connection through the
  host port (5433, for tests and `psql`) uses TLS when the client asks for it (libpq's
  default `prefer`), not verified against the CA.
- **HSTS is sent, but only HTTPS makes browsers apply it**; the TLS proxy in front of nginx
  must serve the site over HTTPS. Frontend majors (React 19, Tailwind 4) are behind, with no
  known vulnerability.

## Operating the secrets

| Secret | Where | Rotation |
|---|---|---|
| `SECRET_KEY` | Environment | Change and restart: every access token becomes invalid at once (refresh cookies then renew sessions), and every two-factor enrolment ends (users set it up again) |
| `POSTGRES_PASSWORD` (owner) | Environment | Change in PostgreSQL and in the environment; used only at startup |
| `APP_DB_PASSWORD` (app role) | Environment | Change in the environment and restart: `setup-app-role` sets the new password |
| Ingest keys | Shipper's secret store | `POST /api/sources/{id}/ingest-key` issues a new one and ends the old one immediately |
| User passwords | Argon2id hashes | Users change their own; an admin reset gives a temporary password that must be changed at next sign-in |
| Two-factor | A per-user salt (secret derived from `SECRET_KEY`); recovery codes as SHA-256 hashes | Users turn it off and on again (new key, new codes); admins reset it for a lost device |
| Database TLS certificate | Volumes `db_tls_server` (key, postgres only) and `db_tls_ca` (CA certificate, backend) | Reissued by `db-certs` at start when missing or within 30 days of expiry; force it by removing both volumes |
