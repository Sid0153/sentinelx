# Security model and threat model

> Status: **Implemented and tested:** authentication, authorization and audit logging
> (Phase 3); append-only evidence storage and admin-only context inventory (Phase 4). The
> other controls are planned in the phases shown. The full review is Phase 13, and this
> document becomes the record of what was actually verified.

## Authentication (Phase 3, implemented)

The design reuses the model proven in CloudSentinel (same author), with two improvements
found while building it (revocation reasons and the pinned proxy address, below).
- Passwords are hashed with **Argon2id** (`argon2-cffi`). Length policy is 12–128
  characters. There is no public registration: the first ADMIN is created by CLI with a hidden
  prompt.
- **Access token**: JWT (HS256, algorithm pinned on decode, `iss`/`exp`/`iat`/`sub`/`typ`
  required), 15 minutes, kept **in JavaScript memory only**.
- **Refresh token**: 384-bit random value, stored only as a SHA-256 hash, `httpOnly` +
  `SameSite=Strict` cookie scoped to `/api/auth`, `Secure` in production, **rotated on every
  use**. Each revoked token records *why* (`ROTATED`, `LOGOUT`, `PASSWORD_CHANGED`,
  `DEACTIVATED`, `REUSE_DETECTED`). Only replaying a **rotated** token counts as theft (two
  parties hold a copy): every session of that user is revoked and `REFRESH_TOKEN_REUSED` is
  audited. A token that ended by logout or password change is simply refused, so an old
  browser tab after a logout does not sign the user out everywhere.
- Concurrent refreshes never send the same cookie twice. Within a tab they share one request;
  across tabs the Web Locks API runs them one after another (the second tab then sends the
  already-rotated cookie). Without this, opening two tabs at once could look like theft.
- The role is read from the database on every request, so a demotion or deactivation takes
  effect immediately.
- Login hardening: one generic error for every failure, a dummy hash check for unknown emails
  (no timing difference), lockout after 5 failures for 15 minutes, and a per-IP rate limit.
- Client IP for rate limits and audit is **never** the left-most `X-Forwarded-For` entry
  (`core/client_ip.py`). The header is read only when the direct peer is a trusted proxy
  (`TRUSTED_PROXIES`), and then from the right ("rightmost untrusted"). Compose gives nginx a
  fixed address (172.28.0.10) and trusts exactly that address, so requests that bypass nginx
  (straight to the backend port, arriving from the bridge gateway) cannot choose their
  address either. Counting proxy hops alone, as CloudSentinel first did, would trust a forged
  header on the direct port. CI sends forged headers through both paths and expects the rate
  limit to hold.
- Users are never deleted, only deactivated (their sessions end immediately). Admins cannot
  change their own role or status, so nobody can accidentally lock out the last admin.
- Admin inputs reject unknown fields (`extra="forbid"`): a misspelled field in a user, asset
  or identity change fails with 422 instead of looking like it worked.

## Authorization (Phase 3, extended every phase)

- ADMIN: users, roles, rules, settings, sources, audit log, demo controls, and everything
  ANALYST can do.
- ANALYST: ingest, triage alerts, work incidents, notes, evidence, saved hunts.
- VIEWER: read-only across events, alerts, incidents, rules, assets, identities, dashboard.
  The one exception is the viewer's **own account**: they can change their own password and
  sign out. "Read-only" is about the security data, not about maintaining your own
  credentials. Forbidding it would make an admin handle every password change and leave
  viewers unable to react to a suspected leak, which is weaker, not safer. The route-access
  test pins this (`/api/auth/change-password` is VIEWER-level).
- Enforcement happens in FastAPI dependencies (`require_role`). The frontend only hides
  controls. The RBAC matrix test fails if any route has no declared access rule.
  See [ADR-007](decisions/0007-backend-authoritative-rbac.md).

## Audit logging (Phase 3 onward)

Recorded in the same transaction as the change:
- login, logout, failed login (client IP only; the submitted email and password are never
  stored), lockout, token reuse
- access denied
- user created / role changed / deactivated
- rule change (old → new effective values plus reason)
- settings change
- source change
- ingest rejected
- detection re-run
- alert transition
- incident transition / assignment / note (ID only, not the body) / evidence / link / rename
- demo run / reset

`audit_logs` is append-only through a database trigger. No passwords, tokens or keys go into
`details`, and a redaction helper plus tests enforce that.

## Threat model (initial; completed in Phase 13)

### Assets

1. Stored security events and raw records (evidence integrity and confidentiality: they can
   contain usernames, internal IPs, and sometimes secrets typed into command lines).
2. Investigation records (alerts, incidents, notes, audit log): their integrity is the point
   of the product.
3. User accounts and sessions.
4. Detection configuration: an attacker who can disable a rule is invisible.
5. Server secrets (`JWT_SECRET`, database credentials).

### Trust boundaries

```
[Log sources / shippers] ──(untrusted content)──► Ingest API ─┐
[Browser (analyst)] ──(authenticated, untrusted input)──► API ─┼─► Backend ──► PostgreSQL
[Admin CLI on server] ──(trusted operator)────────────────────┘
```

The key idea: **log content is attacker-controlled even when the sender is trusted.** An
attacker who can make a host write a log line (for example an SSH login with a crafted
username) controls text that SentinelX parses, stores and shows to analysts.

### Threats and mitigations

| Threat | Mitigation | Phase |
|---|---|---|
| Stored XSS through log content (usernames, user agents, command lines rendered in the UI) | React text rendering only, never `dangerouslySetInnerHTML`; raw records in `<pre>` as text; strict CSP (`default-src 'self'`) from nginx; tests with `<script>` / `"><img onerror>` payloads in every parser | 5, 9, 13 |
| Log injection / forging, e.g. a newline inside a username faking a second line | **Implemented:** one input record is one event (a line break inside a record cannot start another); names with control characters (including NUL) are rejected; JSON log lines keep attacker text inside one field; the fingerprint covers the whole raw record | 5 |
| Parser crash or resource exhaustion from malformed input | **Implemented and tested:** every record ends as PARSED, SKIPPED or FAILED, and a parser bug becomes `parser_error` for that record only; random-byte fuzzing of every parser; anchored regexes with bounded repetition (hostile 60 KB lines parse in well under 0.5 s); deep JSON nesting fails cleanly; 5 MB / 5,000-record / 64 KiB-per-record limits, the body read with a cap (not loaded first); failure codes are fixed strings, so reports never echo record content | 5, 14 |
| ReDoS through regex conditions | **Implemented:** regex only in repo-shipped rules (admins can only tune numbers, severity, enabled and exclusions), compiled at load, 8 KB input cap, adversarial-length tests; an invalid pattern stops startup with the file named | 6 |
| Code execution through rule configuration | **Implemented:** rules are data validated by a strict schema (unknown keys refused); field and operator allowlists; `string.Template` with placeholders checked at load; `yaml.safe_load` only; no `eval`/`exec`/`pickle` | 6 |
| Detection tampering (disabling rules, raising thresholds) | **Implemented:** ADMIN only; tunable fields only, within per-rule bounds; reason required; append-only versions; audited with from/to values. **Planned:** UI shows disabled rules prominently | 6, 9, 12 |
| Detection evasion through look-alike names | **Implemented:** text comparisons and exclusions fold ASCII case only. Unicode case folding would map `ſvc` to `svc` (and the Kelvin sign to `k`), letting a crafted account match an allowlist entry | 6 |
| Detection gaps from the SQL prefilter (events silently not evaluated) | **Implemented:** Python decides; the prefilter is proven a superset over awkward stored values (case, Unicode, NULL, JSON types); a rule over the candidate cap is reported, never evaluated on a truncated set | 6 |
| Flooding the pipeline (event flood, alert flood) | Size limits, bounded queries; **implemented (7):** alert dedup (one open alert per activity, database-enforced), evidence cap per alert (1,000 links), history cap (50). **Planned:** per-source rate limit | 5, 7, 13 |
| Hiding activity by closing its alert | **Implemented (7):** only ANALYST+ change status; false positives and reopening need a reason; every change audited with the actor; a closed alert is never re-created by re-runs, but new activity opens a new alert pointing to the closed one, so recurrence stays visible | 7 |
| Unauthorized ingestion (fake evidence) | **Implemented:** ingest needs ANALYST+; each batch records who sent it and through which channel; refused requests are audited (`INGEST_REJECTED`); sources are ADMIN-managed and audited. **Planned (Phase 13):** per-source ingest keys (hashed, one source, ingest only) for log shippers | 5, 13 |
| SQL injection via hunts or filters | Structured queries compile to SQLAlchemy expressions over an allowlisted field set; no string-built SQL | 10 |
| Broken access control (IDOR, missing role check) | RBAC matrix test over every route and role; object-level checks for saved hunts | 3+ |
| Session theft | In-memory access token, `httpOnly` `SameSite=Strict` refresh cookie, rotation plus reuse detection, CSP | 3 |
| Credential stuffing against SentinelX itself | Rate limit, lockout, generic errors | 3 |
| Evidence tampering in the database | Append-only triggers rejecting UPDATE, DELETE **and TRUNCATE** on `audit_logs`, `raw_events`, `events`, `detection_rule_versions` (implemented, tested) and later on notes and activity; raw records stored as exact bytes ([ADR-0010](decisions/0010-evidence-storage.md)); Phase 15 evaluates a separate, less privileged runtime DB role | 3, 4, 8, 15 |
| Secrets leak through logs or Git | Env-only config, `.env` ignored, gitleaks in CI, redaction helper, raw events never logged at INFO | 2, 9, 13 |
| Vulnerable dependencies | Hash-locked Python dependencies, `pip-audit`, `npm audit` in CI, few dependencies | 2, 13 |

### Residual risks (accepted, documented)

- Anyone with database superuser access can defeat the append-only triggers. Triggers protect
  against application bugs and application-level compromise, not a DBA.
- A compromised log source can inject convincing fake events. SentinelX can say who submitted
  a batch, not whether the host told the truth.
- Rate limiting and lockout are per backend instance.
- There is no MFA and no password-reset flow at first.
- Sensitive data inside raw logs (for example a password typed as a username) is stored as
  received. Masking would alter evidence; access is limited by RBAC instead. This is a
  trade-off to revisit.
