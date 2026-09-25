# Repository assessment (Phase 1)

The brief asks Phase 1 to start by inspecting the existing repository instead of assuming it is
empty. This records what was found on 2026-09-25 and what was decided.

## What existed

| Location | Finding | Consequence |
|---|---|---|
| `C:\sentinelx` | Did not exist. No SentinelX code, docs or history anywhere on the machine. | Nothing to migrate or overwrite; a new repository was created (after asking the user where SentinelX should live). |
| `C:\cloudsentinel` | A **separate, finished project** by the same author: an AWS security-posture scanner (FastAPI, SQLAlchemy/Alembic, PostgreSQL, React/Vite/Tailwind, Docker Compose, GitHub Actions), 12 phases done, green in CI, deployed publicly. | Not a starting point to extend: a different product (cloud configuration findings, not event detection). Building SentinelX inside it would mix two products, their CI and their deployment. |

Options offered to the user: new repository (recommended), inside CloudSentinel, or replace
CloudSentinel. The user chose a **new repository at `C:\sentinelx`**.

## What was reused from CloudSentinel, and how

Reuse is by **copying and adapting**, not a shared package. Two products coupled through a
library would force releases in lockstep for code of a few hundred lines. Each reused part
was chosen because it was already proven in CI and in a live deployment:

| Reused | Adapted for SentinelX |
|---|---|
| Settings validation (no secret defaults, production lock-down) | Same approach; SentinelX-specific fields |
| Argon2id passwords, JWT access token, rotating refresh cookie | Refresh tokens record *why* they were revoked, so only a replayed **rotated** token counts as theft (CloudSentinel treated a post-logout refresh the same way) |
| Append-only audit log with DB triggers | Shared `reject_modification()` trigger function (future append-only tables reuse it); `result` includes `DENIED` |
| Route-access test (every route × every role) | Unchanged idea; lists every SentinelX route |
| Client-IP resolution (rightmost untrusted) | Proxy trust is limited to nginx's pinned address, so requests to the direct backend port cannot forge `X-Forwarded-For` |
| Hash-locked dependencies, pip-audit / npm audit, gitleaks, Compose hardening checks in CI | Same tooling; stricter `ruff format --check` because SentinelX started format-clean |

What was **not** reused: CloudSentinel's AWS collectors, rule engine and risk model. Its rules
evaluate one resource's configuration at a time (PASS/FAIL/UNKNOWN). SentinelX detects
patterns across many events over time (thresholds, sequences, windows), which is a different
engine ([detection-engine.md](detection-engine.md)).

## State at the end of Phase 1

Design documents only: architecture, event model, detection engine, correlation, risk model,
ATT&CK mapping (verified against attack.mitre.org, v19.2), database design, API plan, security
and threat model, testing strategy, roadmap, and nine ADRs. No application code.
