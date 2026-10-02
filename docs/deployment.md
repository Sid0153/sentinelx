# Deployment

> Status: **Phase 15.** SentinelX runs on one host with Docker Compose, without any paid cloud
> service. Two configurations share the same images: **development** (`docker-compose.yml`:
> plain http on 127.0.0.1, API docs on) and **production** (plus `docker-compose.prod.yml`:
> https, production settings, only the site published). CI starts both and runs the end-to-end
> checks against each, including a backup, the loss of the database and a restore.

## What runs

| Service | Image | Role | Published (development / production) |
|---|---|---|---|
| `db` | `db/Dockerfile`: PostgreSQL 16 (official Alpine image, OS packages updated, `gosu` removed) | Events, alerts, incidents, users, audit log | 127.0.0.1:5433 / not published |
| `backend` | `backend/Dockerfile`: Python 3.12, FastAPI, uvicorn | The API; runs migrations and checks its configuration at start | 127.0.0.1:8001 / not published |
| `frontend` | `frontend/Dockerfile`: the React build served by nginx (unprivileged) | The web app; proxies `/api` to the backend | 127.0.0.1:8081 (http) / `SITE_PORT` https, `HTTP_PORT` redirect |
| `db-certs` | Python slim (pinned), runs `db/make-certs.sh` once | TLS certificate for the database (name `db`) | none |
| `site-certs` (production) | same | TLS certificate for the site (`SITE_NAMES`) | none |

Volumes: `db_data` (the database; back it up, below), `db_tls_ca` / `db_tls_server` and, in
production, `site_tls_ca` / `site_tls_server` (certificates, recreated when missing or close to
expiry).

Every long-running container runs as a non-root user with a read-only root filesystem, no
Linux capabilities and `no-new-privileges`; CI checks each of these on the running stack.
Logs are rotated (3 files of 10 MB per service). Base images are pinned by digest, their OS
packages are updated at build time, and CI fails if any image has a fixable HIGH or CRITICAL
vulnerability (Trivy). Dependabot proposes new digests; it does not propose PostgreSQL major
versions (see [Upgrades](#upgrades)).

## Requirements

- Docker Engine with the Compose plugin v2.24.4 or later (`!reset` / `!override` in the
  production file), or Docker Desktop. Tested with Compose v5.5 (local) and the version on
  GitHub's `ubuntu-latest` runners (CI).
- About 2 GB of RAM for the production configuration's limits (database 1 GB, backend 768 MB,
  nginx 128 MB); disk for the database (1 million events took 1.3 GB in the benchmark,
  [performance.md](performance.md)).
- `openssl` to generate secrets. Nothing else on the host: the certificates are made in a
  container.

## Development (local demonstration)

The [README](../README.md#quick-start) and the [setup guide](setup.md) have the commands: copy `.env.example` to `.env`, set
the three secrets, `docker compose up -d --build --wait`, create the first admin. The app is on
http://localhost:8081, the API docs on http://localhost:8001/api/docs.

## Production configuration

```bash
cp .env.example .env     # then set POSTGRES_PASSWORD, APP_DB_PASSWORD and SECRET_KEY
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build --wait
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec backend \
    python -m app.cli create-admin --email you@example.com
```

To avoid repeating the file names, set `COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml`
in the shell (on Windows the separator is `;`). The scripts below honour it too.

What changes from development:

- `APP_ENV=production`: the backend refuses to start with an http origin in `CORS_ORIGINS`, a
  weak `SECRET_KEY` or `LOG_LEVEL=DEBUG` (tested in CI); the refresh cookie is `Secure`
  (https only); the interactive API docs and `openapi.json` are not served.
- nginx serves https on `SITE_PORT` (TLS 1.2 and 1.3) with HSTS; plain http on `HTTP_PORT`
  only redirects to https.
- Only the site is published. The database and the backend are reachable from the other
  containers only.
- Memory limits per container.

**Checklist before exposing it to other machines**

1. Set `SITE_BIND=0.0.0.0`, `SITE_PORT=443`, `HTTP_PORT=80`, `SITE_NAMES` to the host's name,
   and `SITE_ORIGIN=https://<that name>` in `.env`.
2. Use a certificate browsers trust ([TLS for the site](#tls-for-the-site)).
3. Generate fresh secrets (`openssl rand -hex 32` for `SECRET_KEY`, `-hex 24` for the two
   database passwords). Never reuse the development ones.
4. Create the first admin, then turn on two-factor sign-in for it (Account page).
5. Schedule backups and test a restore ([Backup and restore](#backup-and-restore)).
6. Ship the container logs somewhere the host's administrators cannot rewrite: they hold the
   audit chain's anchors ([security.md](security.md#audit-logging-phase-3-onward)).
7. Firewall: only `HTTP_PORT` and `SITE_PORT` need to be reachable.

**Verify**

```bash
curl --cacert ca.crt https://localhost:8443/api/ready     # {"status":"ok",...}
docker compose exec backend python -m app.cli check-config
docker compose exec backend python -m app.cli verify-audit
```

## TLS for the site

By default `site-certs` creates a private CA and a certificate for `SITE_NAMES` (valid 825
days, recreated within 30 days of expiry or when `SITE_NAMES` changes; the CA's key is thrown
away after signing). Browsers do not know this CA. Either:

- **Trust the local CA** on the machines that use SentinelX (a lab, a demo). Export it:
  `docker compose run --rm -T --no-deps --entrypoint cat site-certs /out/ca/ca.crt > ca.crt`
  and import `ca.crt` into the operating system's or browser's trusted roots.
- **Use your own certificate** (for example from Let's Encrypt): put `server.crt` (with its
  chain) and `server.key` in the `site_tls_server` volume, the key readable by uid 101, and an
  empty file named `external` next to them: `site-certs` then never touches the volume.
  Renew by replacing the two files and running `docker compose restart frontend`.
- **Terminate TLS in front** (an existing reverse proxy or load balancer): keep the
  production configuration and point the proxy at `SITE_PORT` (https again, with the local CA
  trusted by the proxy), and set `TRUSTED_PROXIES=172.28.0.10/32,<the proxy's address>` so
  the client's address, not the proxy's, reaches rate limits and the audit log
  ([security.md](security.md#authentication-phase-3)). Without it every request appears to
  come from the proxy.

The database connection is always TLS 1.3 with a verified certificate, in both configurations
([security.md](security.md#residual-risks-closed-after-the-review)).

## Free public deployment (Render and Neon)

A public link where anyone can explore SentinelX at no cost: the real app with the SIMULATED
demo environment ([demo.md](demo.md)), and **Explore as guest** on the sign-in page. It is a
portfolio demo, not a service. Everything is described in [`render.yaml`](../render.yaml),
a Render Blueprint; the same setup as CloudSentinel's public demo.

| Part | Where | Free plan terms (as used for CloudSentinel, September 2026; re-check) |
|---|---|---|
| React app | Render static site `sentinelx-demo` | Always on; proxies `/api/*` to the backend, so the browser sees one origin (the `SameSite=Strict` cookie and the CSP work as in Compose) and sends the same security headers as nginx (tested) |
| Backend | Render free web service `sentinelx-demo-api` (`backend/Dockerfile`) | 512 MB, 0.1 CPU; stops after 15 minutes without traffic; 750 instance hours a month |
| PostgreSQL | Neon free project | 0.5 GB storage; suspends when idle. Render's free PostgreSQL is not used: it is deleted 30 days after creation |

**What is different from Docker Compose, and why.**
- *One secret to paste.* Only Neon's owner connection string is entered (`MIGRATION_DATABASE_URL`).
  It runs the migrations and creates the least-privilege role; the app connects as that role,
  with a password Render generates (`APP_DB_PASSWORD`). `DATABASE_URL` is derived: the same
  host, the role's name and password.
- *A hosted owner is not a superuser.* Neon's `neondb_owner` may create roles but not restate
  superuser attributes, so on later starts only the role's password is updated and its rights
  are checked instead (a role with more than row rights is refused). Found by the rehearsal
  below before the first deployment.
- *TLS to the database*: Neon's certificate is verified against the system's CAs
  (`sslmode=verify-full&sslrootcert=system`), not a local CA. The backend hands libpq the CA
  bundle as a file (`/etc/ssl/certs/ca-certificates.crt`): the libpq bundled in psycopg's
  wheel looks for "system" CAs where it was built, so the first deployment failed with
  "certificate verify failed" until this was found (verified against Neon afterwards).
- *Client addresses*: `TRUSTED_PROXIES=private, cloudflare, 74.220.48.0/20`, the chain measured
  on Render for CloudSentinel (Render's internal network, Cloudflare, Render's proxy); the
  rightmost address outside it is the visitor. Named groups are in `app/core/client_ip.py`.
- *A read-only guest* (`GUEST_EMAIL`): visitors sign in without a password as a VIEWER. It can
  see everything a viewer sees (raw log text is withheld from viewers, as everywhere) and
  change nothing, including its own password or two-factor settings, so no visitor can lock
  the others out. The account is created at start; an existing analyst or admin with that
  email is refused, never handed out.
- *The demo on the first start* (`DEMO_AUTOLOAD=true`): the story is loaded only into an empty
  database, anchored at that moment; later starts leave it as it is.

**Rehearsed on every push** (CI job "Free public deployment", `scripts/hosted_check.sh`): the
backend image at 512 MB and 0.1 CPU with Render's settings, against a PostgreSQL whose owner
is a non-superuser that can create roles, as on Neon. It checks guest sign-in, the 15 alerts
and 5 incidents, the read-only restrictions, that the app connects as `sentinelx_app` only, and
a restart that leaves the demo as it is. Measured on the development machine at 0.1 CPU: first
start (migrations, role, rules, guest, loading the demo) 60 s, a restart 52 s, memory about
85 MB of 512. The rehearsal first measured 123 s for both: the entrypoint started eight
Python processes, each re-importing the app; `python -m app.cli startup` now runs every step
in one. Not rehearsed: Neon's TLS and Render's proxies themselves.

### Steps

Only you can do these: they create accounts and connect your GitHub repository. Never paste
the database URL into chat, issues or the repository.

1. **Neon**: at https://neon.com, create a project named `sentinelx` in **AWS Asia Pacific
   (Singapore)** (the Render region in `render.yaml`; change both if you prefer another).
   Open **Connect**, turn **connection pooling off**, and copy the connection string. Edit it:
   - change the start from `postgresql://` to `postgresql+psycopg://`;
   - replace `sslmode=require` with `sslmode=verify-full&sslrootcert=system` (keep any other
     parameters, such as `channel_binding=require`).
2. **Render**: at https://render.com, choose **New → Blueprint**, allow Render to read the
   `sentinelx` repository and select it. Render reads `render.yaml` and asks for
   `MIGRATION_DATABASE_URL`: paste the edited Neon string. Apply.
3. Wait for both services to deploy. The backend's first start takes a few minutes after its
   build (it loads the demo). If Render says a service name is taken, choose another name and
   update the `/api/*` rewrite and `CORS_ORIGINS` in `render.yaml` (a test checks they match).
4. Open https://sentinelx-demo.onrender.com and click **Explore as guest (read-only)**.

**An admin account (optional).** Free services have no shell. Run the CLI on your own machine
against Neon, as the owner, in your own terminal (the password is asked for, hidden):

```bash
cd backend
export DATABASE_URL='postgresql+psycopg://neondb_owner:...@...neon.tech/neondb?sslmode=verify-full&sslrootcert=system'
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m app.cli create-admin --email you@example.com
```

(A throwaway `SECRET_KEY` is enough: settings need one, and the server keeps its own.)

**Starting the demo over.** The story is dated when it was loaded, so after a week or two the
dashboard's recent days are empty. To load it again, in Neon's **SQL Editor** run
`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`, then in Render choose **Manual Deploy →
Restart service**: the backend migrates the empty database and loads the story anchored at
that moment. This deletes everything, the audit log included (there is no backup step on
the free plan, unlike `scripts/demo_reset.sh`), and any admin account must be created again.

**Updates.** `autoDeployTrigger: checksPass`: Render deploys a commit to `main` only after CI
passed. Pull-request previews are off.

**Limits to be honest about.**
- *Cold starts*: after 15 minutes without visitors the backend stops; the next one waits for
  Render to start the container and for the start-up steps (52 s in the rehearsal at 0.1 CPU,
  plus Render's own start). The site itself stays up and shows the sign-in page meanwhile.
- *Read-only*: visitors cannot triage, write notes or use the playground (analyst features);
  the demo shows what an analyst would see.
- *Shared data*: every visitor sees the same demo, which ages until it is started over.
- *Free plans change*: re-check Render's and Neon's terms if something stops working.

## Configuration reference

All configuration is environment variables, read from `.env` by Docker Compose. The backend
validates its settings at start (`python -m app.cli check-config` runs them without starting):
an invalid value stops it with a message that never echoes the value.

**Docker Compose** (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `POSTGRES_USER` | `sentinelx` | The database owner: migrations and the role setup only |
| `POSTGRES_PASSWORD` | none (required) | The owner's password; URL-safe characters |
| `POSTGRES_DB` | `sentinelx` | The database name |
| `APP_DB_USER` | `sentinelx_app` | The application's least-privilege role (rows only; [security.md](security.md#the-least-privilege-database-role)) |
| `APP_DB_PASSWORD` | none (required) | Its password; set again at every start |
| `SECRET_KEY` | none (required) | Signs access tokens and derives two-factor secrets; at least 32 characters |
| `APP_ENV` | `development` | `production` in the production file; `test` for the test suite |
| `LOG_LEVEL` | `INFO` | `DEBUG` is refused in production |
| `CORS_ORIGINS` | `http://localhost:8081,...` | Browser origins allowed to call the API (comma-separated); https only in production. The production file sets it from `SITE_ORIGIN` |
| `SITE_NAMES` | `localhost,127.0.0.1` | Production: names and addresses on the site's certificate |
| `SITE_ORIGIN` | `https://localhost:8443` | Production: the origin browsers use |
| `SITE_BIND` | `127.0.0.1` | Production: host address the site is published on |
| `SITE_PORT` | `8443` | Production: https port on the host (also used in the redirect) |
| `HTTP_PORT` | `8081` | Production: http port on the host (redirects to https) |
| `TRUSTED_PROXIES` | `172.28.0.10/32` (nginx) | Reverse proxies allowed to state the client's address; add a proxy in front of nginx here, keeping nginx's. Also accepts the groups `private` and `cloudflare` |
| `COMPOSE_FILE` | unset | Shell variable: `docker-compose.yml:docker-compose.prod.yml` selects production for every command and script |

**Backend settings** (`app/core/config.py`; set by Compose from the variables above, or in the
environment when running the backend outside Docker)

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | Compose: the app role over TLS | `postgresql+psycopg://...` for the application's role. Outside Docker use `127.0.0.1`, not `localhost`. Unset: derived from `MIGRATION_DATABASE_URL` with `APP_DB_USER` and `APP_DB_PASSWORD` (Render) |
| `MIGRATION_DATABASE_URL` | Compose: the owner over TLS | Owner connection for migrations and `setup-app-role`; unset: `DATABASE_URL` |
| `LOG_FORMAT` | `json` | `json` (one object per line) or `text` (readable, local runs) |
| `PORT` | `8000` | Port uvicorn listens on inside the container |
| `INTERNAL_NETWORKS` | RFC 1918 + `fc00::/7` | Addresses counted as internal by enrichment |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token lifetime (1–120) |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Session lifetime (1–90) |
| `MAX_FAILED_LOGINS` | `5` | Failures (passwords or codes) before a lockout |
| `LOCKOUT_MINUTES` | `15` | Lockout duration |
| `LOGIN_RATE_LIMIT_PER_MINUTE` | `10` | Sign-in attempts per client address per minute |
| `INGEST_MAX_BYTES` | `5242880` | Largest ingest request body |
| `INGEST_MAX_RECORDS` | `5000` | Most records per ingest request |
| `INGEST_RATE_LIMIT_PER_MINUTE` | `120` | Ingest requests per log source per minute |
| `HUNT_TIMEOUT_MS` | `5000` | Each hunt query is cancelled after this long |
| `GUEST_EMAIL` | unset | A public demo's shared, read-only guest (VIEWER): `POST /api/auth/guest` signs in as it without a password; created at start ([free public deployment](#free-public-deployment-render-and-neon)) |
| `DEMO_AUTOLOAD` | unset | `true`: the entrypoint loads the demo story at start, into an empty database only (a hosted demo's first start) |

`tests/unit/test_deployment_docs.py` fails if a setting, a Compose variable or an
`.env.example` entry is missing from these tables.

## Health and monitoring

- `GET /api/health`: the process is up (no database call). `GET /api/ready`: the database is
  reachable and the schema is at the code's migration head; 503 with `checks` otherwise. The
  container health checks use these (backend) and nginx's own response (frontend).
- Logs: one JSON object per line on stdout, with a request ID on every line of a request (the
  same ID nginx logs and returns as `X-Request-ID`). Ingestion counts, detection runs (per
  rule: candidates, detections, milliseconds) and errors are logged; secrets, query strings and
  request bodies never are (CI checks every secret against all container logs).
- `audit.chained` log lines carry the audit chain's newest sequence and hash: keep them
  outside the host to detect a rewritten audit log (`cli verify-audit --anchor SEQ:HASH`).
- `docker compose ps` shows each container's health; `docker compose logs -f backend` follows
  the API.

## Backup and restore

```bash
scripts/backup.sh [directory]                         # default: backups/
scripts/restore.sh backups/sentinelx-<time>.dump      # asks before replacing anything
```

- **Backup** takes a consistent snapshot (`pg_dump`, custom format) while SentinelX keeps
  running, and records the audit chain's newest entry next to it (`.dump.anchor`). The dump
  holds every event, the audit log and the users' password hashes: encrypt it and keep it
  where only operators can read it (`backups/` is git-ignored). Schedule it (cron, a Windows
  scheduled task) as often as you can afford to lose data, and keep copies off the host.
- **Restore** stops the backend and frontend, drops and recreates the database, restores the
  dump into the empty database, starts the backend (which applies newer migrations and grants
  its role again) and verifies the audit chain against the anchor. Restoring into an *empty*
  database matters: a full dump loads the data before it creates the triggers, so the audit
  chain is not recomputed and the per-day summaries are not counted twice.
- **Tested**: CI backs up a populated production stack, drops the database, restores, and
  checks that every count is identical, the summaries still equal the rows, the audit chain
  verifies against the anchor and sign-in works.
- Not covered: point-in-time recovery (WAL archiving). With nightly dumps, a failure loses up
  to a day.

## Upgrades

1. Back up.
2. `git pull`, then `docker compose up -d --build --wait` (with `COMPOSE_FILE` set for
   production). The backend applies new migrations before it serves; the old containers keep
   running until the new ones are built.
3. `docker compose exec backend python -m app.cli verify-audit`.

Rolling back code is a restore of the backup taken in step 1 with the previous version
checked out: migrations are not reversed automatically.

**PostgreSQL major versions** (16 to 17 or 18) cannot open the existing data volume. Back up,
change the base image in `db/Dockerfile`, remove the `db_data` volume, start, restore. This
is why Dependabot does not propose them.

**Image updates**: Dependabot opens pull requests with new base image digests; CI builds and
scans them. Rebuilding also applies OS package updates released since the base image.

## Secrets

Where each secret lives and how to rotate it: [security.md](security.md#operating-the-secrets).
Rotating `SECRET_KEY` signs everyone out and ends two-factor enrolments.

## Limits

- One host. No high availability: a host failure means restoring from the last backup on
  another one.
- Detection runs one batch at a time (by design); measured throughput on a laptop in
  [performance.md](performance.md).
- The default certificates come from a local CA browsers do not trust until you import it.
- Secrets are environment variables (visible to anyone who can run `docker inspect` on the
  host), not a secrets manager.
- No automatic backup scheduling or off-site copy: the scripts make and restore a backup; when
  and where to keep it is the operator's decision.
