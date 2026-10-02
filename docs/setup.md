# Setup guide

From nothing to a running SentinelX with the demo loaded, then with your own logs. For every
setting and the production procedures, see [deployment.md](deployment.md). For a development
environment (tests, hot reload), see the [README](../README.md#develop).

## 1. Requirements

- Docker with Compose v2 (Docker Desktop on Windows or macOS).
- `openssl` (or any other way) to generate secrets.
- Free host ports 5433, 8001 and 8081, all bound to 127.0.0.1 only. The production
  configuration publishes only the site, on 8443.

## 2. Configure

```bash
git clone https://github.com/Sid0153/sentinelx.git
cd sentinelx
cp .env.example .env
```

Fill in the three secrets in `.env`. Compose refuses to start without them:

| Variable | What | Generate with |
|---|---|---|
| `POSTGRES_PASSWORD` | The database owner (migrations only) | `openssl rand -hex 24` |
| `APP_DB_PASSWORD` | The application's least-privilege database role | `openssl rand -hex 24` |
| `SECRET_KEY` | Signs sessions; two-factor secrets derive from it | `openssl rand -hex 32` |

`.env` is git-ignored. Never commit it.

## 3. Start

```bash
docker compose up -d --build --wait
```

The first build takes a few minutes. `--wait` returns when every container is healthy. On
the way up the backend:
- migrates the database;
- grants its least-privilege role;
- checks its configuration;
- loads the detection rules.

Readiness: http://localhost:8081/api/ready answers `"status":"ok"` once the database is
reachable and migrated.

## 4. Create the first admin

There is no self-registration. The first admin is created on the server, and the password
is asked for twice, hidden:

```bash
docker compose exec backend python -m app.cli create-admin --email you@example.com
```

Sign in at http://localhost:8081. Then, under **Users**, create analysts (they investigate
and act) and viewers (read only). Under **Account**, turn on two-factor sign-in. Roles:
[security.md](security.md#authorization-phase-3-extended-every-phase).

## 5. Load the demo

```bash
docker compose exec backend python -m app.cli demo-load
```

This loads a fictional company: three days of SIMULATED activity and one example of every
attack scenario, which give 15 alerts and 5 incidents. [demo.md](demo.md) describes what is
in it and walks through a demonstration. To start the demo over (accounts are kept):

```bash
scripts/demo_reset.sh
```

## 6. Send your own logs

Do this on a separate deployment from the demo. `scripts/demo_reset.sh` refuses to touch a
database holding real records, and mixing both makes the numbers hard to read.

Register one log source per sender and format. The type picks the parser: `linux_auth`,
`windows_security`, `http_access`, `app_json` or `generic_json` (formats:
[event-model.md](event-model.md)).

```bash
docker compose exec backend python -m app.cli create-source --name web-01-auth --type linux_auth
docker compose exec backend python -m app.cli issue-ingest-key --source web-01-auth
```

The second command prints the source ID and its ingest key **once**. Store the key in the
shipper's secret store. Then any shipper can post batches (at most 5,000 records or 5 MB):

```bash
curl -X POST https://sentinelx.example/api/ingest/<source-id> \
  -H "X-Ingest-Key: <key>" -H "Content-Type: text/plain" --data-binary @auth.log
```

The key works for that source only and can read nothing. For a one-off file there is also:

```bash
docker compose exec -T backend python -m app.cli ingest-file --source web-01-auth --file /dev/stdin < auth.log
```

Every batch is parsed, stored and run through detection before the response returns. The
batch report counts parsed, skipped, failed and duplicate records, detections, and new alerts
and incidents. Sources and ingest keys are managed with the CLI or the API
([api.md](api.md)); the UI does not manage them yet.

To make priorities meaningful, register your hosts and accounts under **Assets** and
**Identities**, with their criticality and privilege ([risk-model.md](risk-model.md)). This
works best before the logs arrive: events record the context known when they are stored.

## 7. Production

The production configuration adds https with a locally issued certificate, production
settings, and memory limits, and publishes only the site:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build --wait
```

Before exposing it, read [deployment.md](deployment.md): the configuration reference, using
your own certificate, health checks, backups (`scripts/backup.sh`), restores and upgrades.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `docker compose up` stops at once naming a variable | A secret in `.env` is empty (step 2). |
| `/api/ready` reports not ready | The database is down or not migrated: `docker compose logs backend db`. |
| Sign-in says "too many attempts" | 10 attempts a minute per address, and an account locks after repeated failures; wait, or have an admin reset it. |
| A batch shows `failed` records | The lines are not in the source's format. The batch report gives a reason code per record, and the raw record is stored anyway. |
| No alert for logs that should trigger one | Check the event times (rules use the event's own time, and a source's time zone matters for syslog), and use the **Playground** to test the lines against the rule. |
| On Windows (Git Bash), a `docker compose exec` path is mangled | Prefix the command with `MSYS_NO_PATHCONV=1`. |
