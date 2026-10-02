#!/bin/sh
# Rehearses the free public deployment (docs/deployment.md#free-public-deployment-render-and-neon)
# on one machine, and is run by CI on every push:
#
# - a PostgreSQL shaped like Neon's: the database owner is NOT a superuser, but may create
#   roles (Neon's neondb_owner), so the migrations and the least-privilege role setup must
#   work without superuser rights;
# - the backend image as Render runs it: Render's free limits (512 MB, 0.1 CPU), PORT=10000,
#   production settings, only the owner's URL given (DATABASE_URL is derived), the guest
#   account and the demo loaded on the first start.
#
# Then it checks what a visitor gets: guest sign-in, the demo's alerts and incidents, read-only
# access, and memory. Difference from Neon: no TLS here (Neon: sslmode=verify-full against the
# system CAs, sslrootcert=system).
#
#   scripts/hosted_check.sh            (PYTHON=python3 by default; needs Docker)
set -eu

PYTHON="${PYTHON:-python3}"
NET=sx-hosted-check
DB=sx-hosted-db
APP=sx-hosted-app
IMAGE=sentinelx-hosted-check
OWNER_PW="$(openssl rand -hex 16)"
APP_PW="$(openssl rand -hex 24)"
PORT=18080

cleanup() {
    docker rm -f "$APP" "$DB" > /dev/null 2>&1 || true
    docker network rm "$NET" > /dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$NET" > /dev/null

# PostgreSQL 16 with a Neon-like owner. The superuser exists only to set the database up.
docker run -d --name "$DB" --network "$NET" -e POSTGRES_PASSWORD="$(openssl rand -hex 16)" \
    postgres:16-alpine > /dev/null
until docker exec "$DB" pg_isready -U postgres > /dev/null 2>&1; do sleep 1; done
sleep 2
docker exec -i "$DB" psql -U postgres -v ON_ERROR_STOP=1 -q <<SQL
CREATE ROLE neondb_owner LOGIN PASSWORD '$OWNER_PW' CREATEROLE CREATEDB NOSUPERUSER;
CREATE DATABASE neondb OWNER neondb_owner;
SQL

docker build -q -t "$IMAGE" backend > /dev/null
start=$(date +%s)
docker run -d --name "$APP" --network "$NET" --memory 512m --cpus 0.1 -p "127.0.0.1:$PORT:10000" \
    -e PORT=10000 \
    -e APP_ENV=production \
    -e SECRET_KEY="$(openssl rand -hex 32)" \
    -e MIGRATION_DATABASE_URL="postgresql+psycopg://neondb_owner:$OWNER_PW@$DB:5432/neondb" \
    -e APP_DB_USER=sentinelx_app \
    -e APP_DB_PASSWORD="$APP_PW" \
    -e CORS_ORIGINS=https://sentinelx-demo.onrender.com \
    -e GUEST_EMAIL=guest@sentinelx.example \
    -e DEMO_AUTOLOAD=true \
    -e TRUSTED_PROXIES="private, cloudflare, 74.220.48.0/20" \
    "$IMAGE" > /dev/null

for _ in $(seq 1 180); do
    if curl -fsS "http://127.0.0.1:$PORT/api/health" > /dev/null 2>&1; then break; fi
    if [ "$(docker inspect -f '{{.State.Running}}' "$APP")" != "true" ]; then
        docker logs "$APP" 2>&1 | tail -30
        echo "FAIL the backend exited during start-up" >&2
        exit 1
    fi
    sleep 2
done
echo "Start-up (migrations, role, rules, guest, demo load) under 0.1 CPU: $(( $(date +%s) - start )) s"

# The role the application runs as has rights on rows only.
docker exec "$DB" psql -U postgres -d neondb -Atc \
    "SELECT rolsuper OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname = 'sentinelx_app'" \
    | grep -qx f
echo "ok   the application's role exists with no rights beyond rows"

"$PYTHON" - "http://127.0.0.1:$PORT" <<'PY'
import json
import sys
import urllib.error
import urllib.request

base = sys.argv[1]


def call(method, path, token=None, body=None):
    request = urllib.request.Request(base + path, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(request, data) as response:  # noqa: S310
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"null")


def check(ok, what, detail=""):
    print(("ok   " if ok else "FAIL ") + what + (f" ({detail})" if detail and not ok else ""))
    if not ok:
        sys.exit(1)


status, options = call("GET", "/api/auth/options")
check(status == 200 and options == {"guest_access": True}, "the sign-in page offers guest access")
status, session = call("POST", "/api/auth/guest")
check(status == 200, "a visitor signs in as the guest", status)
user, token = session["user"], session["access_token"]
check(user["role"] == "VIEWER" and user["is_guest"], "the guest is a read-only viewer", user)

status, summary = call("GET", "/api/dashboard/summary", token)
check(status == 200 and summary["open_alerts"] == 15, "the demo is loaded: 15 open alerts", summary.get("open_alerts"))
status, incidents = call("GET", "/api/incidents?limit=50", token)
check(status == 200 and incidents["total"] == 5, "5 incidents", incidents.get("total"))
check(all(i["simulated"] for i in incidents["items"]), "every incident is labelled simulated")

alert = call("GET", "/api/alerts?limit=1", token)[1]["items"][0]
status, _ = call("POST", f"/api/alerts/{alert['id']}/transition", token, {"status": "TRIAGED"})
check(status == 403, "the guest cannot change an alert", status)
status, _ = call("POST", "/api/auth/mfa/setup", token)
check(status == 403, "the guest cannot turn on two-factor sign-in for everyone", status)
status, _ = call("POST", "/api/auth/login", None, {"email": "guest@sentinelx.example", "password": "x" * 12})
check(status == 401, "nobody can sign in to the guest account with a password", status)
PY

# After those requests the app's pooled connections are open: all as the restricted role.
roles="$(docker exec "$DB" psql -U postgres -d neondb -Atc \
    "SELECT DISTINCT usename FROM pg_stat_activity WHERE datname = 'neondb' AND usename <> 'postgres'")"
[ "$roles" = "sentinelx_app" ] || { echo "FAIL the app connects as: $roles" >&2; exit 1; }
echo "ok   the app connects as sentinelx_app (derived from the owner's URL), never as the owner"

memory="$(docker stats --no-stream --format '{{.MemUsage}}' "$APP")"
echo "Memory after start-up and the checks: $memory (Render free plan: 512 MB)"
# A restart (Render stops idle free services) must not load the demo twice.
restart=$(date +%s)
docker restart "$APP" > /dev/null
for _ in $(seq 1 120); do
    if curl -fsS "http://127.0.0.1:$PORT/api/health" > /dev/null 2>&1; then break; fi
    sleep 2
done
echo "Restart (what a visitor waits for after Render stops an idle service, plus Render's own start): $(( $(date +%s) - restart )) s"
if ! docker logs "$APP" 2>&1 | grep -q "Demo not loaded: the database already holds records"; then
    docker logs "$APP" 2>&1 | tail -20
    echo "FAIL the backend did not start again cleanly" >&2
    exit 1
fi
echo "ok   a restart starts cleanly and keeps the demo (not loaded twice)"
