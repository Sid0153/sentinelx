#!/bin/sh
# Resets the demo environment (Phase 16, docs/demo.md#resetting-the-demo).
#
#   scripts/demo_reset.sh [--yes] [--no-backup] [--start 2026-09-25T18:00:00Z]
#
# Replaces the database with a fresh one holding the demo story again: alerts, incidents,
# notes, status changes and the audit log of the previous demo are gone. User accounts are
# kept (with their passwords and two-factor settings); everyone has to sign in again.
# Run from the repository root with the stack running (COMPOSE_FILE as for backup.sh).
#
# Why the whole database: raw records, events and the audit log are append-only (they refuse
# UPDATE, DELETE and TRUNCATE, ADR-0010), so demo data cannot be deleted row by row, and
# should not be. A reset is the same operation as a restore: a new, empty database.
#
# Steps, and why:
# 1. Refuse unless every stored record is SIMULATED: a database with real evidence is never
#    a demo, and is never reset by this script.
# 2. Back up the database (scripts/backup.sh) unless --no-backup: the audit log of the demo
#    just given is kept that way.
# 3. Note the audit log's newest entry; the new audit log records it (DEMO_RESET), so the
#    chain of audit logs across resets can be followed back to the backups.
# 4. Copy the users table inside the database container (its /tmp is memory only; password
#    hashes never leave the container), recreate the database, let the backend migrate it,
#    and put the users back.
# 5. Load the demo story (python -m app.cli demo-load) and verify the new audit log.
set -eu

confirm=ask
backup=yes
start=""
while [ $# -gt 0 ]; do
    case "$1" in
        --yes) confirm=no ;;
        --no-backup) backup=no ;;
        --start) start="${2:?--start needs an ISO 8601 time}"; shift ;;
        *) echo "usage: scripts/demo_reset.sh [--yes] [--no-backup] [--start ISO-TIME]" >&2
           exit 2 ;;
    esac
    shift
done

if ! docker compose exec -T backend python -m app.cli demo-status; then
    echo "Refusing to reset: this database is not (only) a demo environment." >&2
    exit 1
fi

if [ "$confirm" != no ]; then
    printf 'This replaces the database with a fresh demo; accounts are kept. Type "reset": '
    read -r answer
    [ "$answer" = reset ] || { echo "Cancelled."; exit 1; }
fi

if [ "$backup" = yes ]; then
    "$(dirname "$0")/backup.sh"
fi

# A broken audit chain stops the reset here (verify-audit exits 1): investigate first.
head="$(docker compose exec -T backend python -m app.cli verify-audit \
    | tr -d '\r' | sed -n 's/^Newest entry: \([0-9][0-9]*\) \([0-9a-f]\{64\}\)$/\1:\2/p')"

# The variables are expanded inside the database container (its own environment).
# shellcheck disable=SC2016
docker compose exec -T db sh -c \
    'pg_dump --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --data-only --table=users \
        --file /tmp/sentinelx-users.sql'

docker compose stop backend frontend
# shellcheck disable=SC2016
docker compose exec -T db sh -c \
    'dropdb --username "$POSTGRES_USER" --force --if-exists "$POSTGRES_DB" \
     && createdb --username "$POSTGRES_USER" "$POSTGRES_DB"'
docker compose up -d --wait backend  # migrates the empty database and loads the rules

# shellcheck disable=SC2016
docker compose exec -T db sh -c \
    'psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --quiet --output /dev/null \
        --set ON_ERROR_STOP=1 --file /tmp/sentinelx-users.sql && rm /tmp/sentinelx-users.sql'
# (If that failed, the copy stays in the database container's /tmp for the operator.)

set -- demo-load
if [ -n "$head" ]; then
    set -- "$@" --previous-audit-head "$head"
fi
if [ -n "$start" ]; then
    set -- "$@" --start "$start"
fi
docker compose exec -T backend python -m app.cli "$@"

docker compose up -d --wait frontend
docker compose exec -T backend python -m app.cli verify-audit
echo "Demo environment reset${head:+ (previous audit log ended at $head)}"
