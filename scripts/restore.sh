#!/bin/sh
# Restores a backup made by scripts/backup.sh (Phase 15, docs/deployment.md#backup-and-restore).
#
#   scripts/restore.sh [--yes] backups/sentinelx-<time>.dump
#
# REPLACES the current database with the backup: everything stored since the backup is lost.
# Run from the repository root with the stack running (COMPOSE_FILE as for backup.sh).
#
# Steps, and why:
# 1. Stop the backend and frontend: nothing may write while the database is replaced.
# 2. Drop and recreate the database, then restore the dump into it as the owner. A full dump
#    loads the data before it creates the triggers, so restoring into an *empty* database
#    neither recomputes the audit hash chain nor counts the events into the daily summaries a
#    second time. (Restoring data into the migrated database the backend creates would.)
#    Privileges are not restored: the backend grants its least-privilege role again at start.
# 3. Start the backend: it applies any newer migrations (restoring an older backup into newer
#    code works) and checks its configuration.
# 4. Verify the audit chain end to end, and against the anchor recorded with the backup.
set -eu

confirm=yes-please-ask
if [ "${1:-}" = "--yes" ]; then
    confirm=no
    shift
fi
file="${1:?usage: scripts/restore.sh [--yes] <backup.dump>}"
if [ ! -s "$file" ]; then
    echo "No backup at $file" >&2
    exit 1
fi

if [ "$confirm" != no ]; then
    printf 'This replaces the current database with %s. Type "restore" to continue: ' "$file"
    read -r answer
    [ "$answer" = restore ] || { echo "Cancelled."; exit 1; }
fi

docker compose stop backend frontend

# The variables are expanded inside the database container (its own environment).
# shellcheck disable=SC2016
docker compose exec -T db sh -c \
    'dropdb --username "$POSTGRES_USER" --force --if-exists "$POSTGRES_DB" \
     && createdb --username "$POSTGRES_USER" "$POSTGRES_DB"'
# shellcheck disable=SC2016
docker compose exec -T db sh -c \
    'pg_restore --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --no-owner --no-privileges --exit-on-error' \
    < "$file"

docker compose up -d --wait backend frontend

anchor=""
if [ -s "$file.anchor" ]; then
    anchor="$(tr -d '\r\n' < "$file.anchor")"
fi
if [ -n "$anchor" ]; then
    docker compose exec -T backend python -m app.cli verify-audit --anchor "$anchor"
else
    docker compose exec -T backend python -m app.cli verify-audit
fi
echo "Restored $file"
