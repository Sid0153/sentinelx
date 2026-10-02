#!/bin/sh
# Backs up the SentinelX database (Phase 15, docs/deployment.md#backup-and-restore).
#
#   scripts/backup.sh [output-directory]          (default: backups/)
#
# Run from the repository root, with the stack running. For the production configuration set
# COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml (on Windows, use ; between the files).
#
# Writes two files:
# - sentinelx-<time>.dump: pg_dump in custom format, a consistent snapshot taken while the
#   application keeps running. It holds every event, alert, incident, the audit log and the
#   users' password hashes: store it encrypted and readable only by operators.
# - sentinelx-<time>.dump.anchor: the audit log's newest chained entry (sequence:hash) just
#   before the dump. scripts/restore.sh checks the restored log against it, which proves the
#   restored audit trail is the one that was backed up (docs/security.md, tamper evidence).
set -eu

out="${1:-backups}"
mkdir -p "$out"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
file="$out/sentinelx-$stamp.dump"

anchor="$(docker compose exec -T backend python -m app.cli verify-audit \
    | tr -d '\r' | sed -n 's/^Newest entry: \([0-9][0-9]*\) \([0-9a-f]\{64\}\)$/\1:\2/p')"

# The variables are expanded inside the database container (its own environment).
# shellcheck disable=SC2016
docker compose exec -T db sh -c \
    'pg_dump --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --format custom' > "$file"

if [ ! -s "$file" ]; then
    echo "Backup failed: $file is empty" >&2
    rm -f "$file"
    exit 1
fi
printf '%s\n' "$anchor" > "$file.anchor"
echo "Backup written: $file ($(wc -c < "$file" | tr -d ' ') bytes), audit anchor ${anchor:-none}"
