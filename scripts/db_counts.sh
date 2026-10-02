#!/bin/sh
# Prints the row counts a backup must preserve, and whether the per-day summaries still equal
# the rows (Phase 15: used by CI's backup-and-restore check; handy before and after a restore).
set -eu
# shellcheck disable=SC2016
docker compose exec -T db sh -c 'psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -At -c "
SELECT (SELECT count(*) FROM users) AS users,
       (SELECT count(*) FROM raw_events) AS raw_events,
       (SELECT count(*) FROM events) AS events,
       (SELECT count(*) FROM alerts) AS alerts,
       (SELECT count(*) FROM incidents) AS incidents,
       (SELECT count(*) FROM audit_logs) AS audit_logs,
       (SELECT coalesce(sum(records), 0) FROM event_daily_counts WHERE kind = \$\$event\$\$)
           = (SELECT count(*) FROM events) AS event_summary_ok,
       (SELECT coalesce(sum(records), 0) FROM event_daily_counts WHERE kind = \$\$raw\$\$)
           = (SELECT count(*) FROM raw_events) AS raw_summary_ok"' | tr -d '\r'
