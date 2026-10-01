#!/bin/sh
set -e

# Apply pending migrations (as the database owner), give the application's least-privilege
# role its grants, then check the configuration as that role and start the API. Fine for one
# container; with several replicas, migrations would run as a separate one-off job.
alembic upgrade head
if [ -n "${APP_DB_USER:-}" ]; then
  python -m app.cli setup-app-role
fi
python -m app.cli check-config
# Loads the shipped detection rules (new rules, library updates); admin tuning is kept.
python -m app.cli seed-rules
# A crash between storing a batch and running its detection leaves it STORED: flag it.
python -m app.cli reconcile-batches
# After a risk model change, open alerts and incidents are scored again with the new model.
python -m app.cli rescore
# --no-proxy-headers: uvicorn must not rewrite the client address from X-Forwarded-For. The app
# decides which forwarding entries to trust itself (Phase 3, docs/security.md).
exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port "${PORT:-8000}" \
    --no-proxy-headers
