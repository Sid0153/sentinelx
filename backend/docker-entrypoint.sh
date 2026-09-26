#!/bin/sh
set -e

# Check the configuration, apply pending migrations, then start the API. Fine for one
# container; with several replicas, migrations would run as a separate one-off job.
python -m app.cli check-config
alembic upgrade head
# Loads the shipped detection rules (new rules, library updates); admin tuning is kept.
python -m app.cli seed-rules
# A crash between storing a batch and running its detection leaves it STORED: flag it.
python -m app.cli reconcile-batches
# --no-proxy-headers: uvicorn must not rewrite the client address from X-Forwarded-For. The app
# decides which forwarding entries to trust itself (Phase 3, docs/security.md).
exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port "${PORT:-8000}" \
    --no-proxy-headers
