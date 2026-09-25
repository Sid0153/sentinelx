#!/bin/sh
set -e

# Check the configuration, apply pending migrations, then start the API. Fine for one
# container; with several replicas, migrations would run as a separate one-off job.
python -m app.cli check-config
alembic upgrade head
# --no-proxy-headers: uvicorn must not rewrite the client address from X-Forwarded-For. The app
# decides which forwarding entries to trust itself (Phase 3, docs/security.md).
exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port "${PORT:-8000}" \
    --no-proxy-headers
