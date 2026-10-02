#!/bin/sh
set -e

# Every step before serving, in one Python process (`python -m app.cli startup`):
# 1. apply pending migrations, as the database owner;
# 2. give the application's least-privilege role its grants (when APP_DB_USER is set);
# 3. check the configuration, as that role;
# 4. load the shipped detection rules (new rules, library updates; admin tuning is kept);
# 5. flag batches a crash left without detection (STORED -> DETECTION_FAILED);
# 6. score open alerts and incidents again after a risk model change;
# 7. a public demo (docs/deployment.md#free-public-deployment-render-and-neon): the read-only
#    guest account (GUEST_EMAIL), and the demo story on the first start (DEMO_AUTOLOAD, an
#    empty database only).
# One process because each separate start re-imports the app, which takes seconds on a small
# instance (Render's free plan: 0.1 CPU). Fine for one container; with several replicas,
# migrations would run as a separate one-off job.
python -m app.cli startup
# --no-proxy-headers: uvicorn must not rewrite the client address from X-Forwarded-For. The app
# decides which forwarding entries to trust itself (Phase 3, docs/security.md).
exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port "${PORT:-8000}" \
    --no-proxy-headers
