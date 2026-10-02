# ADR-0014: Single-host Docker Compose deployment, with a production overlay CI runs

**Context.** SentinelX must be deployable and demonstrable without paid cloud services
(brief §35, Phase 15), and the production configuration must be something CI actually runs,
not a document. Until Phase 15 CI ran only the development configuration (plain http,
`APP_ENV=development`), so production-only behaviour (https-only cookies, refused unsafe
settings, docs off) had never run end to end.

**Options.**
- (a) Kubernetes manifests or a Helm chart.
- (b) A separate production Compose file duplicating the development one.
- (c) One Compose file for development, plus an overlay (`docker-compose.prod.yml`) that
  changes only what production changes: TLS on nginx with a locally generated certificate,
  `APP_ENV=production`, only the site published, memory limits.

**Decision.** (c). The same images serve both; nginx's headers and routing live in one
included file (`frontend/nginx/app.conf`), so the two configurations cannot drift. A CI job
starts the overlay and runs the end-to-end scripts over https, checks the production settings
and runs a backup, the loss of the database and a restore. Backups are `pg_dump` snapshots
restored into an empty database by `scripts/restore.sh`, with the audit chain's head recorded
at backup time and verified after the restore.

**Consequences.**
- Production behaviour is tested on every push (a CI job of its own).
- Deployment needs Docker and nothing else; no cluster, no managed services.
- One host: no high availability and no horizontal scaling. Recovery from a host failure is a
  restore on another host. Kubernetes (a) would add this at the cost of operating a cluster,
  out of proportion for the lab and small deployments SentinelX targets.
- Secrets are environment variables, not a secrets manager.
- Restoring must use an empty database (triggers are created after the data in a full dump);
  restoring data into a migrated database would recompute the audit chain and double-count
  the per-day summaries. The restore script enforces the order.
