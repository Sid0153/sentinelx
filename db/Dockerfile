# PostgreSQL for SentinelX (Phase 15): the official image, with its OS packages brought up to
# date at build time and without `gosu`.
#
# The official entrypoint uses gosu only to drop from root to the postgres user. This container
# runs as postgres (uid 70) from the start (docker-compose.yml), so gosu is never executed;
# removing it removes code that image scanners flag (its Go runtime) and that nothing uses.
FROM postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea

# Security fixes released after the pinned base image (the base stays pinned by digest; CI's
# image scan fails if a fixable HIGH or CRITICAL issue remains).
RUN apk upgrade --no-cache && rm -f /usr/local/bin/gosu

USER postgres
