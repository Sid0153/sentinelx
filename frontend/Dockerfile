FROM node:26-alpine@sha256:0b36e8c136b94cd4fcf02188228e76c31ad5872eef3fec8cbd2eee500cfd9e80 AS build
WORKDIR /app
COPY package.json package-lock.json ./
# npm ci installs exactly what package-lock.json records (versions and integrity hashes).
RUN npm ci
COPY . .
RUN npm run build

# The 1.29 line is no longer updated upstream (Phase 15 image scan: 42 fixable HIGH issues).
FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:26b0bf6fbf07297983cb341998d79c831508787de26627dd2a112321b9c3a4af
# Security fixes released after the pinned base image (CI's image scan gates this).
USER root
RUN apk upgrade --no-cache
USER 101
COPY nginx/app.conf /etc/nginx/sentinelx/app.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
# Used by the production configuration only (docker-compose.prod.yml).
COPY nginx-tls.conf.template /etc/nginx/sentinelx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
