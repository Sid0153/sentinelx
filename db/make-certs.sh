#!/bin/sh
# Issues the TLS certificate PostgreSQL uses in Docker Compose (Phase 13, docs/security.md).
#
# Runs once per `docker compose up` as the one-shot service `db-certs`, before the database.
# - A private CA and a server certificate for the name `db` (the service name the backend
#   connects to; the backend verifies it with sslmode=verify-full).
# - The CA's private key is thrown away after signing: nothing can issue another certificate
#   from it later. When the server certificate is missing or expires within 30 days, a new
#   CA and certificate are made (the backend reads the new CA when it reconnects).
# - Only the CA certificate goes to the backend's volume; the server key goes to the
#   database's volume only, readable by the postgres user (uid 70 in the Alpine image).
set -eu
umask 077

CA_OUT=/out/ca
SERVER_OUT=/out/server
POSTGRES_UID=70

# The key is handed to the postgres user last, so its owner shows that a run completed.
if [ -f "$SERVER_OUT/server.crt" ] && [ -f "$CA_OUT/ca.crt" ] && [ -f "$SERVER_OUT/server.key" ] \
    && [ "$(stat -c %u "$SERVER_OUT/server.key")" = "$POSTGRES_UID" ] \
    && openssl x509 -checkend 2592000 -noout -in "$SERVER_OUT/server.crt" > /dev/null; then
    echo "Database TLS certificate present and valid for at least 30 more days"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

openssl req -x509 -new -noenc -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$work/ca.key" -out "$work/ca.crt" -days 3650 \
    -subj "/CN=SentinelX local database CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -noenc -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$work/server.key" -out "$work/server.csr" -subj "/CN=db"

cat > "$work/server.ext" << 'EOF'
subjectAltName = DNS:db
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
    -CAcreateserial -days 825 -extfile "$work/server.ext" -out "$work/server.crt"

# Old files are removed first: a key already owned by postgres cannot be overwritten here
# (no CAP_DAC_OVERRIDE / CAP_FOWNER), only unlinked from the root-owned directory.
rm -f "$CA_OUT/ca.crt" "$SERVER_OUT/server.crt" "$SERVER_OUT/server.key"
cp "$work/ca.crt" "$CA_OUT/ca.crt"
cp "$work/server.crt" "$SERVER_OUT/server.crt"
cp "$work/server.key" "$SERVER_OUT/server.key"
chmod 0644 "$CA_OUT/ca.crt" "$SERVER_OUT/server.crt"
chmod 0600 "$SERVER_OUT/server.key"
chmod 0755 "$CA_OUT" "$SERVER_OUT"
chown "$POSTGRES_UID:$POSTGRES_UID" "$SERVER_OUT/server.key"  # last: marks the run complete

echo "Database TLS certificate issued for 'db', valid until $(openssl x509 -enddate -noout -in "$SERVER_OUT/server.crt" | cut -d= -f2)"
