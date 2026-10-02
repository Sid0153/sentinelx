#!/bin/sh
# Issues a TLS certificate from a private CA (Phase 13 for PostgreSQL, Phase 15 also for the
# site in the production configuration; docs/deployment.md).
#
# Runs as a one-shot Compose service before the service that uses the certificate:
# - `db-certs`: the name `db` (the backend verifies it with sslmode=verify-full), key owned by
#   the postgres user (uid 70).
# - `site-certs` (docker-compose.prod.yml): the site's names, key owned by nginx (uid 101).
# Settings (environment): CERT_NAMES (comma-separated DNS names and IP addresses, the first is
# the common name), CERT_OWNER_UID, CERT_LABEL.
#
# - The CA's private key is thrown away after signing: nothing can issue another certificate
#   from it later. When the certificate is missing, expires within 30 days, or no longer has
#   the names asked for, a new CA and certificate are made.
# - Only the CA certificate goes to /out/ca (for clients); the key goes to /out/server only,
#   readable by its owner.
set -eu
umask 077

CA_OUT=/out/ca
SERVER_OUT=/out/server
NAMES="${CERT_NAMES:-db}"
OWNER_UID="${CERT_OWNER_UID:-70}"
LABEL="${CERT_LABEL:-Database}"
COMMON_NAME="${NAMES%%,*}"

# subjectAltName: DNS:name for names, IP:address for addresses.
SAN=""
for name in $(echo "$NAMES" | tr ',' ' '); do
    case "$name" in
        *[!0-9.:]*) entry="DNS:$name" ;;
        *) entry="IP:$name" ;;
    esac
    SAN="${SAN:+$SAN,}$entry"
done

# A certificate managed outside SentinelX (your own, e.g. Let's Encrypt): never touched.
if [ -f "$SERVER_OUT/external" ]; then
    echo "$LABEL TLS certificate is managed externally ($SERVER_OUT/external): left as it is"
    exit 0
fi

# The key is handed to its owner last, so its owner shows that a run completed. Certificates
# issued before Phase 15 have no `names` file; they were all for `db`.
if [ -f "$SERVER_OUT/server.crt" ] && [ -f "$CA_OUT/ca.crt" ] && [ -f "$SERVER_OUT/server.key" ] \
    && [ "$(stat -c %u "$SERVER_OUT/server.key")" = "$OWNER_UID" ] \
    && [ "$(cat "$SERVER_OUT/names" 2>/dev/null || echo db)" = "$NAMES" ] \
    && openssl x509 -checkend 2592000 -noout -in "$SERVER_OUT/server.crt" > /dev/null; then
    echo "$LABEL TLS certificate present and valid for at least 30 more days"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

openssl req -x509 -new -noenc -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$work/ca.key" -out "$work/ca.crt" -days 3650 \
    -subj "/CN=SentinelX local $LABEL CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -noenc -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$work/server.key" -out "$work/server.csr" -subj "/CN=$COMMON_NAME"

cat > "$work/server.ext" << EOF
subjectAltName = $SAN
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in "$work/server.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
    -CAcreateserial -days 825 -extfile "$work/server.ext" -out "$work/server.crt"

# Old files are removed first: a key already owned by its user cannot be overwritten here
# (no CAP_DAC_OVERRIDE / CAP_FOWNER), only unlinked from the root-owned directory.
rm -f "$CA_OUT/ca.crt" "$SERVER_OUT/server.crt" "$SERVER_OUT/server.key" "$SERVER_OUT/names"
cp "$work/ca.crt" "$CA_OUT/ca.crt"
cp "$work/server.crt" "$SERVER_OUT/server.crt"
cp "$work/server.key" "$SERVER_OUT/server.key"
echo "$NAMES" > "$SERVER_OUT/names"
chmod 0644 "$CA_OUT/ca.crt" "$SERVER_OUT/server.crt" "$SERVER_OUT/names"
chmod 0600 "$SERVER_OUT/server.key"
chmod 0755 "$CA_OUT" "$SERVER_OUT"
chown "$OWNER_UID:$OWNER_UID" "$SERVER_OUT/server.key"  # last: marks the run complete

echo "$LABEL TLS certificate issued for $SAN, valid until $(openssl x509 -enddate -noout -in "$SERVER_OUT/server.crt" | cut -d= -f2)"
