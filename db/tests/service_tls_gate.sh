#!/usr/bin/env bash
set -euo pipefail
test "$PGDATABASE" = verivaro_test
test -n "$VV_CI_PG_CONTAINER"
tls_root="$(mktemp -d)"
cleanup_tls() { rm -rf "$tls_root"; }
trap cleanup_tls EXIT
umask 077
openssl req -new -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Verivaro CI CA' -addext 'basicConstraints=critical,CA:TRUE' -keyout "$tls_root/ca.key" -out "$tls_root/ca.pem" 2>/dev/null
openssl req -new -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Wrong CI CA' -addext 'basicConstraints=critical,CA:TRUE' -keyout "$tls_root/wrong.key" -out "$tls_root/wrong.pem" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=localhost' -keyout "$tls_root/server.key" -out "$tls_root/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$tls_root/extensions"
openssl x509 -req -in "$tls_root/server.csr" -CA "$tls_root/ca.pem" -CAkey "$tls_root/ca.key" -CAcreateserial -days 2 -extfile "$tls_root/extensions" -out "$tls_root/server.crt" 2>/dev/null
docker cp "$tls_root/server.key" "$VV_CI_PG_CONTAINER:/tmp/vv-server.key"
docker cp "$tls_root/server.crt" "$VV_CI_PG_CONTAINER:/tmp/vv-server.crt"
docker exec -u 0 "$VV_CI_PG_CONTAINER" sh -ec 'chown postgres:postgres /tmp/vv-server.key /tmp/vv-server.crt; chmod 600 /tmp/vv-server.key; chmod 644 /tmp/vv-server.crt'
psql -X -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET ssl_cert_file='/tmp/vv-server.crt'"
psql -X -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET ssl_key_file='/tmp/vv-server.key'"
psql -X -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET ssl=on"
# Restrict only the two synthetic service identities; CI admin remains usable.
hba="$(psql -X -At -c 'SHOW hba_file')"
docker exec -u 0 "$VV_CI_PG_CONTAINER" sh -ec 'hba="$1"; cp "$hba" "$hba.vv-original"; { printf "%s\n" "hostnossl all vv_ci_tls_old,vv_ci_tls_new 0.0.0.0/0 reject" "hostnossl all vv_ci_tls_old,vv_ci_tls_new ::/0 reject" "hostssl all vv_ci_tls_old,vv_ci_tls_new 0.0.0.0/0 scram-sha-256" "hostssl all vv_ci_tls_old,vv_ci_tls_new ::/0 scram-sha-256"; cat "$hba.vv-original"; } > "$hba"' sh "$hba"
psql -X -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()'
for i in $(seq 1 30); do
 if test "$(psql -X -At -c 'SHOW ssl')" = on; then break; fi
 sleep 1
done
test "$(psql -X -At -c 'SHOW ssl')" = on
test "$(psql -X -At -c 'SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL')" = 0
printf '127.0.0.1 vv-wrong.test\n' | sudo tee -a /etc/hosts >/dev/null
old="$(openssl rand -hex 32)"
next="$(openssl rand -hex 32)"
echo "::add-mask::$old"
echo "::add-mask::$next"
printf '%s\n' "$old" > "$tls_root/old-password"
printf '%s\n' "$next" > "$tls_root/new-password"
export VV_TLS_OLD_PASSWORD="$old" VV_TLS_NEW_PASSWORD="$next"
psql -X -v ON_ERROR_STOP=1 -f db/tests/service_tls_logins.sql
VV_TLS_FIXTURE="$tls_root" VV_LIVE_TEST=1 VV_TEST_DRIVER_DIR="$RUNNER_TEMP/vv-live-driver" node --test tests/integration/live-service-tls.test.mjs
VV_TLS_FIXTURE="$tls_root" VV_LIVE_TEST=1 VV_TEST_DRIVER_DIR="$RUNNER_TEMP/vv-live-driver" node --test tests/integration/live-application-runtime.test.mjs
# Real disposable PostgreSQL state verification with injected CLIENT failures.
# This must never be run against external staging or a production cluster.
VV_TLS_FIXTURE="$tls_root" VV_LIVE_TEST=1 VV_TEST_DRIVER_DIR="$RUNNER_TEMP/vv-live-driver" node --test tests/integration/live-credential-faults.test.mjs
cleanup_tls
