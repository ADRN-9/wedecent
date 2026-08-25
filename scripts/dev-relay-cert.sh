#!/usr/bin/env sh
set -eu

OUT=${1:-.dev-certs}
mkdir -p "$OUT"
openssl req -x509 -newkey rsa:3072 -nodes \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
  -subj '/CN=WeDecent Development CA' -days 30
openssl req -newkey rsa:3072 -nodes \
  -keyout "$OUT/relay.key" -out "$OUT/relay.csr" \
  -subj '/CN=localhost'
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$OUT/relay.ext"
openssl x509 -req -in "$OUT/relay.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/relay.crt" -days 30 -extfile "$OUT/relay.ext"
printf 'Development certificates written to %s\n' "$OUT"
