#!/usr/bin/env bash
# Regenerates the contract/v1 test vector with the same tools the release
# workflow uses (openssl, sha256sum/shasum), so the device-side verifier
# (iot-jobs/src/manifest.rs) and the release tooling are checked against one
# byte string. The signing key is thrown away: only its public half is kept.
#
#   contract/v1/make-vector.sh
set -euo pipefail
cd "$(dirname "$0")"
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A small, deterministic "image".
python3 -c 'import sys; sys.stdout.buffer.write(bytes((i * 31 + 7) % 256 for i in range(4099)))' > app.bin
printf 'factory image placeholder' > "$work/factory.bin"

sha() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
size=$(wc -c < app.bin | tr -d ' ')

# Canonical JSON: sorted keys, no whitespace, no trailing newline.
python3 - "$(sha app.bin)" "$size" "$(sha "$work/factory.bin")" > manifest.json <<'PY'
import json, sys
m = {"contract": 1, "product": "vaktus", "version": "0.9.0",
     "sha256": sys.argv[1], "size": int(sys.argv[2]), "factory_sha256": sys.argv[3]}
sys.stdout.write(json.dumps(m, sort_keys=True, separators=(",", ":")))
PY

openssl ecparam -name prime256v1 -genkey -noout -out "$work/key.pem"
openssl ec -in "$work/key.pem" -pubout -out test-key.pub.pem 2>/dev/null
openssl dgst -sha256 -sign "$work/key.pem" manifest.json | openssl base64 -A > manifest.sig
openssl dgst -sha256 -verify test-key.pub.pem -signature <(openssl base64 -d -A < manifest.sig) manifest.json
