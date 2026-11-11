#!/usr/bin/env bash
# Creates a product's firmware-signing keys (platform plan §5b, §8): two P-256
# key pairs, <id>-a (active) and <id>-b (offline backup).
#
#   scripts/signing-keys.sh <product repository checkout>
#
# 1. Public keys: keys/<id>-a.pub.pem and keys/<id>-b.pub.pem in the product
#    repository, and `keys = ["<id>-a", "<id>-b"]` in its platform.toml, so
#    every image accepts both. Commit them (a fix: commit) yourself.
# 2. The same public keys to SSM /iot-platform/products/<id>/signing_keys,
#    where the OTA controller verifies releases.
# 3. GitHub Environment `release` in the product repository (deployments from
#    main only), with the private key of <id>-a as FIRMWARE_SIGNING_KEY.
# 4. The private key of <id>-b goes to the clipboard once, for the password
#    manager; the clipboard is cleared afterwards.
#
# No private key is written to disk or printed. Rotating to the backup later
# touches no Terraform: `gh secret set FIRMWARE_SIGNING_KEY --env release`
# with <id>-b's key; then retire <id>-a from keys/ and SSM once every unit
# runs an image without it.
#
# Needs: the owner's AWS session, `gh` logged in as the repository owner,
# openssl, jq, and pbcopy (macOS).
set -euo pipefail

repo_dir="${1:-}"
[[ -n "$repo_dir" && -f "$repo_dir/platform.toml" ]] || { echo "usage: $0 <product repository checkout>" >&2; exit 2; }
cd "$repo_dir"

product=$(python3 -c 'import tomllib; print(tomllib.load(open("platform.toml","rb"))["product"]["id"])')
[[ "$product" =~ ^[a-z][a-z0-9]{1,15}$ ]] || { echo "bad product id $product" >&2; exit 1; }
origin=$(git remote get-url origin)
repo=$(sed -E 's#^(git@github\.com:|https://github\.com/)##; s#\.git$##' <<< "$origin")
[[ "$repo" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$ ]] || { echo "cannot tell the GitHub repository from $origin" >&2; exit 1; }
parameter="/iot-platform/products/$product/signing_keys"

if compgen -G "keys/$product-*.pub.pem" >/dev/null; then
  echo "refusing: keys/$product-*.pub.pem exist already (rotation is described in this script's header)" >&2
  exit 1
fi
if aws ssm get-parameter --name "$parameter" >/dev/null 2>&1; then
  echo "refusing: $parameter exists already" >&2
  exit 1
fi
grep -Eq '^keys = \[\]' platform.toml || { echo "refusing: platform.toml has no empty 'keys = []' to fill" >&2; exit 1; }
gh auth status >/dev/null
aws sts get-caller-identity --query Account --output text >/dev/null

echo "product $product, repository $repo"
read -r -p "Create its signing keys, SSM $parameter and Environment release? [y/N] " answer
[[ "$answer" == [yY] ]] || { echo "nothing changed"; exit 1; }

umask 077
key_a=$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256)
key_b=$(openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256)
trap 'unset key_a key_b' EXIT
pub_a=$(openssl pkey -pubout <<< "$key_a")
pub_b=$(openssl pkey -pubout <<< "$key_b")

# SSM first: the controller must know the keys before a release is signed.
aws ssm put-parameter --name "$parameter" --type String --overwrite \
  --description "Firmware-signing public keys of $product (key id -> PEM). Read by the OTA controller." \
  --value "$(jq -cn --arg a "$pub_a" --arg b "$pub_b" --arg ia "$product-a" --arg ib "$product-b" '{($ia): $a, ($ib): $b}')" >/dev/null
echo "wrote SSM $parameter"

# Environment `release`: deployments from main only, no reviewers (the
# signature is the gate, plan decision B).
gh api -X PUT "repos/$repo/environments/release" --input - >/dev/null <<'JSON'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
if ! gh api "repos/$repo/environments/release/deployment-branch-policies" --jq '.branch_policies[].name' | grep -qx main; then
  gh api -X POST "repos/$repo/environments/release/deployment-branch-policies" -f name=main -f type=branch >/dev/null
fi
gh secret set FIRMWARE_SIGNING_KEY --env release --repo "$repo" <<< "$key_a"
echo "Environment release: main only, FIRMWARE_SIGNING_KEY = $product-a"

mkdir -p keys
printf '%s\n' "$pub_a" > "keys/$product-a.pub.pem"
printf '%s\n' "$pub_b" > "keys/$product-b.pub.pem"
chmod 0644 keys/*.pub.pem
sed -i.bak -E "s/^keys = \[\]/keys = [\"$product-a\", \"$product-b\"]/" platform.toml && rm platform.toml.bak
echo "wrote keys/$product-a.pub.pem, keys/$product-b.pub.pem and platform.toml"

printf '%s\n' "$key_b" | pbcopy
echo
echo "The PRIVATE key of $product-b (the offline backup) is on the clipboard."
read -r -p "Paste it into the password manager as \"$product-b firmware signing key\", then press Enter to clear the clipboard. "
pbcopy < /dev/null
echo "clipboard cleared. Commit keys/ and platform.toml in $repo (a fix: commit releases the first keyed image)."
