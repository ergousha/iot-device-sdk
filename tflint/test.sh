#!/usr/bin/env bash
# Runs the cloud/ policies against the fixtures in testdata/: `good` must
# pass, `bad` and `untagged` must fail with exactly the rules listed below.
# Needs tflint; the plugins are installed on first run (tflint --init).
set -euo pipefail
cd "$(dirname "$0")"
export TFLINT_OPA_POLICY_DIR="$PWD/policies"

expect() { # fixture, expected sorted rule names (space-separated)
  local fixture="$1" want="$2" got
  (cd "testdata/$fixture" && tflint --init >/dev/null)
  got=$(cd "testdata/$fixture" && tflint --format json || true)
  got=$(jq -r '[.issues[].rule.name] | sort | join(" ")' <<<"$got")
  if [[ "$got" != "$want" ]]; then
    echo "testdata/$fixture: got [$got], want [$want]" >&2
    return 1
  fi
  echo "ok  testdata/$fixture"
}

expect good ""
expect bad "opa_deny_backend opa_deny_lambda_concurrency opa_deny_log_retention opa_deny_names opa_deny_names opa_deny_rule_killable opa_deny_rule_name opa_deny_rule_sql opa_deny_table_billing opa_deny_table_billing"
expect untagged "opa_deny_backend opa_deny_product_tag"
