# tflint configuration for a product's cloud/ root: copy it there (the
# template does). The policies come from this directory at the SDK revision
# the product pins (TFLINT_OPA_POLICY_DIR=<sdk>/tflint/policies).
plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "aws" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

plugin "opa" {
  enabled = true
  version = "0.12.0"
  source  = "github.com/terraform-linters/tflint-ruleset-opa"
}
