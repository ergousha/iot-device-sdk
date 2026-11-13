# The platform's rules for a product's cloud/ Terraform root (PLATFORM.md,
# "Cost rules"; plan §7). Read by tflint-ruleset-opa: a product's CI runs
# tflint in cloud/ with TFLINT_OPA_POLICY_DIR pointing here, at the SDK
# revision its Cargo.toml pins.
#
# The product id P is the Product tag of the aws provider's default_tags.
# Every rule here is an error:
#
#   product tag      the aws provider sets default_tags { tags = { Product = P } }
#   backend          state in s3, key products/P/cloud.tfstate
#   rule name        IoT rules are named P_*: the kill switch disables every
#                    enabled P_* rule when the guard trips, and Basic Ingest
#                    reaches them as $aws/rules/P_*
#   rule killable    IoT rules are tagged killable = "true"
#   rule sql         never SELECT *: explicit, small fields
#   table billing    DynamoDB tables are PAY_PER_REQUEST (no fixed cost) and
#                    capped by on_demand_throughput at 1-5 writes a second
#   lambda           no reserved_concurrent_executions: the account limit
#                    of 10 caps every Lambda
#   log retention    log groups keep 1-3 days
#   names            IAM roles, Lambdas, tables: P-*; log groups /P/* or
#                    /aws/lambda/P-*
#
# A deliberate exception takes a `# tflint-ignore: opa_deny_<rule>` comment
# with its reason on the line above.
package tflint

import rego.v1

product_id_pattern := `^[a-z][a-z0-9]{1,15}$`

# --- the product id ----------------------------------------------------------

aws_providers := [p |
	some p in terraform.providers({"default_tags": {"tags": "map(string)"}}, {})
	p.name == "aws"
]

product_tags contains tags if {
	some p in aws_providers
	some block in p.config.default_tags
	tags := block.config.tags
}

products contains id if {
	some tags in product_tags
	id := tags.value.Product
	regex.match(product_id_pattern, id)
}

product := id if {
	count(products) == 1
	some id in products
}

deny_product_tag contains issue if {
	count(aws_providers) == 0
	some s in terraform.settings({}, {})
	issue := tflint.issue("cloud/ needs an aws provider with default_tags { tags = { Product = \"<product id>\" } }", s.decl_range)
}

deny_product_tag contains issue if {
	some p in aws_providers
	count(products) != 1
	issue := tflint.issue("the aws provider's default_tags must set Product to the product id (one id, 2-16 lowercase letters and digits)", p.decl_range)
}

# --- state -------------------------------------------------------------------

backends := [b |
	some s in terraform.settings({"backend": {"__labels": ["type"], "key": "string"}}, {})
	some b in s.config.backend
]

deny_backend contains issue if {
	some s in terraform.settings({"backend": {"__labels": ["type"]}}, {})
	count(backends) == 0
	issue := tflint.issue("cloud/ keeps its state in the platform's state bucket: backend \"s3\" with key products/<product id>/cloud.tfstate", s.decl_range)
}

deny_backend contains issue if {
	some b in backends
	b.labels[0] != "s3"
	issue := tflint.issue("the backend must be s3 (the platform's state bucket)", b.decl_range)
}

deny_backend contains issue if {
	some b in backends
	b.config.key.value != sprintf("products/%s/cloud.tfstate", [product])
	issue := tflint.issue(sprintf("the state key must be products/%s/cloud.tfstate", [product]), b.config.key.range)
}

# --- IoT rules -----------------------------------------------------------------

topic_rules := terraform.resources("aws_iot_topic_rule", {"name": "string", "sql": "string", "tags": "map(string)"}, {})

deny_rule_name contains issue if {
	some r in topic_rules
	r.config.name.unknown
	issue := tflint.issue("an IoT rule's name must be a literal the guard can match (P_*)", r.config.name.range)
}

deny_rule_name contains issue if {
	some r in topic_rules
	not startswith(r.config.name.value, sprintf("%s_", [product]))
	issue := tflint.issue(sprintf("IoT rules are named %s_* so the kill switch can disable them", [product]), r.config.name.range)
}

deny_rule_killable contains issue if {
	some r in topic_rules
	not rule_killable(r)
	issue := tflint.issue("IoT rules are tagged killable = \"true\" (the guard's traffic scope disables them)", r.decl_range)
}

rule_killable(r) if r.config.tags.value.killable == "true"

deny_rule_sql contains issue if {
	some r in topic_rules
	regex.match(`(?i)select\s+\*`, r.config.sql.value)
	issue := tflint.issue("never SELECT *: select the explicit, small fields the action needs", r.config.sql.range)
}

deny_rule_sql contains issue if {
	some r in topic_rules
	r.config.sql.unknown
	issue := tflint.issue("an IoT rule's SQL must be a literal the linter can check", r.config.sql.range)
}

# --- DynamoDB ------------------------------------------------------------------

tables := terraform.resources("aws_dynamodb_table", {
	"name": "string",
	"billing_mode": "string",
	"on_demand_throughput": {"max_write_request_units": "number"},
}, {})

deny_table_billing contains issue if {
	some t in tables
	not t.config.billing_mode.value == "PAY_PER_REQUEST"
	issue := tflint.issue("DynamoDB tables are billing_mode = \"PAY_PER_REQUEST\" (a provisioned table costs every hour)", t.decl_range)
}

deny_table_billing contains issue if {
	some t in tables
	not table_capped(t)
	issue := tflint.issue("DynamoDB tables need on_demand_throughput { max_write_request_units = 1..5 }", t.decl_range)
}

table_capped(t) if {
	some block in t.config.on_demand_throughput
	w := block.config.max_write_request_units.value
	w >= 1
	w <= 5
}

# --- Lambda --------------------------------------------------------------------

deny_lambda_concurrency contains issue if {
	some f in terraform.resources("aws_lambda_function", {"reserved_concurrent_executions": "number"}, {})
	r := f.config.reserved_concurrent_executions
	issue := tflint.issue("no reserved_concurrent_executions: it would take from the account's 10, which cap every Lambda", r.range)
}

# --- Logs ----------------------------------------------------------------------

log_groups := terraform.resources("aws_cloudwatch_log_group", {"name": "string", "retention_in_days": "number"}, {})

deny_log_retention contains issue if {
	some g in log_groups
	not log_retention_ok(g)
	issue := tflint.issue("log groups keep 1-3 days (retention_in_days)", g.decl_range)
}

log_retention_ok(g) if {
	d := g.config.retention_in_days.value
	d >= 1
	d <= 3
}

# --- names ---------------------------------------------------------------------

named := array.concat(
	array.concat(
		terraform.resources("aws_iam_role", {"name": "string"}, {}),
		terraform.resources("aws_lambda_function", {"function_name": "string"}, {}),
	),
	tables,
)

deny_names contains issue if {
	some r in named
	some attr in ["name", "function_name"]
	v := r.config[attr]
	not startswith(v.value, sprintf("%s-", [product]))
	issue := tflint.issue(sprintf("%s.%s: name it %s-*", [r.type, r.name, product]), v.range)
}

deny_names contains issue if {
	some g in log_groups
	not startswith(g.config.name.value, sprintf("/%s/", [product]))
	not startswith(g.config.name.value, sprintf("/aws/lambda/%s-", [product]))
	issue := tflint.issue(sprintf("log groups are named /%s/* (or /aws/lambda/%s-*)", [product, product]), g.config.name.range)
}
