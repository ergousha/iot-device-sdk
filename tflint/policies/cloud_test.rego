# Unit tests for cloud.rego, run by tflint/test.sh with TFLINT_OPA_TEST=1.
# Each mock is one small cloud/ root; testdata/ holds the end-to-end fixtures.
package tflint

import rego.v1

# --- DynamoDB: reads and writes capped -----------------------------------------

tables_capped(type, schema, options) := terraform.mock_resources(type, schema, options, {"main.tf": `
resource "aws_dynamodb_table" "readings" {
  name         = "demo-readings"
  billing_mode = "PAY_PER_REQUEST"
  on_demand_throughput {
    max_read_request_units  = 5
    max_write_request_units = 1
  }
}`})

test_table_capped_passes if {
	count(deny_table_billing) == 0 with terraform.resources as tables_capped
}

tables_uncapped(type, schema, options) := terraform.mock_resources(type, schema, options, {"main.tf": `
resource "aws_dynamodb_table" "no_read_cap" {
  name         = "demo-no-read-cap"
  billing_mode = "PAY_PER_REQUEST"
  on_demand_throughput {
    max_write_request_units = 2
  }
}

resource "aws_dynamodb_table" "read_cap_too_high" {
  name         = "demo-read-cap-too-high"
  billing_mode = "PAY_PER_REQUEST"
  on_demand_throughput {
    max_read_request_units  = 6
    max_write_request_units = 2
  }
}

resource "aws_dynamodb_table" "read_cap_zero" {
  name         = "demo-read-cap-zero"
  billing_mode = "PAY_PER_REQUEST"
  on_demand_throughput {
    max_read_request_units  = 0
    max_write_request_units = 2
  }
}

resource "aws_dynamodb_table" "read_cap_unknown" {
  name         = "demo-read-cap-unknown"
  billing_mode = "PAY_PER_REQUEST"
  on_demand_throughput {
    max_read_request_units  = var.reads
    max_write_request_units = 2
  }
}

variable "reads" {
  type = number
}`})

test_table_read_cap_missing_or_out_of_range_fails if {
	count(deny_table_billing) == 4 with terraform.resources as tables_uncapped
}

# --- IoT identity --------------------------------------------------------------

iot_auth_resources(type, schema, options) := terraform.mock_resources(type, schema, options, {"main.tf": `
resource "aws_iot_role_alias" "device" {
  alias    = "demo-device"
  role_arn = "arn:aws:iam::123456789012:role/demo-device"
}

resource "aws_iot_authorizer" "open" {
  name                    = "demo-open"
  authorizer_function_arn = "arn:aws:lambda:eu-central-1:123456789012:function:demo-auth"
  signing_disabled        = true
}`})

test_iot_auth_fails if {
	issues := deny_iot_auth with terraform.resources as iot_auth_resources
	count(issues) == 2
}

no_iot_auth_resources(type, schema, options) := terraform.mock_resources(type, schema, options, {"main.tf": `
resource "aws_iot_topic_rule" "readings" {
  name        = "demo_readings"
  enabled     = false
  sql         = "SELECT t FROM 'dt/+/readings'"
  sql_version = "2016-03-23"
}`})

test_iot_auth_passes if {
	count(deny_iot_auth) == 0 with terraform.resources as no_iot_auth_resources
}

# --- IoT rules: no republish ---------------------------------------------------

republishing_rules(type, schema, options) := terraform.mock_resources(type, schema, options, {"main.tf": `
resource "aws_iot_topic_rule" "action" {
  name        = "demo_action"
  enabled     = false
  sql         = "SELECT t FROM 'dt/+/readings'"
  sql_version = "2016-03-23"
  republish {
    topic    = "dt/demo/readings"
    role_arn = "arn:aws:iam::123456789012:role/demo-rule"
  }
}

resource "aws_iot_topic_rule" "error_action" {
  name        = "demo_error_action"
  enabled     = false
  sql         = "SELECT t FROM 'dt/+/readings'"
  sql_version = "2016-03-23"
  cloudwatch_logs {
    log_group_name = "/demo/readings"
    role_arn       = "arn:aws:iam::123456789012:role/demo-rule"
  }
  error_action {
    republish {
      topic    = "dt/demo/errors"
      role_arn = "arn:aws:iam::123456789012:role/demo-rule"
    }
  }
}`})

test_rule_republish_fails if {
	count(deny_rule_republish) == 2 with terraform.resources as republishing_rules
}

sink_rules(type, schema, options) := terraform.mock_resources(type, schema, options, {"main.tf": `
resource "aws_iot_topic_rule" "readings" {
  name        = "demo_readings"
  enabled     = false
  sql         = "SELECT t FROM 'dt/+/readings'"
  sql_version = "2016-03-23"
  cloudwatch_logs {
    log_group_name = "/demo/readings"
    role_arn       = "arn:aws:iam::123456789012:role/demo-rule"
  }
  error_action {
    cloudwatch_logs {
      log_group_name = "/demo/errors"
      role_arn       = "arn:aws:iam::123456789012:role/demo-rule"
    }
  }
}`})

test_rule_republish_passes if {
	count(deny_rule_republish) == 0 with terraform.resources as sink_rules
}

# --- public endpoints ----------------------------------------------------------

open_endpoints(type, schema, options) := terraform.mock_resources(type, schema, options, {"main.tf": `
resource "aws_lambda_function_url" "open" {
  function_name      = "demo-consumer"
  authorization_type = "NONE"
}

resource "aws_api_gateway_method" "open" {
  rest_api_id   = "abc123"
  resource_id   = "def456"
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_apigatewayv2_route" "default_none" {
  api_id    = "abc123"
  route_key = "GET /readings"
}

resource "aws_apigatewayv2_route" "explicit_none" {
  api_id             = "abc123"
  route_key          = "GET /status"
  authorization_type = "NONE"
}`})

test_public_endpoint_fails if {
	count(deny_public_endpoint) == 4 with terraform.resources as open_endpoints
}

authorized_endpoints(type, schema, options) := terraform.mock_resources(type, schema, options, {"main.tf": `
resource "aws_lambda_function_url" "iam" {
  function_name      = "demo-consumer"
  authorization_type = "AWS_IAM"
}

resource "aws_api_gateway_method" "iam" {
  rest_api_id   = "abc123"
  resource_id   = "def456"
  http_method   = "GET"
  authorization = "AWS_IAM"
}

resource "aws_apigatewayv2_route" "jwt" {
  api_id             = "abc123"
  route_key          = "GET /readings"
  authorization_type = "JWT"
  authorizer_id      = "ghi789"
}`})

test_public_endpoint_passes if {
	count(deny_public_endpoint) == 0 with terraform.resources as authorized_endpoints
}

# --- S3: public access blocked -------------------------------------------------

unblocked_buckets(type, schema, options) := terraform.mock_resources(type, schema, options, {"main.tf": `
resource "aws_s3_bucket" "none" {
  bucket = "demo-none"
}

resource "aws_s3_bucket" "partial" {
  bucket = "demo-partial"
}

resource "aws_s3_bucket_public_access_block" "partial" {
  bucket                  = aws_s3_bucket.partial.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "other_name" {
  bucket = "demo-other-name"
}

resource "aws_s3_bucket_public_access_block" "mismatched" {
  bucket                  = aws_s3_bucket.other_name.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`})

test_s3_public_fails if {
	count(deny_s3_public) == 3 with terraform.resources as unblocked_buckets
}

blocked_buckets(type, schema, options) := terraform.mock_resources(type, schema, options, {"main.tf": `
resource "aws_s3_bucket" "exports" {
  bucket = "demo-exports"
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`})

test_s3_public_passes if {
	count(deny_s3_public) == 0 with terraform.resources as blocked_buckets
}
