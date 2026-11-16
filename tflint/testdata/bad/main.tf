terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.71"
    }
  }
  backend "s3" {
    bucket = "esp32-ztp-tfstate-637423178579"
    key    = "demo.tfstate"
    region = "eu-central-1"
  }
}

provider "aws" {
  region = "eu-central-1"
  default_tags {
    tags = { Product = "demo" }
  }
}

resource "aws_cloudwatch_log_group" "readings" {
  name              = "/other/readings"
  retention_in_days = 30
}

resource "aws_iam_role" "rule" {
  name               = "rule-role"
  assume_role_policy = "{}"
}

resource "aws_iot_topic_rule" "readings" {
  name        = "readings"
  enabled     = true
  sql         = "select *, topic(2) AS thing FROM 'dt/+/readings'"
  sql_version = "2016-03-23"

  cloudwatch_logs {
    log_group_name = aws_cloudwatch_log_group.readings.name
    role_arn       = aws_iam_role.rule.arn
  }

  republish {
    topic    = "dt/demo/readings"
    role_arn = aws_iam_role.rule.arn
  }

  error_action {
    republish {
      topic    = "dt/demo/errors"
      role_arn = aws_iam_role.rule.arn
    }
  }
}

resource "aws_dynamodb_table" "readings" {
  name           = "demo-readings"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "thing"

  attribute {
    name = "thing"
    type = "S"
  }
}

resource "aws_lambda_function" "consumer" {
  function_name                  = "demo-consumer"
  role                           = aws_iam_role.rule.arn
  runtime                        = "provided.al2023"
  handler                        = "bootstrap"
  filename                       = "consumer.zip"
  reserved_concurrent_executions = 1
}

resource "aws_dynamodb_table" "events" {
  name         = "demo-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "thing"

  attribute {
    name = "thing"
    type = "S"
  }

  on_demand_throughput {
    max_write_request_units = 2
  }
}

resource "aws_iot_role_alias" "device" {
  alias    = "demo-device"
  role_arn = aws_iam_role.rule.arn
}

resource "aws_iot_authorizer" "open" {
  name                    = "demo-open"
  authorizer_function_arn = aws_lambda_function.consumer.arn
  signing_disabled        = true
}

resource "aws_lambda_function_url" "consumer" {
  function_name      = aws_lambda_function.consumer.function_name
  authorization_type = "NONE"
}

resource "aws_api_gateway_method" "readings" {
  rest_api_id   = "abc123"
  resource_id   = "def456"
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_apigatewayv2_route" "readings" {
  api_id    = "abc123"
  route_key = "GET /readings"
}

resource "aws_s3_bucket" "exports" {
  bucket = "demo-exports"
}

resource "aws_s3_bucket" "assets" {
  bucket = "demo-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}
