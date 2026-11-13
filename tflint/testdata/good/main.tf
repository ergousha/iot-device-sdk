terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.71"
    }
  }
  backend "s3" {
    bucket       = "esp32-ztp-tfstate-637423178579"
    key          = "products/demo/cloud.tfstate"
    region       = "eu-central-1"
    use_lockfile = true
  }
}

provider "aws" {
  region = "eu-central-1"
  default_tags {
    tags = {
      Product   = "demo"
      ManagedBy = "terraform"
    }
  }
}

resource "aws_cloudwatch_log_group" "readings" {
  name              = "/demo/readings"
  retention_in_days = 3
}

resource "aws_iam_role" "rule" {
  name               = "demo-rule-role"
  assume_role_policy = "{}"
}

resource "aws_iot_topic_rule" "readings" {
  name        = "demo_readings"
  enabled     = false
  sql         = "SELECT t, v, topic(2) AS thing FROM 'dt/+/readings'"
  sql_version = "2016-03-23"
  tags        = { killable = "true" }

  cloudwatch_logs {
    log_group_name = aws_cloudwatch_log_group.readings.name
    role_arn       = aws_iam_role.rule.arn
  }
}

resource "aws_dynamodb_table" "readings" {
  name         = "demo-readings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "thing"

  attribute {
    name = "thing"
    type = "S"
  }

  on_demand_throughput {
    max_read_request_units  = 5
    max_write_request_units = 2
  }
}

resource "aws_lambda_function" "consumer" {
  function_name = "demo-consumer"
  role          = aws_iam_role.rule.arn
  runtime       = "provided.al2023"
  handler       = "bootstrap"
  filename      = "consumer.zip"
}
