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
  sql         = "select * FROM 'dt/+/readings'"
  sql_version = "2016-03-23"

  cloudwatch_logs {
    log_group_name = aws_cloudwatch_log_group.readings.name
    role_arn       = aws_iam_role.rule.arn
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
