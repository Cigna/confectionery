# Terraform template for Lambda Invoke Role
# Generated plan output used for rego test lambda_invoke_role_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

resource "aws_iam_role" "iam_for_lambda_invalid" {
  name = "iam_for_lambda_invalid"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "lambda:InvokeLambda",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

# INVALID : attached role has invokeLambda action and principal.service is lambda
resource "aws_lambda_function" "invalid" {
  filename      = "lambda_function_payload.zip"
  function_name = "lambda_function_name_invalid"
  role          = aws_iam_role.iam_for_lambda_invalid.arn
  handler       = "exports.test"

  runtime = "nodejs12.x"

  environment {
    variables = {
      foo = "bar"
    }
  }
}

# VALID : attached role does not have invokeLambda action
resource "aws_lambda_function" "valid" {
  filename      = "lambda_function_payload.zip"
  function_name = "lambda_function_name_valid"
  role          = aws_iam_role.iam_for_lambda_valid.arn
  handler       = "exports.test"

  runtime = "nodejs12.x"

  environment {
    variables = {
      foo = "bar"
    }
  }
}

resource "aws_iam_role" "iam_for_lambda_valid" {
  name = "iam_for_lambda_valid"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}