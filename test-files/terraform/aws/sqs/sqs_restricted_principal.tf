# Terraform template for SQS Principal Restriction
# Generated plan output used for rego test sqs_restricted_principal_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID : although principal is *, a condition restricts
resource "aws_sqs_queue_policy" "valid_sqs_policy_condition" {
  queue_url = "SampleQueue"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "*"
      ],
      "Principal":"*",
      "Effect": "Allow",
      "Resource": "*",
      "Condition": {"ArnEquals": {
          "aws:SourceArn": "example_arn"}
          }
    }
  ]
}
EOF
}

# VALID : principal is not wildcard (*)
resource "aws_sqs_queue_policy" "valid_sqs_policy_non_star_principal" {
  queue_url = "SampleQueue"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "*"
      ],
      "Principal":"Tom",
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

# INVALID : principal is * and no condition to restrict
resource "aws_sqs_queue_policy" "invalid_sqs_policy" {
  queue_url = "SampleQueue"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "*"
      ],
      "Principal":"*",
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
