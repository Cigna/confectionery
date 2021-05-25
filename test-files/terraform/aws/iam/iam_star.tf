# Terraform template for IAM Service Star Policy
# Generated plan output used for rego test iam_star_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID: Service action uses wildcard attribute . Actions should be listed. 
resource "aws_iam_policy" "invalid_policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:*"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

# VALID: Service actions are listed 
resource "aws_iam_policy" "valid_policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

# Creates s3 bucket
resource "aws_s3_bucket" "example" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}
