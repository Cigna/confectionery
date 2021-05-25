# Terraform template for IAM Resource Star Policy
# Generated plan output used for rego test iam_star_resource_policy_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID: The resource is specified with a wildcard attribute. Powerful actions should be scoped with a specific resource 
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
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

# VALID: This powerful action is scoped with a specific resource
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
      "Resource": "arn:aws:s3:us-east-1:504760316746:example"
    }
  ]
}
EOF
}

# Creates an s3 bucket
resource "aws_s3_bucket" "example" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}
