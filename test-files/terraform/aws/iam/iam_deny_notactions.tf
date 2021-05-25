# Terraform template for IAM Deny NotActions
# Generated plan output used for rego test iam_deny_notactions_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID: Allows NotAction Element
resource "aws_iam_policy" "invalid_test_policy" {
  name        = "invalid_test_policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "NotAction": [
        "ec2:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

# INVALID: Allows NotAction Element
resource "aws_iam_role_policy" "invalid_role_policy" {
  name = "invalid_role_policy"
  role = aws_iam_role.test_role.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "NotAction": [
          "ec2:Delete*"
        ],
        "Effect": "Allow",
        "Resource": "*"
      }
    ]
  }
  EOF
}

# Creates iam_role
resource "aws_iam_role" "test_role" {
  name = "test_role"

  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  }
  EOF
}

# INVALID: Allows NotAction Element
resource "aws_iam_policy" "invalid_policy_b" {
  name        = "invalid_policy_b"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "NotAction": [
        "s3:*"
      ],
      "Effect": "Deny",
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
EOF
}

# INVALID: Allows NotAction Element
resource "aws_iam_user_policy" "invalid_policy_c" {
  name = "invalid_policy_c"
  user = aws_iam_user.tester.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "NotAction": [
        "iam:*",
        "cloudfront:*",
        "route53:*",
	"ec2:*"
      ],
      "Effect": "Deny",
      "Resource": "*"
    }
  ]
}
EOF
}

# Creates iam_user
resource "aws_iam_user" "tester" {
  name = "tester"
  path = "/system/"
}

# VALID: Action Element is allowed
resource "aws_iam_policy" "valid_policy3" {
  name        = "valid_policy3"
  description = "My test policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}



