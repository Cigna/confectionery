# Terraform template for IAM Permissive Policy Attachments
# Generated plan output used for rego test iam_permissive_policy_attachment_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID: This managed policy attachmeent is overly permissive
resource "aws_iam_user_policy_attachment" "invalid_adminAccess" {
  user       = "${aws_iam_user.user.name}"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Creates iam user
resource "aws_iam_user" "user" {
  name = "loadbalancer"
  path = "/system/"
}

# Creates iam role
resource "aws_iam_role" "role" {
  name = "test-role"

  assume_role_policy = <<EOF
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

# INVALID: This managed policy attachment is overly permissive 
resource "aws_iam_role_policy_attachment" "invalid_iamFull" {
  role       = "${aws_iam_role.role.name}"
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}

# Creates iam group
resource "aws_iam_group" "group" {
  name = "test-group"
}

# INVALID: This managed policy attachment is overly permissive
resource "aws_iam_policy_attachment" "invalid_s3Full" {
  name       = "test-attachment"
  users      = [aws_iam_user.user.name]
  roles      = [aws_iam_role.role.name]
  groups     = [aws_iam_group.group.name]
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# VALID:  This managed policy attachment follows least privilege
resource "aws_iam_policy_attachment" "valid" {
  name       = "test-attachment"
  users      = [aws_iam_user.user.name]
  roles      = [aws_iam_role.role.name]
  groups     = [aws_iam_group.group.name]
  policy_arn = "arn:aws:iam::aws:policy/ListAllMyBuckets"
}
