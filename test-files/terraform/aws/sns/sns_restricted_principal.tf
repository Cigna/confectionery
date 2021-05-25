# Terraform template for SNS Restricted Principal
# Generated plan output used for rego test sns_restricted_principal_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/credentials"
  profile                 = "saml"
}

#Creating a sns topic
resource "aws_sns_topic" "test_a" {
  name = "test_a"
}

# INVALID: sns topic policy extends permissions to all principals
resource "aws_sns_topic_policy" "invalid_policy_a" {
 arn = aws_sns_topic.test_a.arn

policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action":[
        "sns:Publish"
     ],
      "Principal":"*",
      "Effect": "Allow",
      "Resource": "aws_sns_topic.test_a.arn"
    }
  ]
}
EOF
}

#Creating a sns topic
resource "aws_sns_topic" "test_b" {
  name = "test_b"
}

# INVALID: sns topic policy extends permissions to all principals
resource "aws_sns_topic_policy" "invalid_policy_b" {
 arn = aws_sns_topic.test_b.arn

policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "sns:Publish",
        "sns:Subscribe"
     ],
      "Principal":"*",
      "Effect": "Allow",
      "Resource": "aws_sns_topic.test_b.arn"
    }
  ]
}
EOF
}


# VALID: sns topic policy does not extend permissions to all principals
resource "aws_sns_topic_policy" "valid_policy_c" {
 arn = aws_sns_topic.test_b.arn

policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [ 
        "sns:Publish",
        "sns:Subscribe"
      ],
      "Principal":{"AWS":"arn:aws:iam::965447543943:role/ACCOUNTADMIN"},
      "Effect": "Allow",
      "Resource": "aws_sns_topic.test_b.arn"
    }
  ]
}
EOF
}

# INVALID: sns topic policy extends permissions to everyone
resource "aws_sns_topic_policy" "invalid_policy_d" {
 arn = aws_sns_topic.test_b.arn

policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "sns:Publish"
      ],
      "Principal" : { "AWS" : "*" },
      "Effect": "Allow",
      "Resource": "aws_sns_topic.test_b.arn"
    }
  ]
}
EOF
}


# VALID: sns topic policy extends permissions to everyone but it contains conditions which restrict access to everyone
resource "aws_sns_topic_policy" "valid_policy_e" {
 arn = aws_sns_topic.test_b.arn

policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "sns:Publish"
      ],
      "Condition": {"StringEquals": "AWS:SourceOwner"},
      "Principal": "*",
      "Effect": "Allow",
      "Resource": "aws_sns_topic.test_b.arn"
    }
  ]
}
EOF
}
