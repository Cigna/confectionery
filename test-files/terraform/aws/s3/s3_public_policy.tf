# Terraform template for Public S3 Bucket Policy
# Generated plan output used for rego test rs3_public_policy_test.rego


provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# S3 Bucket for Bucket Policies
resource "aws_s3_bucket" "b" {
  bucket = "my_tf_test_bucket"
}

#VALID: Policy contains Principal:* but also aws:PrincipalOrgID as a limiting condition.
resource "aws_s3_bucket_policy" "valid" {
  bucket = aws_s3_bucket.b.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": {
    "Sid": "AllowPutObject",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::policy-ninja-dev/*",
    "Condition": {"StringEquals":
      {"aws:PrincipalOrgID": "o-xxxxxxxxxxx"}
    }
  }
}
POLICY
}

#VALID: Policy Statement contains Deny
resource "aws_s3_bucket_policy" "valid_deny" {
  bucket = aws_s3_bucket.b.id

  policy = <<POLICY 
{
    "Version": "2012-10-17",
    "Id": "DefaultBucketPolicy",
    "Statement": [
        {
          "Sid": "DefaultDenyNonSecure",
          "Effect": "Deny",
          "Principal": { "AWS": ["arn:aws:iam::123456789012:root"] },
          "Action": "*",
          "Condition": {
            "Bool": {
              "aws:SecureTransport": "false"
            },
            "StringEquals": {
              "aws:PrincipalOrgID": "o-xxxxxxxxxxx"
            }            
          },
          "Resource": "arn:aws:s3:::example-bucket-dev/*"
        }
    ]
}
POLICY
}

#INVALID: Policy contains Principal: AWS: * but has no limiting condition.
resource "aws_s3_bucket_policy" "invalid" {
  bucket = aws_s3_bucket.b.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": {
    "Sid": "AllowPutObject",
    "Effect": "Allow",
    "Principal" : { "AWS" : "*" },
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::example-bucket-dev/*"
  }
}
POLICY
}
