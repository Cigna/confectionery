# Terraform template for cloudtrail log file, including valid and invalid cloudtrail resources
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# aws caller id data source 
data "aws_caller_identity" "current" {}

# Supporting s3 bucket policy resource 
resource "aws_s3_bucket_policy" "policy" {
  bucket = aws_s3_bucket.trail_bucket.id

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Sid1",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "${aws_s3_bucket.trail_bucket.arn}"
        },
        {
            "Sid": "Sid2",
            "Effect": "Allow",
            "Principal": {
                "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "${aws_s3_bucket.trail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        }
    ]
}
POLICY
}

# S3 bucket resource
resource "aws_s3_bucket" "trail_bucket" {
  force_destroy = true
}

# VALID cloudtrail resource with enabled log file validation 
resource "aws_cloudtrail" "valid_trail" {
  name           = "valid_trail"
  s3_bucket_name = aws_s3_bucket.trail_bucket.id

  enable_log_file_validation = true

  depends_on = [aws_s3_bucket_policy.policy]
}

# INVALID cloudtrail resource without enabled log file validation
resource "aws_cloudtrail" "invalid_trail" {
  name           = "invalid_trail"
  s3_bucket_name = aws_s3_bucket.trail_bucket.id

  enable_log_file_validation = false

  depends_on = [aws_s3_bucket_policy.policy]
}
