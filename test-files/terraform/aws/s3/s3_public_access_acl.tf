# Terraform template for S3 Bucket ACL
# Generated plan output used for rego test s3_public_access_acl.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID: ACL value beings with "public-"
resource "aws_s3_bucket" "public" {
  bucket = "public"
  acl    = "public-read"

  tags = {
    Name        = "My public bucket"
    Environment = "Dev"
  }
}

# VALID: ACL value does not being with "public-" or "authenticated-"
resource "aws_s3_bucket" "private" {
  bucket = "private"
  acl    = "private"

  tags = {
    Name        = "My private bucket"
    Environment = "Dev"
  }
}
