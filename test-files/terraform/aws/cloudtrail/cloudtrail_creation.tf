# Terraform template for Cloudtrail Creation
# Generated plan output used for rego test cloudtrail_creation_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}
# INVALID : cloudtrails are not allowed to be created
resource "aws_cloudtrail" "invalid" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = aws_s3_bucket.foo.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = false
}

resource "aws_s3_bucket" "foo" {
  bucket        = "tf-test-trail"
  force_destroy = true
}
