# Terraform template for Kinesis Encrypted
# Generated plan output used for rego test kinesis_encrypted_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID: Valid stream since it is encrypted with the non default key
resource "aws_kinesis_stream" "valid_stream" {
  name             = "terraform-kinesis-test"
  shard_count      = 1
  retention_period = 48
  encryption_type  = "KMS"
  kms_key_id       = "alias/aws/kinesis2"
  shard_level_metrics = [
    "IncomingBytes",
    "OutgoingBytes",
  ]

  tags = {
    Environment = "test"
  }
}

# INVALID: Invalid stream since it is not encrypted
resource "aws_kinesis_stream" "invalid_stream" {
  name             = "terraform-kinesis-test"
  shard_count      = 1
  retention_period = 48
  shard_level_metrics = [
    "IncomingBytes",
    "OutgoingBytes",
  ]

  tags = {
    Environment = "test"
  }
}

# INVALID: Invalid stream since it is not encrypted with a CMK
resource "aws_kinesis_stream" "invalid_stream_default" {
  name             = "terraform-kinesis-test"
  shard_count      = 1
  retention_period = 48
  encryption_type  = "KMS"
  kms_key_id       = "alias/aws/kinesis"
  shard_level_metrics = [
    "IncomingBytes",
    "OutgoingBytes",
  ]

  tags = {
    Environment = "test"
  }
}