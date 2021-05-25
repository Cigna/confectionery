# Terraform template for SQS Server Side Encryption
# Generated plan output used for rego test sqs_server_side_encryption_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID : kms_master_key_id is not null
resource "aws_sqs_queue" "valid" {
  name                      = "terraform-example-queue"
  delay_seconds             = 90
  max_message_size          = 2048
  message_retention_seconds = 86400
  receive_wait_time_seconds = 10
  kms_master_key_id = "alias/aws/sns"
  redrive_policy = jsonencode({
    deadLetterTargetArn = null
    maxReceiveCount     = null
  })

  tags = {
    Environment = "production"
  }
}

# INVALID : kms_master_key_id is null by default
resource "aws_sqs_queue" "invalid" {
  name                      = "terraform-example-queue"
  delay_seconds             = 90
  max_message_size          = 2048
  message_retention_seconds = 86400
  receive_wait_time_seconds = 10
  redrive_policy = jsonencode({
    deadLetterTargetArn = null
    maxReceiveCount     = null
  })

  tags = {
    Environment = "production"
  }
}