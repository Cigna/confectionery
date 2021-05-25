# Terraform template for SNS Encryption
# Generated plan output used for rego test sns_encryption_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID: Encrypted - kms_master_key_id is enabled
resource "aws_sns_topic" "valid_example" {
  name = "valid-encrypted-topic"
  kms_master_key_id = "alias/aws/sns"
}

# INVALID: Not Encrypted 
resource "aws_sns_topic" "invalid_example" {
  name = "invalid-unencrypted-topic"
}

