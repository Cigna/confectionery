# Terraform template for KMS Key Rotation
# Generated plan output used for rego test kms_rotate_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

#VALID: KMS Key has enable_key_rotation enabled
resource "aws_kms_key" "valid" {
  description         = "KMS key 1"
  enable_key_rotation = true
}

#INVALID: KMS Key has enable_key_rotation disabled
resource "aws_kms_key" "invalid" {
  description         = "KMS key 2"
  enable_key_rotation = false
}

resource "aws_kms_key" "blank-invalid" {
  description = "KMS key 3"
}
