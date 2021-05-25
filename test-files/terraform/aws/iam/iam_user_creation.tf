# Terraform template for IAM User Creation
# Generated plan output used for rego test iam_user_creation_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}
# INVALID : IAM Users are not allowed to be created
resource "aws_iam_user" "invalid" {
  name = "loadbalancer"
  path = "/system/"

  tags = {
    tag-key = "tag-value"
  }
}
