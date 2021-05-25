# Terraform template for EKS Version
# Generated plan output used for rego test eks_version_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

#VALID: Version number is at least 1.15
resource "aws_eks_cluster" "valid" {
  name     = "example"
  role_arn = "arn:aws:iam::123456789012:user/*"
  version = "1.15"

  vpc_config {
    subnet_ids = ["subnet-abcde012", "subnet-bcde012a", "subnet-fghi345a" ]
  }
}

#INVALID: Version Number is below 1.15
resource "aws_eks_cluster" "invalid" {
  name     = "example"
  role_arn = "arn:aws:iam::123456789012:user/*"
  version = "1.14"

  vpc_config {
    subnet_ids = ["subnet-abcde012", "subnet-bcde012a", "subnet-fghi345a" ]
  }
}