# Terraform template for VPC Internet Gateway Creation Block
# Generated plan output used for rego test vpc_igw_creation_block_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID : Internet gateways are prohibited for creation
resource "aws_internet_gateway" "invalid" {
  vpc_id = "vpc-abcde123"

  tags = {
    Name = "main"
  }
}
