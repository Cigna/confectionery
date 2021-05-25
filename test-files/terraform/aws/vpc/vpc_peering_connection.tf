# Terraform template for VPC Peering Connection
# Generated plan output used for rego test vpc_peering_connection_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}
# INVALID : vpc peering connections are not allowed to be created
resource "aws_vpc_peering_connection" "invalid" {
  peer_owner_id = "peer_owner_id"
  peer_vpc_id   = aws_vpc.bar.id
  vpc_id        = aws_vpc.foo.id
  auto_accept   = true

  tags = {
    Name = "VPC Peering between foo and bar"
  }
}

resource "aws_vpc" "foo" {
  cidr_block = "10.1.0.0/16"
}

resource "aws_vpc" "bar" {
  cidr_block = "10.2.0.0/16"
}
