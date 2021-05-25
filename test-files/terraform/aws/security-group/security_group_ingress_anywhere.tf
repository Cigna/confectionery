# Terraform template for Security Group Ingress Anywhere
# Generated plan output used for rego test security_group_ingress_anywhere_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

#VALID: Ingress from CIDR 0.0.0.0/0 is only on ports 80 and 443
resource "aws_security_group" "valid_exact_80" {
  name        = "valid_exact_80"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "valid_exact_443" {
  name        = "valid_exact_443"
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#INVALID: Ingress from 0.0.0.0/0 includes ports other than 80 and 443
resource "aws_security_group" "invalid_include_80" {
  name        = "invalid_include_valid_80"

  ingress {
    from_port   = 79
    to_port     = 81
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "invalid_include_443" {
  name        = "invalid_include_valid_443"

  ingress {
    from_port   = 442
    to_port     = 444
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "invalid_allow_all" {
  name        = "invalid_allow_all"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}