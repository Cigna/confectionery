# Terraform template for Security Group Ingress Port Range
# Generated plan output used for rego test security_group_ingress_port_range_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID : security group has limited ingress port range
resource "aws_security_group" "limited_range" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"

  ingress {
    description = "TLS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}

# VALID : security group allows all ingress port range locally
resource "aws_security_group" "self_referencing" {
  name        = "allow_sg_local"
  description = "Allow all traffic within SG"

  ingress {
    description = "All traffic within SG"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    cidr_blocks = []
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_sg_local"
  }
}

# INVALID : security group allows all ingress port range locally and within given cidr blocks
resource "aws_security_group" "self_referencing_with_cidr_blocks" {
  name        = "allow_sg_local_with_cidr_blocks"
  description = "Allow all traffic within SG and cidr blocks"

  ingress {
    description = "All traffic within SG and given cidr blocks"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_sg_local_with_cidr_blocks"
  }
}

# INVALID : security group has an open ingress port range
resource "aws_security_group" "open_range" {
  name = "open"

  ingress {
    description = "Open from VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VALID : security group has no ingress rule
resource "aws_security_group" "no_ingress" {
  name = "noingress"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}