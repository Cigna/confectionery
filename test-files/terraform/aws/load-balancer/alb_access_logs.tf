#Terraform template for Application Load Balancer access logging configuration
#Generated plan output used for rego alb_access_logs.tf
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID: access logs enabled
resource "aws_lb" "valid_logs" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "application"

  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.lb_logs.bucket
    prefix  = "test-lb"
    enabled = true
  }

  tags = {
    Environment = "production"
  }
}

# INVALID: access logs block not specified
resource "aws_lb" "invalid_logs" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "application"

  tags = {
    Environment = "production"
  }
}

# Helper resource and does not affect policy
resource "aws_s3_bucket" "lb_logs" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

