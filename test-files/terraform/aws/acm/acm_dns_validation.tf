# Terraform template for ACM valid and invalid examples
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/credentials"
  profile                 = "saml"
}

# VALID: ACM certificate validated by DNS
resource "aws_acm_certificate" "valid_example" {
  domain_name               = "example.com"
  subject_alternative_names = ["www.example.com", "example.org"]
  validation_method         = "DNS"
}

# INVALID: Email validated is not allowed
resource "aws_acm_certificate" "invalid_example" {
  domain_name       = "example.com"
  validation_method = "EMAIL"
}

# Example of valid certificate A
resource "aws_acm_certificate_validation" "validation_a" {
  certificate_arn = aws_acm_certificate.valid_example.arn
}

# Example of valid certificate B 
resource "aws_acm_certificate_validation" "validation_b" {
  certificate_arn = aws_acm_certificate.invalid_example.arn
}

