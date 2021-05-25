# Terraform template for Redshift TLS
# Generated plan output used for rego test redshift_tls_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID : require_ssl parameter is set to true
resource "aws_redshift_parameter_group" "valid" {
  name   = "parameter-group-test-terraform"
  family = "redshift-1.0"

  parameter {
    name  = "require_ssl"
    value = "true"
  }

  parameter {
    name  = "query_group"
    value = "example"
  }

  parameter {
    name  = "enable_user_activity_logging"
    value = "true"
  }
}

# INVALID : require_ssl parameter is missing
resource "aws_redshift_parameter_group" "invalid-missing" {
  name   = "parameter-group-test-terraform"
  family = "redshift-1.0"

  parameter {
    name  = "query_group"
    value = "example"
  }

  parameter {
    name  = "enable_user_activity_logging"
    value = "true"
  }
}

# INVALID : require_ssl parameter is set to false
resource "aws_redshift_parameter_group" "invalid-false" {
  name   = "parameter-group-test-terraform"
  family = "redshift-1.0"

  parameter {
    name  = "query_group"
    value = "example"
  }

  parameter {
    name  = "enable_user_activity_logging"
    value = "true"
  }
}