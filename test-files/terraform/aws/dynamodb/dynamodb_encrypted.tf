# Terraform template for Dynamodb Encryption   
# Generated plan output used for rego test dynamodb_encrypted_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID: Dynamodb table encrypted using AWS Owned CMK 
resource "aws_dynamodb_table" "invalid_dynamodb_table" {
  name             = "invalid_dynamodb_table"
  hash_key         = "TestTableHashKey"

  attribute {
    name = "TestTableHashKey"
    type = "S"
  }

  server_side_encryption {
    enabled = false
  }
}

# INVALID: Dynamodb table encrypted using AWS Owned CMK
resource "aws_dynamodb_table" "my_invalid_dynamodb_table" {
  name             = "my_invalid_dynamodb_table"
  hash_key         = "TestTableHashKey"

  attribute {
    name = "TestTableHashKey"
    type = "S"
  }

}

# VALID: Dynamodb table is encrypted using AWS managed CMK 
resource "aws_dynamodb_table" "valid_dynamodb_example" {
  name             = "valid_dynamodb_example"
  hash_key         = "TestTableHashKey"

  attribute {
    name = "TestTableHashKey"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}

