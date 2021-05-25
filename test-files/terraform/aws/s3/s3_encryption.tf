# Terraform template for S3 Bucket Encryption
# Generated plan output used for rego test s3_encryption_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}


resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
}

# INVALID: Not encrypted with aws:kms or AES256
resource "aws_s3_bucket" "unencrypted" {
  bucket = "unencrypted"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.mykey.arn}"
        sse_algorithm     = "aws"
      }
    }
  }
}

# VALID: Encrypted with AES
resource "aws_s3_bucket" "aes_encrypted" {
  bucket = "aes_encrypted"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.mykey.arn}"
        sse_algorithm     = "AES256"
      }
    }
  }
}

# VALID: Encrypted with KMS
resource "aws_s3_bucket" "kms_encrypted" {
  bucket = "kms_encrypted"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = "${aws_kms_key.mykey.arn}"
        sse_algorithm     = "aws:kms"
      }
    }
  }
}



