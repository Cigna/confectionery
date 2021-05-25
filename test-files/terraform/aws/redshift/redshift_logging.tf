# Terraform template for redshift logging, including an invalid and valid redshift cluster resource
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# Supportinging s3 bucket resource
resource "aws_s3_bucket" "b" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

# VALID redshift cluster with logging enabled
resource "aws_redshift_cluster" "valid" {
  cluster_identifier = "tf-redshift-cluster-valid"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
  logging {
    enable      = true
    bucket_name = "aws_s3_bucket.b"
  }
}

# INVALID redshift cluster with no logging enabled
resource "aws_redshift_cluster" "invalid" {
  cluster_identifier = "tf-redshift-cluster-invalid"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"

}

