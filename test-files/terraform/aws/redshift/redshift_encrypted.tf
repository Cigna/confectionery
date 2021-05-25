provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID: Invalid cluster since it is not encrypted
resource "aws_redshift_cluster" "invalid" {
  cluster_identifier = "tf-redshift-cluster"
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
}

# VALID: Cluster is valid since it is encrypted
resource "aws_redshift_cluster" "valid" {
  cluster_identifier = "tf-redshift-cluster-valid"
  database_name      = "mynewdb"
  master_username    = "foo"
  master_password    = "Mustbe8characters"
  node_type          = "dc1.large"
  cluster_type       = "single-node"
  encrypted          = true
}