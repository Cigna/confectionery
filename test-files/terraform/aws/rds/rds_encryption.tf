# Terraform template for RDS Encryption
# Generated plan output used for rego test rds_encryption_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID : encryption is enabled with customer kms key
resource "aws_db_instance" "valid-encryption" {
  allocated_storage       = 100
  db_subnet_group_name    = "db-subnetgrp"
  engine                  = "postgres"
  engine_version          = "11.5"
  identifier              = "muffy-test"
  instance_class          = "db.m5.large"
  password                = "password"
  skip_final_snapshot     = true
  username                = "postgres"
  kms_key_id              = "arn:aws:kms:us-east-1:123456789012:key/6d749788-dbdb-4e6b-ad73-eb0278614abc"
  storage_encrypted       = true
  backup_retention_period = 6
  #multi_az              = true
  auto_minor_version_upgrade = false
}

# INVALID : encryption is not enabled with customer kms key
resource "aws_rds_cluster" "invalid-encryption" {
  cluster_identifier      = "aurora-cluster-demo"
  engine                  = "aurora-mysql"
  engine_version          = "5.7.mysql_aurora.2.03.2"
  availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "bar"
  preferred_backup_window = "07:00-09:00"
  storage_encrypted       = true
  backup_retention_period = 7
}
