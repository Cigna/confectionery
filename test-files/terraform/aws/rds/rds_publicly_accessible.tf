# Terraform template for RDS Publicly Exposed
# Generated plan output used for rego test rds_publicly_accessible.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID : Publicly Accesible is set to true
resource "aws_db_instance" "invalid" {
  allocated_storage    = 10
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  name                 = "mydb"
  username             = "sql"
  password             = "password"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true
  publicly_accessible = true
}

# VALID : Publicly Accesible is set to false
resource "aws_rds_cluster_instance" "valid" {
  count              = 1
  identifier         = "aurora-cluster-demo-${count.index}"
  cluster_identifier = aws_rds_cluster.default.id
  instance_class     = "db.r4.large"
  engine             = aws_rds_cluster.default.engine
  engine_version     = aws_rds_cluster.default.engine_version
  publicly_accessible = false
}
resource "aws_rds_cluster" "default" {
  cluster_identifier = "aurora-cluster-demo"
  availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]
  database_name      = "mydb"
  master_username    = "foo"
  master_password    = "barbut8chars"
}