 # Terraform template for Elasticsearch resource with a valid and invalid configuration
 # Generated plan output used for rego test elasticsearch_vpc_test.rego

 provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "main"
  }
}

resource "aws_subnet" "main" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "Main"
  }
}

resource "aws_security_group" "es" {
  name        = "test-elasticsearch-testdomain"
  description = "Managed by Terraform"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"

    cidr_blocks = [
      aws_vpc.main.cidr_block,
    ]
  }
}

resource "aws_iam_service_linked_role" "es" {
  aws_service_name = "es.amazonaws.com"
}

#VALID: elasticsearch resource contains VPC
resource "aws_elasticsearch_domain" "valid-es" {
  domain_name           = "testdomain"
  elasticsearch_version = "6.3"

  cluster_config {
    instance_type = "m4.large.elasticsearch"
  }


  vpc_options {
    subnet_ids = [
      aws_subnet.main.id
    ]

    security_group_ids = [aws_security_group.es.id]
  }

  snapshot_options {
    automated_snapshot_start_hour = 23
  }

  tags = {
    Domain = "TestDomain"
  }

  depends_on = [aws_iam_service_linked_role.es]
}


#INVALID: elasticsearch resource does not have VPC
resource "aws_elasticsearch_domain" "invalid-es" {
  domain_name           = "testdomain"
  elasticsearch_version = "6.3"

  cluster_config {
    instance_type = "m4.large.elasticsearch"
  }

  snapshot_options {
    automated_snapshot_start_hour = 23
  }

  tags = {
    Domain = "TestDomain"
  }

  depends_on = [aws_iam_service_linked_role.es]
}