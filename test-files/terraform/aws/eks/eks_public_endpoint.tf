# Terraform template for EKS Cluster Public Endpoint
# Generated plan output used for rego test eks_public_endpoint_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

#VALID: eks cluster enpoint is not public
resource "aws_eks_cluster" "valid_private" {
  name     = "example"
  role_arn = aws_iam_role.example.arn

  vpc_config {
    subnet_ids              = [aws_subnet.example1.id, aws_subnet.example2.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

}

#INVALID: eks cluster endpoint is public
resource "aws_eks_cluster" "invalid_public" {
  name     = "example"
  role_arn = aws_iam_role.example.arn

  vpc_config {
    subnet_ids = [aws_subnet.example1.id, aws_subnet.example2.id]
  }

}
resource "aws_subnet" "example1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "Main"
  }
}
resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "main"
  }
}

resource "aws_subnet" "example2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "Main"
  }
}

resource "aws_iam_role" "example" {
  name = "test_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    tag-key = "tag-value"
  }
}
output "endpoint" {
  value = aws_eks_cluster.valid_private.endpoint
}

output "kubeconfig-certificate-authority-data" {
  value = aws_eks_cluster.valid_private.certificate_authority[0].data
}
