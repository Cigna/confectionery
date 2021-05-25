# Terraform template for EKS Control Plane Logging
# Generated plan output used for rego test eks_controlplane_logging_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID: Control plane logging is enabled
resource "aws_eks_cluster" "valid_eks_cluster" {
  name     = "valid_eks_cluster"
  role_arn = "arn:aws:iam::123456789000:user/*"
  enabled_cluster_log_types = ["api", "controllerManager", "scheduler", "audit", "authenticator"] 

  vpc_config {
    subnet_ids = ["subnet-abcde123", "subnet-bcdef456", "subnet-fghi320b" ]
  }
}

# INVALID: Control plane logging is not enabled
resource "aws_eks_cluster" "invalid_eks_cluster" {
  name     = "invalid_eks_cluster"
  role_arn = "arn:aws:iam::123456789000:user/*"

  vpc_config {
    subnet_ids = ["subnet-abcde123", "subnet-bcdef456", "subnet-fghi320b" ]
  }
}




