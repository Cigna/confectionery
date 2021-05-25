# Terraform template for Sagemaker Internet Access
# Generated plan output used for rego test sagemaker_notebook_internet_access_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID : Direct internet access is disabled
resource "aws_sagemaker_notebook_instance" "valid" {
  name          = "my-notebook-instance"
  role_arn      = aws_iam_role.test_role.arn
  instance_type = "ml.t2.medium"
  direct_internet_access = "Disabled"

  tags = {
    Name = "foo"
  }
}
# INVALID : Direct internet access is enabled by default
resource "aws_sagemaker_notebook_instance" "invalid" {
  name          = "my-notebook-instance"
  role_arn      = aws_iam_role.test_role.arn
  instance_type = "ml.t2.medium"

  tags = {
    Name = "foo"
  }
}

resource "aws_iam_role" "test_role" {
  name = "test_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "*",
      "Principal": {
        "Service": "sagemaker.amazonaws.com"
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