provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID: no kms key defined
resource "aws_sagemaker_notebook_instance" "invalid" {
  name          = "my-notebook-instance"
  role_arn      = "arn"
  instance_type = "ml.t2.medium"

  tags = {
    Name = "foo"
  }
}

# VALID: kms key defined
resource "aws_sagemaker_notebook_instance" "valid" {
  name          = "my-notebook-instance-valid"
  role_arn      = "arn"
  instance_type = "ml.t2.medium"
  kms_key_id    =  "rab3wuqwgja25ct3n4jdj2tzu4"

  tags = {
    Name = "foo"
  }
}