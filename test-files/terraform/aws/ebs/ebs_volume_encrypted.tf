#Terraform template for EBS Volume Encryption
#Generated plan output is used for rego test ebs_volume_encrypted.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

#This resource is valid because encryption = true
resource "aws_ebs_volume" "valid" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted = true

  tags = {
    Name = "HelloWorld"
  }
}

#This resource is invalid because encryption = false
resource "aws_ebs_volume" "invalid" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted = false

  tags = {
    Name = "HelloWorld"
  }
}