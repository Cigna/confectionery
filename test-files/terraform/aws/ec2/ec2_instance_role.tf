# Terraform template for EC2 Instance Role
# Generated plan output used for rego test s3_encryption_test.rego
provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# Supporting resources for instance creation
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "aws_iam_role" "test_role" {
  name = "test_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
      "Action": [
                "iam:PassRole",
                "iam:ListInstanceProfiles",
                "ec2:*"
                ],
      "Resource": "*",
      "Effect": "Allow"
    }
  ]
}
EOF

  tags = {
    tag-key = "tag-value"
  }
}

resource "aws_iam_instance_profile" "test_profile" {
  name = "test_profile"
  role = "${aws_iam_role.test_role.name}"
}

# VALID:  This instance is valid as it defines an instance profile to use
resource "aws_instance" "valid" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t3.micro"
  iam_instance_profile = "${aws_iam_instance_profile.test_profile.name}"

  tags = {
    Name = "HelloWorld"
  }
}

# INVALID: This instance is invalid as it does not define an instance profile to use
resource "aws_instance" "invalid" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"

  tags = {
    Name = "HelloWorld"
  }
}
