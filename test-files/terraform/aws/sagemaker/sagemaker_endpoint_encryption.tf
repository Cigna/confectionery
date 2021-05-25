provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# INVALID: endpoint does not use a kms key
resource "aws_sagemaker_endpoint_configuration" "invalid" {
  name = "my-endpoint-config"

  production_variants {
    variant_name           = "variant-1"
    model_name             = "name"
    initial_instance_count = 1
    instance_type          = "ml.t2.medium"
  }

  tags = {
    Name = "foo"
  }
}

# VALID: endpoint uses a kms key
resource "aws_sagemaker_endpoint_configuration" "valid" {
  name = "my-endpoint-config"
  kms_key_arn =  "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"

  production_variants {
    variant_name           = "variant-1"
    model_name             = "name"
    initial_instance_count = 1
    instance_type          = "ml.t2.medium"
  }

  tags = {
    Name = "foo"
  }
}
