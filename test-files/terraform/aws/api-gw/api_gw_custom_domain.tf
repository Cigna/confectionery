provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID : api-gateway rest-api is attached to deployment & path mapping
resource "aws_api_gateway_rest_api" "MyValidAPI" {
  name        = "MyValidAPI"
  description = "This is my API for demonstration purposes"
}

resource "aws_api_gateway_deployment" "example" {
  # See aws_api_gateway_rest_api docs for how to create this
  rest_api_id = aws_api_gateway_rest_api.MyValidAPI.id
  stage_name  = "live"
}

resource "aws_api_gateway_domain_name" "example" {
  domain_name = "example.com"

}

resource "aws_api_gateway_base_path_mapping" "test" {
  api_id      = aws_api_gateway_rest_api.MyValidAPI.id
  stage_name  = aws_api_gateway_deployment.example.stage_name
  domain_name = aws_api_gateway_domain_name.example.domain_name
}

# INVALID : api-gateway rest-api is not attached to deployment & path mapping
resource "aws_api_gateway_rest_api" "MyInvalidAPI" {
  name        = "MyInValidAPI"
  description = "This is my API for demonstration purposes"
}