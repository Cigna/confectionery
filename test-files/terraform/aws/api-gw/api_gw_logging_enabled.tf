# Terraform template for API Gateway Logging
# Generated plan output used for rego test api_gw_logging_enabled_test.rego

provider "aws" {
  region                  = "us-east-1"
  shared_credentials_file = "~/.aws/creds"
  profile                 = "saml"
}

# VALID - Access log setting are configured
resource "aws_api_gateway_stage" "Valid" {
  stage_name    = "prod"
  rest_api_id   = "this would be a reference to rest api"
  deployment_id = "this would be a reference to a gateway depoloyment"

 access_log_settings {
    destination_arn = "testing"
    format          = "{ \"requestId\":\"$context.requestId\", \"ip\": \"$context.identity.sourceIp\", \"caller\":\"$context.identity.caller\", \"user\":\"$context.identity.user\",\"requestTime\":\"$context.requestTime\", \"httpMethod\":\"$context.httpMethod\",\"resourcePath\":\"$context.resourcePath\", \"status\":\"$context.status\",\"protocol\":\"$context.protocol\", \"responseLength\":\"$context.responseLength\" }"
 }
}

# INVALID: No access log settings configured
resource "aws_api_gateway_stage" "InValid" {
  stage_name    = "test"
  rest_api_id   = "this would be a reference to rest api"
  deployment_id = "this would be a reference to a gateway depoloyment"
}