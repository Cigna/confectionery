# Rego test for API Gateway Logging
# Validating rule api_gateway_logging_enabled: Deny an API Gateway Stage that does not have logging enabled 

package rules.api_gw_logging_enabled

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_api_gw_logging {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_api_gateway_stage.Valid"] == true
	resources["aws_api_gateway_stage.InValid"] == false
}

# Mock input is generated plan for api_gw_loggin_enabled.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.26",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_api_gateway_stage.InValid",
			"mode": "managed",
			"type": "aws_api_gateway_stage",
			"name": "InValid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"access_log_settings": [],
				"cache_cluster_enabled": null,
				"cache_cluster_size": null,
				"client_certificate_id": null,
				"deployment_id": "this would be a reference to a gateway depoloyment",
				"description": null,
				"documentation_version": null,
				"rest_api_id": "this would be a reference to rest api",
				"stage_name": "test",
				"tags": null,
				"variables": null,
				"xray_tracing_enabled": null,
			},
		},
		{
			"address": "aws_api_gateway_stage.Valid",
			"mode": "managed",
			"type": "aws_api_gateway_stage",
			"name": "Valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"access_log_settings": [{
					"destination_arn": "testing",
					"format": "{ \"requestId\":\"$context.requestId\", \"ip\": \"$context.identity.sourceIp\", \"caller\":\"$context.identity.caller\", \"user\":\"$context.identity.user\",\"requestTime\":\"$context.requestTime\", \"httpMethod\":\"$context.httpMethod\",\"resourcePath\":\"$context.resourcePath\", \"status\":\"$context.status\",\"protocol\":\"$context.protocol\", \"responseLength\":\"$context.responseLength\" }",
				}],
				"cache_cluster_enabled": null,
				"cache_cluster_size": null,
				"client_certificate_id": null,
				"deployment_id": "this would be a reference to a gateway depoloyment",
				"description": null,
				"documentation_version": null,
				"rest_api_id": "this would be a reference to rest api",
				"stage_name": "prod",
				"tags": null,
				"variables": null,
				"xray_tracing_enabled": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_api_gateway_stage.InValid",
			"mode": "managed",
			"type": "aws_api_gateway_stage",
			"name": "InValid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access_log_settings": [],
					"cache_cluster_enabled": null,
					"cache_cluster_size": null,
					"client_certificate_id": null,
					"deployment_id": "this would be a reference to a gateway depoloyment",
					"description": null,
					"documentation_version": null,
					"rest_api_id": "this would be a reference to rest api",
					"stage_name": "test",
					"tags": null,
					"variables": null,
					"xray_tracing_enabled": null,
				},
				"after_unknown": {
					"access_log_settings": [],
					"arn": true,
					"execution_arn": true,
					"id": true,
					"invoke_url": true,
				},
			},
		},
		{
			"address": "aws_api_gateway_stage.Valid",
			"mode": "managed",
			"type": "aws_api_gateway_stage",
			"name": "Valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access_log_settings": [{
						"destination_arn": "testing",
						"format": "{ \"requestId\":\"$context.requestId\", \"ip\": \"$context.identity.sourceIp\", \"caller\":\"$context.identity.caller\", \"user\":\"$context.identity.user\",\"requestTime\":\"$context.requestTime\", \"httpMethod\":\"$context.httpMethod\",\"resourcePath\":\"$context.resourcePath\", \"status\":\"$context.status\",\"protocol\":\"$context.protocol\", \"responseLength\":\"$context.responseLength\" }",
					}],
					"cache_cluster_enabled": null,
					"cache_cluster_size": null,
					"client_certificate_id": null,
					"deployment_id": "this would be a reference to a gateway depoloyment",
					"description": null,
					"documentation_version": null,
					"rest_api_id": "this would be a reference to rest api",
					"stage_name": "prod",
					"tags": null,
					"variables": null,
					"xray_tracing_enabled": null,
				},
				"after_unknown": {
					"access_log_settings": [{}],
					"arn": true,
					"execution_arn": true,
					"id": true,
					"invoke_url": true,
				},
			},
		},
	],
	"configuration": {
		"provider_config": {"aws": {
			"name": "aws",
			"expressions": {
				"profile": {"constant_value": "saml"},
				"region": {"constant_value": "us-east-1"},
				"shared_credentials_file": {"constant_value": "~/.aws/creds"},
			},
		}},
		"root_module": {"resources": [
			{
				"address": "aws_api_gateway_stage.InValid",
				"mode": "managed",
				"type": "aws_api_gateway_stage",
				"name": "InValid",
				"provider_config_key": "aws",
				"expressions": {
					"deployment_id": {"constant_value": "this would be a reference to a gateway depoloyment"},
					"rest_api_id": {"constant_value": "this would be a reference to rest api"},
					"stage_name": {"constant_value": "test"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_api_gateway_stage.Valid",
				"mode": "managed",
				"type": "aws_api_gateway_stage",
				"name": "Valid",
				"provider_config_key": "aws",
				"expressions": {
					"access_log_settings": [{
						"destination_arn": {"constant_value": "testing"},
						"format": {"constant_value": "{ \"requestId\":\"$context.requestId\", \"ip\": \"$context.identity.sourceIp\", \"caller\":\"$context.identity.caller\", \"user\":\"$context.identity.user\",\"requestTime\":\"$context.requestTime\", \"httpMethod\":\"$context.httpMethod\",\"resourcePath\":\"$context.resourcePath\", \"status\":\"$context.status\",\"protocol\":\"$context.protocol\", \"responseLength\":\"$context.responseLength\" }"},
					}],
					"deployment_id": {"constant_value": "this would be a reference to a gateway depoloyment"},
					"rest_api_id": {"constant_value": "this would be a reference to rest api"},
					"stage_name": {"constant_value": "prod"},
				},
				"schema_version": 0,
			},
		]},
	},
}
