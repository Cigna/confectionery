# Rego test for API Gateway DNS Mapping
# Validating rule api_gateway_custom_domain: Deny an API Gateway that does not have a custom DNS name

package rules.api_gw_custom_domain

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_api_gw_custom_domain {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_api_gateway_rest_api.MyValidAPI"] == true
	resources["aws_api_gateway_rest_api.MyInvalidAPI"] == false
}

# Mock input is generated plan for api_gw_loggin_enabled.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.19",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_api_gateway_base_path_mapping.test",
			"mode": "managed",
			"type": "aws_api_gateway_base_path_mapping",
			"name": "test",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"base_path": null,
				"domain_name": "example.com",
				"stage_name": "live",
			},
		},
		{
			"address": "aws_api_gateway_deployment.example",
			"mode": "managed",
			"type": "aws_api_gateway_deployment",
			"name": "example",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": null,
				"stage_description": null,
				"stage_name": "live",
				"triggers": null,
				"variables": null,
			},
		},
		{
			"address": "aws_api_gateway_domain_name.example",
			"mode": "managed",
			"type": "aws_api_gateway_domain_name",
			"name": "example",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"certificate_arn": null,
				"certificate_body": null,
				"certificate_chain": null,
				"certificate_name": null,
				"certificate_private_key": null,
				"domain_name": "example.com",
				"regional_certificate_arn": null,
				"regional_certificate_name": null,
				"tags": null,
			},
		},
		{
			"address": "aws_api_gateway_rest_api.MyInvalidAPI",
			"mode": "managed",
			"type": "aws_api_gateway_rest_api",
			"name": "MyInvalidAPI",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"api_key_source": "HEADER",
				"binary_media_types": null,
				"body": null,
				"description": "This is my API for demonstration purposes",
				"minimum_compression_size": -1,
				"name": "MyInValidAPI",
				"policy": null,
				"tags": null,
			},
		},
		{
			"address": "aws_api_gateway_rest_api.MyValidAPI",
			"mode": "managed",
			"type": "aws_api_gateway_rest_api",
			"name": "MyValidAPI",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"api_key_source": "HEADER",
				"binary_media_types": null,
				"body": null,
				"description": "This is my API for demonstration purposes",
				"minimum_compression_size": -1,
				"name": "MyValidAPI",
				"policy": null,
				"tags": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_api_gateway_base_path_mapping.test",
			"mode": "managed",
			"type": "aws_api_gateway_base_path_mapping",
			"name": "test",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"base_path": null,
					"domain_name": "example.com",
					"stage_name": "live",
				},
				"after_unknown": {
					"api_id": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_api_gateway_deployment.example",
			"mode": "managed",
			"type": "aws_api_gateway_deployment",
			"name": "example",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": null,
					"stage_description": null,
					"stage_name": "live",
					"triggers": null,
					"variables": null,
				},
				"after_unknown": {
					"created_date": true,
					"execution_arn": true,
					"id": true,
					"invoke_url": true,
					"rest_api_id": true,
				},
			},
		},
		{
			"address": "aws_api_gateway_domain_name.example",
			"mode": "managed",
			"type": "aws_api_gateway_domain_name",
			"name": "example",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"certificate_arn": null,
					"certificate_body": null,
					"certificate_chain": null,
					"certificate_name": null,
					"certificate_private_key": null,
					"domain_name": "example.com",
					"regional_certificate_arn": null,
					"regional_certificate_name": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"certificate_upload_date": true,
					"cloudfront_domain_name": true,
					"cloudfront_zone_id": true,
					"endpoint_configuration": true,
					"id": true,
					"regional_domain_name": true,
					"regional_zone_id": true,
					"security_policy": true,
				},
			},
		},
		{
			"address": "aws_api_gateway_rest_api.MyInvalidAPI",
			"mode": "managed",
			"type": "aws_api_gateway_rest_api",
			"name": "MyInvalidAPI",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"api_key_source": "HEADER",
					"binary_media_types": null,
					"body": null,
					"description": "This is my API for demonstration purposes",
					"minimum_compression_size": -1,
					"name": "MyInValidAPI",
					"policy": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"created_date": true,
					"endpoint_configuration": true,
					"execution_arn": true,
					"id": true,
					"root_resource_id": true,
				},
			},
		},
		{
			"address": "aws_api_gateway_rest_api.MyValidAPI",
			"mode": "managed",
			"type": "aws_api_gateway_rest_api",
			"name": "MyValidAPI",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"api_key_source": "HEADER",
					"binary_media_types": null,
					"body": null,
					"description": "This is my API for demonstration purposes",
					"minimum_compression_size": -1,
					"name": "MyValidAPI",
					"policy": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"created_date": true,
					"endpoint_configuration": true,
					"execution_arn": true,
					"id": true,
					"root_resource_id": true,
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
				"address": "aws_api_gateway_base_path_mapping.test",
				"mode": "managed",
				"type": "aws_api_gateway_base_path_mapping",
				"name": "test",
				"provider_config_key": "aws",
				"expressions": {
					"api_id": {"references": ["aws_api_gateway_rest_api.MyValidAPI"]},
					"domain_name": {"references": ["aws_api_gateway_domain_name.example"]},
					"stage_name": {"references": ["aws_api_gateway_deployment.example"]},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_api_gateway_deployment.example",
				"mode": "managed",
				"type": "aws_api_gateway_deployment",
				"name": "example",
				"provider_config_key": "aws",
				"expressions": {
					"rest_api_id": {"references": ["aws_api_gateway_rest_api.MyValidAPI"]},
					"stage_name": {"constant_value": "live"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_api_gateway_domain_name.example",
				"mode": "managed",
				"type": "aws_api_gateway_domain_name",
				"name": "example",
				"provider_config_key": "aws",
				"expressions": {"domain_name": {"constant_value": "example.com"}},
				"schema_version": 0,
			},
			{
				"address": "aws_api_gateway_rest_api.MyInvalidAPI",
				"mode": "managed",
				"type": "aws_api_gateway_rest_api",
				"name": "MyInvalidAPI",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "This is my API for demonstration purposes"},
					"name": {"constant_value": "MyInValidAPI"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_api_gateway_rest_api.MyValidAPI",
				"mode": "managed",
				"type": "aws_api_gateway_rest_api",
				"name": "MyValidAPI",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "This is my API for demonstration purposes"},
					"name": {"constant_value": "MyValidAPI"},
				},
				"schema_version": 0,
			},
		]},
	},
}
