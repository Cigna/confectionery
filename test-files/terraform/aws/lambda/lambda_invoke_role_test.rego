# Rego test for Lambda Invoke Role
# Validating rule lambda_invoke_role: Lambda functions should not have a iam role that can invoke lambdas.
package rules.lambda_invoke_role

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_lambda_invoke_role {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_lambda_function.valid"] == true
	resources["aws_lambda_function.invalid"] == false
}

# Mock input is generated plan for lambda_invoke_role.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_iam_role.iam_for_lambda_invalid",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "iam_for_lambda_invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"lambda:InvokeLambda\",\n      \"Principal\": {\n        \"Service\": \"lambda.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n",
				"description": null,
				"force_detach_policies": false,
				"max_session_duration": 3600,
				"name": "iam_for_lambda_invalid",
				"name_prefix": null,
				"path": "/",
				"permissions_boundary": null,
				"tags": null,
			},
		},
		{
			"address": "aws_iam_role.iam_for_lambda_valid",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "iam_for_lambda_valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"sts:AssumeRole\",\n      \"Principal\": {\n        \"Service\": \"lambda.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n",
				"description": null,
				"force_detach_policies": false,
				"max_session_duration": 3600,
				"name": "iam_for_lambda_valid",
				"name_prefix": null,
				"path": "/",
				"permissions_boundary": null,
				"tags": null,
			},
		},
		{
			"address": "aws_lambda_function.invalid",
			"mode": "managed",
			"type": "aws_lambda_function",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"dead_letter_config": [],
				"description": null,
				"environment": [{"variables": {"foo": "bar"}}],
				"file_system_config": [],
				"filename": "lambda_function_payload.zip",
				"function_name": "lambda_function_name_invalid",
				"handler": "exports.test",
				"kms_key_arn": null,
				"layers": null,
				"memory_size": 128,
				"publish": false,
				"reserved_concurrent_executions": -1,
				"runtime": "nodejs12.x",
				"s3_bucket": null,
				"s3_key": null,
				"s3_object_version": null,
				"tags": null,
				"timeout": 3,
				"timeouts": null,
				"vpc_config": [],
			},
		},
		{
			"address": "aws_lambda_function.valid",
			"mode": "managed",
			"type": "aws_lambda_function",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"dead_letter_config": [],
				"description": null,
				"environment": [{"variables": {"foo": "bar"}}],
				"file_system_config": [],
				"filename": "lambda_function_payload.zip",
				"function_name": "lambda_function_name_valid",
				"handler": "exports.test",
				"kms_key_arn": null,
				"layers": null,
				"memory_size": 128,
				"publish": false,
				"reserved_concurrent_executions": -1,
				"runtime": "nodejs12.x",
				"s3_bucket": null,
				"s3_key": null,
				"s3_object_version": null,
				"tags": null,
				"timeout": 3,
				"timeouts": null,
				"vpc_config": [],
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_iam_role.iam_for_lambda_invalid",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "iam_for_lambda_invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"lambda:InvokeLambda\",\n      \"Principal\": {\n        \"Service\": \"lambda.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "iam_for_lambda_invalid",
					"name_prefix": null,
					"path": "/",
					"permissions_boundary": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"create_date": true,
					"id": true,
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_iam_role.iam_for_lambda_valid",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "iam_for_lambda_valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"sts:AssumeRole\",\n      \"Principal\": {\n        \"Service\": \"lambda.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "iam_for_lambda_valid",
					"name_prefix": null,
					"path": "/",
					"permissions_boundary": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"create_date": true,
					"id": true,
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_lambda_function.invalid",
			"mode": "managed",
			"type": "aws_lambda_function",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"dead_letter_config": [],
					"description": null,
					"environment": [{"variables": {"foo": "bar"}}],
					"file_system_config": [],
					"filename": "lambda_function_payload.zip",
					"function_name": "lambda_function_name_invalid",
					"handler": "exports.test",
					"kms_key_arn": null,
					"layers": null,
					"memory_size": 128,
					"publish": false,
					"reserved_concurrent_executions": -1,
					"runtime": "nodejs12.x",
					"s3_bucket": null,
					"s3_key": null,
					"s3_object_version": null,
					"tags": null,
					"timeout": 3,
					"timeouts": null,
					"vpc_config": [],
				},
				"after_unknown": {
					"arn": true,
					"dead_letter_config": [],
					"environment": [{"variables": {}}],
					"file_system_config": [],
					"id": true,
					"invoke_arn": true,
					"last_modified": true,
					"qualified_arn": true,
					"role": true,
					"source_code_hash": true,
					"source_code_size": true,
					"tracing_config": true,
					"version": true,
					"vpc_config": [],
				},
			},
		},
		{
			"address": "aws_lambda_function.valid",
			"mode": "managed",
			"type": "aws_lambda_function",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"dead_letter_config": [],
					"description": null,
					"environment": [{"variables": {"foo": "bar"}}],
					"file_system_config": [],
					"filename": "lambda_function_payload.zip",
					"function_name": "lambda_function_name_valid",
					"handler": "exports.test",
					"kms_key_arn": null,
					"layers": null,
					"memory_size": 128,
					"publish": false,
					"reserved_concurrent_executions": -1,
					"runtime": "nodejs12.x",
					"s3_bucket": null,
					"s3_key": null,
					"s3_object_version": null,
					"tags": null,
					"timeout": 3,
					"timeouts": null,
					"vpc_config": [],
				},
				"after_unknown": {
					"arn": true,
					"dead_letter_config": [],
					"environment": [{"variables": {}}],
					"file_system_config": [],
					"id": true,
					"invoke_arn": true,
					"last_modified": true,
					"qualified_arn": true,
					"role": true,
					"source_code_hash": true,
					"source_code_size": true,
					"tracing_config": true,
					"version": true,
					"vpc_config": [],
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
				"address": "aws_iam_role.iam_for_lambda_invalid",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "iam_for_lambda_invalid",
				"provider_config_key": "aws",
				"expressions": {
					"assume_role_policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"lambda:InvokeLambda\",\n      \"Principal\": {\n        \"Service\": \"lambda.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n"},
					"name": {"constant_value": "iam_for_lambda_invalid"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_role.iam_for_lambda_valid",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "iam_for_lambda_valid",
				"provider_config_key": "aws",
				"expressions": {
					"assume_role_policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"sts:AssumeRole\",\n      \"Principal\": {\n        \"Service\": \"lambda.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n"},
					"name": {"constant_value": "iam_for_lambda_valid"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_lambda_function.invalid",
				"mode": "managed",
				"type": "aws_lambda_function",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"environment": [{"variables": {"constant_value": {"foo": "bar"}}}],
					"filename": {"constant_value": "lambda_function_payload.zip"},
					"function_name": {"constant_value": "lambda_function_name_invalid"},
					"handler": {"constant_value": "exports.test"},
					"role": {"references": ["aws_iam_role.iam_for_lambda_invalid"]},
					"runtime": {"constant_value": "nodejs12.x"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_lambda_function.valid",
				"mode": "managed",
				"type": "aws_lambda_function",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"environment": [{"variables": {"constant_value": {"foo": "bar"}}}],
					"filename": {"constant_value": "lambda_function_payload.zip"},
					"function_name": {"constant_value": "lambda_function_name_valid"},
					"handler": {"constant_value": "exports.test"},
					"role": {"references": ["aws_iam_role.iam_for_lambda_valid"]},
					"runtime": {"constant_value": "nodejs12.x"},
				},
				"schema_version": 0,
			},
		]},
	},
}
