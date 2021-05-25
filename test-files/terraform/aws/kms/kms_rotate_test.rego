# Rego test for KMS Key Rotation
# Validating rule kms_rotate: Deny KMS Keys that do not have enable_key_rotation enabled

package rules.kms_rotate

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

mock_resources = mock_input.resources

test_kms_rotate {
	resources = mock_resources

	count(deny) == 1 with input as resources["aws_kms_key.invalid"]
	count(deny) == 1 with input as resources["aws_kms_key.blank-invalid"]
	count(deny) == 0 with input as resources["aws_kms_key.valid"]
}

# Mock input is generated plan for kms_rotate.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.18",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_kms_key.blank-invalid",
			"mode": "managed",
			"type": "aws_kms_key",
			"name": "blank-invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"deletion_window_in_days": null,
				"description": "KMS key 3",
				"enable_key_rotation": false,
				"is_enabled": true,
				"tags": null,
			},
		},
		{
			"address": "aws_kms_key.invalid",
			"mode": "managed",
			"type": "aws_kms_key",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"deletion_window_in_days": null,
				"description": "KMS key 2",
				"enable_key_rotation": false,
				"is_enabled": true,
				"tags": null,
			},
		},
		{
			"address": "aws_kms_key.valid",
			"mode": "managed",
			"type": "aws_kms_key",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"deletion_window_in_days": null,
				"description": "KMS key 1",
				"enable_key_rotation": true,
				"is_enabled": true,
				"tags": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_kms_key.blank-invalid",
			"mode": "managed",
			"type": "aws_kms_key",
			"name": "blank-invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"deletion_window_in_days": null,
					"description": "KMS key 3",
					"enable_key_rotation": false,
					"is_enabled": true,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"key_id": true,
					"key_usage": true,
					"policy": true,
				},
			},
		},
		{
			"address": "aws_kms_key.invalid",
			"mode": "managed",
			"type": "aws_kms_key",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"deletion_window_in_days": null,
					"description": "KMS key 2",
					"enable_key_rotation": false,
					"is_enabled": true,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"key_id": true,
					"key_usage": true,
					"policy": true,
				},
			},
		},
		{
			"address": "aws_kms_key.valid",
			"mode": "managed",
			"type": "aws_kms_key",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"deletion_window_in_days": null,
					"description": "KMS key 1",
					"enable_key_rotation": true,
					"is_enabled": true,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"key_id": true,
					"key_usage": true,
					"policy": true,
				},
			},
		},
	],
	"configuration": {
		"provider_config": {"aws": {
			"name": "aws",
			"version_constraint": "~> 2.41",
			"expressions": {"region": {"constant_value": "us-west-2"}},
		}},
		"root_module": {"resources": [
			{
				"address": "aws_kms_key.blank-invalid",
				"mode": "managed",
				"type": "aws_kms_key",
				"name": "blank-invalid",
				"provider_config_key": "aws",
				"expressions": {"description": {"constant_value": "KMS key 3"}},
				"schema_version": 0,
			},
			{
				"address": "aws_kms_key.invalid",
				"mode": "managed",
				"type": "aws_kms_key",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "KMS key 2"},
					"enable_key_rotation": {"constant_value": false},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_kms_key.valid",
				"mode": "managed",
				"type": "aws_kms_key",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "KMS key 1"},
					"enable_key_rotation": {"constant_value": true},
				},
				"schema_version": 0,
			},
		]},
	},
}
