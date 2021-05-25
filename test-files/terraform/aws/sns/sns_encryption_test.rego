# Rego test for SNS Encryption
# Validating rule sns_encryption: Deny SNS topics that are not server-side encrypted

package rules.sns_encryption

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_sns_encryption {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_sns_topic.valid_example"] == true
	resources["aws_sns_topic.invalid_example"] == false
}

# Mock input is generated plan for sns_encryption.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.29",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_sns_topic.invalid_example",
			"mode": "managed",
			"type": "aws_sns_topic",
			"name": "invalid_example",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"application_failure_feedback_role_arn": null,
				"application_success_feedback_role_arn": null,
				"application_success_feedback_sample_rate": null,
				"delivery_policy": null,
				"display_name": null,
				"http_failure_feedback_role_arn": null,
				"http_success_feedback_role_arn": null,
				"http_success_feedback_sample_rate": null,
				"kms_master_key_id": null,
				"lambda_failure_feedback_role_arn": null,
				"lambda_success_feedback_role_arn": null,
				"lambda_success_feedback_sample_rate": null,
				"name": "invalid-unencrypted-topic",
				"name_prefix": null,
				"sqs_failure_feedback_role_arn": null,
				"sqs_success_feedback_role_arn": null,
				"sqs_success_feedback_sample_rate": null,
				"tags": null,
			},
		},
		{
			"address": "aws_sns_topic.valid_example",
			"mode": "managed",
			"type": "aws_sns_topic",
			"name": "valid_example",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"application_failure_feedback_role_arn": null,
				"application_success_feedback_role_arn": null,
				"application_success_feedback_sample_rate": null,
				"delivery_policy": null,
				"display_name": null,
				"http_failure_feedback_role_arn": null,
				"http_success_feedback_role_arn": null,
				"http_success_feedback_sample_rate": null,
				"kms_master_key_id": "alias/aws/sns",
				"lambda_failure_feedback_role_arn": null,
				"lambda_success_feedback_role_arn": null,
				"lambda_success_feedback_sample_rate": null,
				"name": "valid-encrypted-topic",
				"name_prefix": null,
				"sqs_failure_feedback_role_arn": null,
				"sqs_success_feedback_role_arn": null,
				"sqs_success_feedback_sample_rate": null,
				"tags": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_sns_topic.invalid_example",
			"mode": "managed",
			"type": "aws_sns_topic",
			"name": "invalid_example",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"application_failure_feedback_role_arn": null,
					"application_success_feedback_role_arn": null,
					"application_success_feedback_sample_rate": null,
					"delivery_policy": null,
					"display_name": null,
					"http_failure_feedback_role_arn": null,
					"http_success_feedback_role_arn": null,
					"http_success_feedback_sample_rate": null,
					"kms_master_key_id": null,
					"lambda_failure_feedback_role_arn": null,
					"lambda_success_feedback_role_arn": null,
					"lambda_success_feedback_sample_rate": null,
					"name": "invalid-unencrypted-topic",
					"name_prefix": null,
					"sqs_failure_feedback_role_arn": null,
					"sqs_success_feedback_role_arn": null,
					"sqs_success_feedback_sample_rate": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"policy": true,
				},
			},
		},
		{
			"address": "aws_sns_topic.valid_example",
			"mode": "managed",
			"type": "aws_sns_topic",
			"name": "valid_example",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"application_failure_feedback_role_arn": null,
					"application_success_feedback_role_arn": null,
					"application_success_feedback_sample_rate": null,
					"delivery_policy": null,
					"display_name": null,
					"http_failure_feedback_role_arn": null,
					"http_success_feedback_role_arn": null,
					"http_success_feedback_sample_rate": null,
					"kms_master_key_id": "alias/aws/sns",
					"lambda_failure_feedback_role_arn": null,
					"lambda_success_feedback_role_arn": null,
					"lambda_success_feedback_sample_rate": null,
					"name": "valid-encrypted-topic",
					"name_prefix": null,
					"sqs_failure_feedback_role_arn": null,
					"sqs_success_feedback_role_arn": null,
					"sqs_success_feedback_sample_rate": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"policy": true,
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
				"address": "aws_sns_topic.invalid_example",
				"mode": "managed",
				"type": "aws_sns_topic",
				"name": "invalid_example",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "invalid-unencrypted-topic"}},
				"schema_version": 0,
			},
			{
				"address": "aws_sns_topic.valid_example",
				"mode": "managed",
				"type": "aws_sns_topic",
				"name": "valid_example",
				"provider_config_key": "aws",
				"expressions": {
					"kms_master_key_id": {"constant_value": "alias/aws/sns"},
					"name": {"constant_value": "valid-encrypted-topic"},
				},
				"schema_version": 0,
			},
		]},
	},
}
