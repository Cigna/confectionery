# Rego test for SQS Server Side Encryption
# Validating rule sqs_server_side_encryption: Deny SQS queues that do not have server side encryption.
package rules.sqs_server_side_encryption

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_sqs_server_side_encryption {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_sqs_queue.valid"] == true
	resources["aws_sqs_queue.invalid"] == false
}

# Mock input is generated plan for sqs_server_side_encryption.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_sqs_queue.invalid",
			"mode": "managed",
			"type": "aws_sqs_queue",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"content_based_deduplication": false,
				"delay_seconds": 90,
				"fifo_queue": false,
				"kms_master_key_id": null,
				"max_message_size": 2048,
				"message_retention_seconds": 86400,
				"name": "terraform-example-queue",
				"name_prefix": null,
				"receive_wait_time_seconds": 10,
				"redrive_policy": "{\"deadLetterTargetArn\":null,\"maxReceiveCount\":null}",
				"tags": {"Environment": "production"},
				"visibility_timeout_seconds": 30,
			},
		},
		{
			"address": "aws_sqs_queue.valid",
			"mode": "managed",
			"type": "aws_sqs_queue",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"content_based_deduplication": false,
				"delay_seconds": 90,
				"fifo_queue": false,
				"kms_master_key_id": "alias/aws/sns",
				"max_message_size": 2048,
				"message_retention_seconds": 86400,
				"name": "terraform-example-queue",
				"name_prefix": null,
				"receive_wait_time_seconds": 10,
				"redrive_policy": "{\"deadLetterTargetArn\":null,\"maxReceiveCount\":null}",
				"tags": {"Environment": "production"},
				"visibility_timeout_seconds": 30,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_sqs_queue.invalid",
			"mode": "managed",
			"type": "aws_sqs_queue",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"content_based_deduplication": false,
					"delay_seconds": 90,
					"fifo_queue": false,
					"kms_master_key_id": null,
					"max_message_size": 2048,
					"message_retention_seconds": 86400,
					"name": "terraform-example-queue",
					"name_prefix": null,
					"receive_wait_time_seconds": 10,
					"redrive_policy": "{\"deadLetterTargetArn\":null,\"maxReceiveCount\":null}",
					"tags": {"Environment": "production"},
					"visibility_timeout_seconds": 30,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"kms_data_key_reuse_period_seconds": true,
					"policy": true,
					"tags": {},
				},
			},
		},
		{
			"address": "aws_sqs_queue.valid",
			"mode": "managed",
			"type": "aws_sqs_queue",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"content_based_deduplication": false,
					"delay_seconds": 90,
					"fifo_queue": false,
					"kms_master_key_id": "alias/aws/sns",
					"max_message_size": 2048,
					"message_retention_seconds": 86400,
					"name": "terraform-example-queue",
					"name_prefix": null,
					"receive_wait_time_seconds": 10,
					"redrive_policy": "{\"deadLetterTargetArn\":null,\"maxReceiveCount\":null}",
					"tags": {"Environment": "production"},
					"visibility_timeout_seconds": 30,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"kms_data_key_reuse_period_seconds": true,
					"policy": true,
					"tags": {},
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
				"address": "aws_sqs_queue.invalid",
				"mode": "managed",
				"type": "aws_sqs_queue",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"delay_seconds": {"constant_value": 90},
					"max_message_size": {"constant_value": 2048},
					"message_retention_seconds": {"constant_value": 86400},
					"name": {"constant_value": "terraform-example-queue"},
					"receive_wait_time_seconds": {"constant_value": 10},
					"redrive_policy": {},
					"tags": {"constant_value": {"Environment": "production"}},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_sqs_queue.valid",
				"mode": "managed",
				"type": "aws_sqs_queue",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"delay_seconds": {"constant_value": 90},
					"kms_master_key_id": {"constant_value": "alias/aws/sns"},
					"max_message_size": {"constant_value": 2048},
					"message_retention_seconds": {"constant_value": 86400},
					"name": {"constant_value": "terraform-example-queue"},
					"receive_wait_time_seconds": {"constant_value": 10},
					"redrive_policy": {},
					"tags": {"constant_value": {"Environment": "production"}},
				},
				"schema_version": 0,
			},
		]},
	},
}
