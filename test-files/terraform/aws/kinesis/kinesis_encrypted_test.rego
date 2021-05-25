package rules.kinesis_stream_encrypted

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

mock_resources = mock_input.resources

test_kinesis_stream_encrypted {
	resources = mock_resources

	count(deny) == 1 with input as resources["aws_kinesis_stream.invalid_stream"]
	count(deny) == 1 with input as resources["aws_kinesis_stream.invalid_stream_default"]
	count(deny) == 0 with input as resources["aws_kinesis_stream.valid_stream"]
}

# Mock input in generated from kinesis_encrypted.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.19",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_kinesis_stream.invalid_stream",
			"mode": "managed",
			"type": "aws_kinesis_stream",
			"name": "invalid_stream",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"encryption_type": "NONE",
				"enforce_consumer_deletion": false,
				"kms_key_id": null,
				"name": "terraform-kinesis-test",
				"retention_period": 48,
				"shard_count": 1,
				"shard_level_metrics": [
					"IncomingBytes",
					"OutgoingBytes",
				],
				"tags": {"Environment": "test"},
				"timeouts": null,
			},
		},
		{
			"address": "aws_kinesis_stream.invalid_stream_default",
			"mode": "managed",
			"type": "aws_kinesis_stream",
			"name": "invalid_stream_default",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"encryption_type": "KMS",
				"enforce_consumer_deletion": false,
				"kms_key_id": "alias/aws/kinesis",
				"name": "terraform-kinesis-test",
				"retention_period": 48,
				"shard_count": 1,
				"shard_level_metrics": [
					"IncomingBytes",
					"OutgoingBytes",
				],
				"tags": {"Environment": "test"},
				"timeouts": null,
			},
		},
		{
			"address": "aws_kinesis_stream.valid_stream",
			"mode": "managed",
			"type": "aws_kinesis_stream",
			"name": "valid_stream",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"encryption_type": "KMS",
				"enforce_consumer_deletion": false,
				"kms_key_id": "alias/aws/kinesis2",
				"name": "terraform-kinesis-test",
				"retention_period": 48,
				"shard_count": 1,
				"shard_level_metrics": [
					"IncomingBytes",
					"OutgoingBytes",
				],
				"tags": {"Environment": "test"},
				"timeouts": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_kinesis_stream.invalid_stream",
			"mode": "managed",
			"type": "aws_kinesis_stream",
			"name": "invalid_stream",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"encryption_type": "NONE",
					"enforce_consumer_deletion": false,
					"kms_key_id": null,
					"name": "terraform-kinesis-test",
					"retention_period": 48,
					"shard_count": 1,
					"shard_level_metrics": [
						"IncomingBytes",
						"OutgoingBytes",
					],
					"tags": {"Environment": "test"},
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"shard_level_metrics": [
						false,
						false,
					],
					"tags": {},
				},
			},
		},
		{
			"address": "aws_kinesis_stream.invalid_stream_default",
			"mode": "managed",
			"type": "aws_kinesis_stream",
			"name": "invalid_stream_default",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"encryption_type": "KMS",
					"enforce_consumer_deletion": false,
					"kms_key_id": "alias/aws/kinesis",
					"name": "terraform-kinesis-test",
					"retention_period": 48,
					"shard_count": 1,
					"shard_level_metrics": [
						"IncomingBytes",
						"OutgoingBytes",
					],
					"tags": {"Environment": "test"},
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"shard_level_metrics": [
						false,
						false,
					],
					"tags": {},
				},
			},
		},
		{
			"address": "aws_kinesis_stream.valid_stream",
			"mode": "managed",
			"type": "aws_kinesis_stream",
			"name": "valid_stream",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"encryption_type": "KMS",
					"enforce_consumer_deletion": false,
					"kms_key_id": "alias/aws/kinesis2",
					"name": "terraform-kinesis-test",
					"retention_period": 48,
					"shard_count": 1,
					"shard_level_metrics": [
						"IncomingBytes",
						"OutgoingBytes",
					],
					"tags": {"Environment": "test"},
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"shard_level_metrics": [
						false,
						false,
					],
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
				"address": "aws_kinesis_stream.invalid_stream",
				"mode": "managed",
				"type": "aws_kinesis_stream",
				"name": "invalid_stream",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "terraform-kinesis-test"},
					"retention_period": {"constant_value": 48},
					"shard_count": {"constant_value": 1},
					"shard_level_metrics": {"constant_value": [
						"IncomingBytes",
						"OutgoingBytes",
					]},
					"tags": {"constant_value": {"Environment": "test"}},
				},
				"schema_version": 1,
			},
			{
				"address": "aws_kinesis_stream.invalid_stream_default",
				"mode": "managed",
				"type": "aws_kinesis_stream",
				"name": "invalid_stream_default",
				"provider_config_key": "aws",
				"expressions": {
					"encryption_type": {"constant_value": "KMS"},
					"kms_key_id": {"constant_value": "alias/aws/kinesis"},
					"name": {"constant_value": "terraform-kinesis-test"},
					"retention_period": {"constant_value": 48},
					"shard_count": {"constant_value": 1},
					"shard_level_metrics": {"constant_value": [
						"IncomingBytes",
						"OutgoingBytes",
					]},
					"tags": {"constant_value": {"Environment": "test"}},
				},
				"schema_version": 1,
			},
			{
				"address": "aws_kinesis_stream.valid_stream",
				"mode": "managed",
				"type": "aws_kinesis_stream",
				"name": "valid_stream",
				"provider_config_key": "aws",
				"expressions": {
					"encryption_type": {"constant_value": "KMS"},
					"kms_key_id": {"constant_value": "alias/aws/kinesis2"},
					"name": {"constant_value": "terraform-kinesis-test"},
					"retention_period": {"constant_value": 48},
					"shard_count": {"constant_value": 1},
					"shard_level_metrics": {"constant_value": [
						"IncomingBytes",
						"OutgoingBytes",
					]},
					"tags": {"constant_value": {"Environment": "test"}},
				},
				"schema_version": 1,
			},
		]},
	},
}
