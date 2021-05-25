# Rego test file for Dynamodb Encryption 
# Validating rule dynamodb_encrypted:Deny dynamodb tables that are encrypted using AWS Owned CMK
package rules.dynamodb_encrypted

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_dynamodb_encrypted {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_dynamodb_table.valid_dynamodb_example"] == true
	resources["aws_dynamodb_table.my_invalid_dynamodb_table"] == false
	resources["aws_dynamodb_table.invalid_dynamodb_table"] == false
}

# Mock input is generated plan for dynamodb_encrypted.tf

mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.13.2",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_dynamodb_table.invalid_dynamodb_table",
			"mode": "managed",
			"type": "aws_dynamodb_table",
			"name": "invalid_dynamodb_table",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 1,
			"values": {
				"attribute": [{
					"name": "TestTableHashKey",
					"type": "S",
				}],
				"billing_mode": "PROVISIONED",
				"global_secondary_index": [],
				"hash_key": "TestTableHashKey",
				"local_secondary_index": [],
				"name": "invalid_dynamodb_table",
				"range_key": null,
				"read_capacity": null,
				"replica": [],
				"server_side_encryption": [{"enabled": false}],
				"stream_enabled": null,
				"tags": null,
				"timeouts": null,
				"ttl": [],
				"write_capacity": null,
			},
		},
		{
			"address": "aws_dynamodb_table.my_invalid_dynamodb_table",
			"mode": "managed",
			"type": "aws_dynamodb_table",
			"name": "my_invalid_dynamodb_table",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 1,
			"values": {
				"attribute": [{
					"name": "TestTableHashKey",
					"type": "S",
				}],
				"billing_mode": "PROVISIONED",
				"global_secondary_index": [],
				"hash_key": "TestTableHashKey",
				"local_secondary_index": [],
				"name": "my_invalid_dynamodb_table",
				"range_key": null,
				"read_capacity": null,
				"replica": [],
				"stream_enabled": null,
				"tags": null,
				"timeouts": null,
				"ttl": [],
				"write_capacity": null,
			},
		},
		{
			"address": "aws_dynamodb_table.valid_dynamodb_example",
			"mode": "managed",
			"type": "aws_dynamodb_table",
			"name": "valid_dynamodb_example",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 1,
			"values": {
				"attribute": [{
					"name": "TestTableHashKey",
					"type": "S",
				}],
				"billing_mode": "PROVISIONED",
				"global_secondary_index": [],
				"hash_key": "TestTableHashKey",
				"local_secondary_index": [],
				"name": "valid_dynamodb_example",
				"range_key": null,
				"read_capacity": null,
				"replica": [],
				"server_side_encryption": [{"enabled": true}],
				"stream_enabled": null,
				"tags": null,
				"timeouts": null,
				"ttl": [],
				"write_capacity": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_dynamodb_table.invalid_dynamodb_table",
			"mode": "managed",
			"type": "aws_dynamodb_table",
			"name": "invalid_dynamodb_table",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"attribute": [{
						"name": "TestTableHashKey",
						"type": "S",
					}],
					"billing_mode": "PROVISIONED",
					"global_secondary_index": [],
					"hash_key": "TestTableHashKey",
					"local_secondary_index": [],
					"name": "invalid_dynamodb_table",
					"range_key": null,
					"read_capacity": null,
					"replica": [],
					"server_side_encryption": [{"enabled": false}],
					"stream_enabled": null,
					"tags": null,
					"timeouts": null,
					"ttl": [],
					"write_capacity": null,
				},
				"after_unknown": {
					"arn": true,
					"attribute": [{}],
					"global_secondary_index": [],
					"id": true,
					"local_secondary_index": [],
					"point_in_time_recovery": true,
					"replica": [],
					"server_side_encryption": [{"kms_key_arn": true}],
					"stream_arn": true,
					"stream_label": true,
					"stream_view_type": true,
					"ttl": [],
				},
			},
		},
		{
			"address": "aws_dynamodb_table.my_invalid_dynamodb_table",
			"mode": "managed",
			"type": "aws_dynamodb_table",
			"name": "my_invalid_dynamodb_table",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"attribute": [{
						"name": "TestTableHashKey",
						"type": "S",
					}],
					"billing_mode": "PROVISIONED",
					"global_secondary_index": [],
					"hash_key": "TestTableHashKey",
					"local_secondary_index": [],
					"name": "my_invalid_dynamodb_table",
					"range_key": null,
					"read_capacity": null,
					"replica": [],
					"stream_enabled": null,
					"tags": null,
					"timeouts": null,
					"ttl": [],
					"write_capacity": null,
				},
				"after_unknown": {
					"arn": true,
					"attribute": [{}],
					"global_secondary_index": [],
					"id": true,
					"local_secondary_index": [],
					"point_in_time_recovery": true,
					"replica": [],
					"server_side_encryption": true,
					"stream_arn": true,
					"stream_label": true,
					"stream_view_type": true,
					"ttl": [],
				},
			},
		},
		{
			"address": "aws_dynamodb_table.valid_dynamodb_example",
			"mode": "managed",
			"type": "aws_dynamodb_table",
			"name": "valid_dynamodb_example",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"attribute": [{
						"name": "TestTableHashKey",
						"type": "S",
					}],
					"billing_mode": "PROVISIONED",
					"global_secondary_index": [],
					"hash_key": "TestTableHashKey",
					"local_secondary_index": [],
					"name": "valid_dynamodb_example",
					"range_key": null,
					"read_capacity": null,
					"replica": [],
					"server_side_encryption": [{"enabled": true}],
					"stream_enabled": null,
					"tags": null,
					"timeouts": null,
					"ttl": [],
					"write_capacity": null,
				},
				"after_unknown": {
					"arn": true,
					"attribute": [{}],
					"global_secondary_index": [],
					"id": true,
					"local_secondary_index": [],
					"point_in_time_recovery": true,
					"replica": [],
					"server_side_encryption": [{"kms_key_arn": true}],
					"stream_arn": true,
					"stream_label": true,
					"stream_view_type": true,
					"ttl": [],
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
				"address": "aws_dynamodb_table.invalid_dynamodb_table",
				"mode": "managed",
				"type": "aws_dynamodb_table",
				"name": "invalid_dynamodb_table",
				"provider_config_key": "aws",
				"expressions": {
					"attribute": [{
						"name": {"constant_value": "TestTableHashKey"},
						"type": {"constant_value": "S"},
					}],
					"hash_key": {"constant_value": "TestTableHashKey"},
					"name": {"constant_value": "invalid_dynamodb_table"},
					"server_side_encryption": [{"enabled": {"constant_value": false}}],
				},
				"schema_version": 1,
			},
			{
				"address": "aws_dynamodb_table.my_invalid_dynamodb_table",
				"mode": "managed",
				"type": "aws_dynamodb_table",
				"name": "my_invalid_dynamodb_table",
				"provider_config_key": "aws",
				"expressions": {
					"attribute": [{
						"name": {"constant_value": "TestTableHashKey"},
						"type": {"constant_value": "S"},
					}],
					"hash_key": {"constant_value": "TestTableHashKey"},
					"name": {"constant_value": "my_invalid_dynamodb_table"},
				},
				"schema_version": 1,
			},
			{
				"address": "aws_dynamodb_table.valid_dynamodb_example",
				"mode": "managed",
				"type": "aws_dynamodb_table",
				"name": "valid_dynamodb_example",
				"provider_config_key": "aws",
				"expressions": {
					"attribute": [{
						"name": {"constant_value": "TestTableHashKey"},
						"type": {"constant_value": "S"},
					}],
					"hash_key": {"constant_value": "TestTableHashKey"},
					"name": {"constant_value": "valid_dynamodb_example"},
					"server_side_encryption": [{"enabled": {"constant_value": true}}],
				},
				"schema_version": 1,
			},
		]},
	},
}
