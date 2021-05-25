#Rego test for EBS Volume Encryption
#Validating rule for ebs_volume_encryption: Deny EBS Volumes that are not encrypted
package rules.ebs_volume_encrypted

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

mock_resources = mock_input.resources

test_ebs_volume_encrypted {
	resources = mock_resources

	count(deny) == 1 with input as resources["aws_ebs_volume.invalid"]
	count(deny) == 0 with input as resources["aws_ebs_volume.valid"]
}

#Mock input is generated plan for ebs_volume_encryption.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_ebs_volume.invalid",
			"mode": "managed",
			"type": "aws_ebs_volume",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"availability_zone": "us-west-2a",
				"encrypted": false,
				"multi_attach_enabled": null,
				"outpost_arn": null,
				"size": 40,
				"tags": {"Name": "HelloWorld"},
			},
		},
		{
			"address": "aws_ebs_volume.valid",
			"mode": "managed",
			"type": "aws_ebs_volume",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"availability_zone": "us-west-2a",
				"encrypted": true,
				"multi_attach_enabled": null,
				"outpost_arn": null,
				"size": 40,
				"tags": {"Name": "HelloWorld"},
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_ebs_volume.invalid",
			"mode": "managed",
			"type": "aws_ebs_volume",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"availability_zone": "us-west-2a",
					"encrypted": false,
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "HelloWorld"},
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"iops": true,
					"kms_key_id": true,
					"snapshot_id": true,
					"tags": {},
					"type": true,
				},
			},
		},
		{
			"address": "aws_ebs_volume.valid",
			"mode": "managed",
			"type": "aws_ebs_volume",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"availability_zone": "us-west-2a",
					"encrypted": true,
					"multi_attach_enabled": null,
					"outpost_arn": null,
					"size": 40,
					"tags": {"Name": "HelloWorld"},
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"iops": true,
					"kms_key_id": true,
					"snapshot_id": true,
					"tags": {},
					"type": true,
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
				"address": "aws_ebs_volume.invalid",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"availability_zone": {"constant_value": "us-west-2a"},
					"encrypted": {"constant_value": false},
					"size": {"constant_value": 40},
					"tags": {"constant_value": {"Name": "HelloWorld"}},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_ebs_volume.valid",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"availability_zone": {"constant_value": "us-west-2a"},
					"encrypted": {"constant_value": true},
					"size": {"constant_value": 40},
					"tags": {"constant_value": {"Name": "HelloWorld"}},
				},
				"schema_version": 0,
			},
		]},
	},
}
