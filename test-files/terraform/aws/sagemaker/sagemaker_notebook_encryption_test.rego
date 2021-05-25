# Rego test file for sagemaker notebook encryption rule
package rules.sagemaker_notebook_encryption

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_sagemaker_notebook_encryption_enforcement {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_sagemaker_notebook_instance.invalid"] == false
	resources["aws_sagemaker_notebook_instance.valid"] == true
}

mock_plan_input = {
	"configuration": {
		"provider_config": {"aws": {
			"expressions": {
				"profile": {"constant_value": "saml"},
				"region": {"constant_value": "us-east-1"},
				"shared_credentials_file": {"constant_value": "~/.aws/creds"},
			},
			"name": "aws",
		}},
		"root_module": {"resources": [
			{
				"address": "aws_sagemaker_notebook_instance.invalid",
				"expressions": {
					"instance_type": {"constant_value": "ml.t2.medium"},
					"name": {"constant_value": "my-notebook-instance"},
					"role_arn": {"constant_value": "arn"},
					"tags": {"constant_value": {"Name": "foo"}},
				},
				"mode": "managed",
				"name": "invalid",
				"provider_config_key": "aws",
				"schema_version": 0,
				"type": "aws_sagemaker_notebook_instance",
			},
			{
				"address": "aws_sagemaker_notebook_instance.valid",
				"expressions": {
					"instance_type": {"constant_value": "ml.t2.medium"},
					"kms_key_id": {"constant_value": "rab3wuqwgja25ct3n4jdj2tzu4"},
					"name": {"constant_value": "my-notebook-instance-valid"},
					"role_arn": {"constant_value": "arn"},
					"tags": {"constant_value": {"Name": "foo"}},
				},
				"mode": "managed",
				"name": "valid",
				"provider_config_key": "aws",
				"schema_version": 0,
				"type": "aws_sagemaker_notebook_instance",
			},
		]},
	},
	"format_version": "0.1",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_sagemaker_notebook_instance.invalid",
			"mode": "managed",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"type": "aws_sagemaker_notebook_instance",
			"values": {
				"direct_internet_access": "Enabled",
				"instance_type": "ml.t2.medium",
				"kms_key_id": null,
				"lifecycle_config_name": null,
				"name": "my-notebook-instance",
				"role_arn": "arn",
				"subnet_id": null,
				"tags": {"Name": "foo"},
			},
		},
		{
			"address": "aws_sagemaker_notebook_instance.valid",
			"mode": "managed",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"type": "aws_sagemaker_notebook_instance",
			"values": {
				"direct_internet_access": "Enabled",
				"instance_type": "ml.t2.medium",
				"kms_key_id": "rab3wuqwgja25ct3n4jdj2tzu4",
				"lifecycle_config_name": null,
				"name": "my-notebook-instance-valid",
				"role_arn": "arn",
				"subnet_id": null,
				"tags": {"Name": "foo"},
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_sagemaker_notebook_instance.invalid",
			"change": {
				"actions": ["create"],
				"after": {
					"direct_internet_access": "Enabled",
					"instance_type": "ml.t2.medium",
					"kms_key_id": null,
					"lifecycle_config_name": null,
					"name": "my-notebook-instance",
					"role_arn": "arn",
					"subnet_id": null,
					"tags": {"Name": "foo"},
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"security_groups": true,
					"tags": {},
				},
				"before": null,
			},
			"mode": "managed",
			"name": "invalid",
			"provider_name": "aws",
			"type": "aws_sagemaker_notebook_instance",
		},
		{
			"address": "aws_sagemaker_notebook_instance.valid",
			"change": {
				"actions": ["create"],
				"after": {
					"direct_internet_access": "Enabled",
					"instance_type": "ml.t2.medium",
					"kms_key_id": "rab3wuqwgja25ct3n4jdj2tzu4",
					"lifecycle_config_name": null,
					"name": "my-notebook-instance-valid",
					"role_arn": "arn",
					"subnet_id": null,
					"tags": {"Name": "foo"},
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"security_groups": true,
					"tags": {},
				},
				"before": null,
			},
			"mode": "managed",
			"name": "valid",
			"provider_name": "aws",
			"type": "aws_sagemaker_notebook_instance",
		},
	],
	"terraform_version": "0.12.19",
}
