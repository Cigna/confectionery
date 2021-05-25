# Rego test for Sagemaker Internet Access
# Validating rule sagemaker_notebook_internet_access: Deny all Sagemaker Notebook instances that have direct internet access
package rules.sagemaker_notebook_internet_access

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_sagemaker_notebook_internet_access {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_sagemaker_notebook_instance.invalid"] == false
	resources["aws_sagemaker_notebook_instance.valid"] == true
}

# Mock input is generated plan for sagemaker_notebook_internet_access.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_iam_role.test_role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "test_role",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"*\",\n      \"Principal\": {\n        \"Service\": \"sagemaker.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n",
				"description": null,
				"force_detach_policies": false,
				"max_session_duration": 3600,
				"name": "test_role",
				"name_prefix": null,
				"path": "/",
				"permissions_boundary": null,
				"tags": {"tag-key": "tag-value"},
			},
		},
		{
			"address": "aws_sagemaker_notebook_instance.invalid",
			"mode": "managed",
			"type": "aws_sagemaker_notebook_instance",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"direct_internet_access": "Enabled",
				"instance_type": "ml.t2.medium",
				"kms_key_id": null,
				"lifecycle_config_name": null,
				"name": "my-notebook-instance",
				"subnet_id": null,
				"tags": {"Name": "foo"},
			},
		},
		{
			"address": "aws_sagemaker_notebook_instance.valid",
			"mode": "managed",
			"type": "aws_sagemaker_notebook_instance",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"direct_internet_access": "Disabled",
				"instance_type": "ml.t2.medium",
				"kms_key_id": null,
				"lifecycle_config_name": null,
				"name": "my-notebook-instance",
				"subnet_id": null,
				"tags": {"Name": "foo"},
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_iam_role.test_role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "test_role",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"*\",\n      \"Principal\": {\n        \"Service\": \"sagemaker.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "test_role",
					"name_prefix": null,
					"path": "/",
					"permissions_boundary": null,
					"tags": {"tag-key": "tag-value"},
				},
				"after_unknown": {
					"arn": true,
					"create_date": true,
					"id": true,
					"tags": {},
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_sagemaker_notebook_instance.invalid",
			"mode": "managed",
			"type": "aws_sagemaker_notebook_instance",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"direct_internet_access": "Enabled",
					"instance_type": "ml.t2.medium",
					"kms_key_id": null,
					"lifecycle_config_name": null,
					"name": "my-notebook-instance",
					"subnet_id": null,
					"tags": {"Name": "foo"},
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"role_arn": true,
					"security_groups": true,
					"tags": {},
				},
			},
		},
		{
			"address": "aws_sagemaker_notebook_instance.valid",
			"mode": "managed",
			"type": "aws_sagemaker_notebook_instance",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"direct_internet_access": "Disabled",
					"instance_type": "ml.t2.medium",
					"kms_key_id": null,
					"lifecycle_config_name": null,
					"name": "my-notebook-instance",
					"subnet_id": null,
					"tags": {"Name": "foo"},
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"role_arn": true,
					"security_groups": true,
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
				"address": "aws_iam_role.test_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "test_role",
				"provider_config_key": "aws",
				"expressions": {
					"assume_role_policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"*\",\n      \"Principal\": {\n        \"Service\": \"sagemaker.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n"},
					"name": {"constant_value": "test_role"},
					"tags": {"constant_value": {"tag-key": "tag-value"}},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_sagemaker_notebook_instance.invalid",
				"mode": "managed",
				"type": "aws_sagemaker_notebook_instance",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"instance_type": {"constant_value": "ml.t2.medium"},
					"name": {"constant_value": "my-notebook-instance"},
					"role_arn": {"references": ["aws_iam_role.test_role"]},
					"tags": {"constant_value": {"Name": "foo"}},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_sagemaker_notebook_instance.valid",
				"mode": "managed",
				"type": "aws_sagemaker_notebook_instance",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"direct_internet_access": {"constant_value": "Disabled"},
					"instance_type": {"constant_value": "ml.t2.medium"},
					"name": {"constant_value": "my-notebook-instance"},
					"role_arn": {"references": ["aws_iam_role.test_role"]},
					"tags": {"constant_value": {"Name": "foo"}},
				},
				"schema_version": 0,
			},
		]},
	},
}
