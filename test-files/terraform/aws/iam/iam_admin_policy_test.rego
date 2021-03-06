# Rego test for IAM Admin Policy
# Validating rule iam_admin_policy:Deny full administrative permissions 

package rules.iam_admin_policy

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_admin_policy {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_iam_group_policy.invalid_group_policy"] == false
	resources["aws_iam_group_policy.valid_group_policy"] == true
	resources["aws_iam_policy.invalid_policy"] == false
	resources["aws_iam_policy.valid_deny_policy"] == true
	resources["aws_iam_role_policy.invalid_role_policy"] == false
	resources["aws_iam_role_policy.valid_role_policy"] == true
	resources["aws_iam_user_policy.invalid_user_policy"] == false
	resources["aws_iam_user_policy.valid_user_policy"] == true
}

# Mock input is generated plan for iam_admin_policy.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.18",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_iam_group.my_group",
			"mode": "managed",
			"type": "aws_iam_group",
			"name": "my_group",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "my_group",
				"path": "/users/",
			},
		},
		{
			"address": "aws_iam_group_policy.invalid_group_policy",
			"mode": "managed",
			"type": "aws_iam_group_policy",
			"name": "invalid_group_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "invalid_group_policy",
				"name_prefix": null,
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_group_policy.valid_group_policy",
			"mode": "managed",
			"type": "aws_iam_group_policy",
			"name": "valid_group_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "valid_group_policy",
				"name_prefix": null,
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_policy.invalid_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "invalid_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "Invalid policy",
				"name": "test_invalid_policy",
				"name_prefix": null,
				"path": "/",
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_policy.valid_deny_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "valid_deny_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "Valid deny policy",
				"name": "test_valid_deny_policy",
				"name_prefix": null,
				"path": "/",
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Deny\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_role.my_test_role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "my_test_role",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"sts:AssumeRole\",\n      \"Principal\": {\n        \"Service\": \"ec2.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n",
				"description": null,
				"force_detach_policies": false,
				"max_session_duration": 3600,
				"name": "my_test_role",
				"name_prefix": null,
				"path": "/",
				"permissions_boundary": null,
				"tags": null,
			},
		},
		{
			"address": "aws_iam_role_policy.invalid_role_policy",
			"mode": "managed",
			"type": "aws_iam_role_policy",
			"name": "invalid_role_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "invalid_role_policy",
				"name_prefix": null,
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_role_policy.valid_role_policy",
			"mode": "managed",
			"type": "aws_iam_role_policy",
			"name": "valid_role_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "valid_role_policy",
				"name_prefix": null,
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_user.my_test_user",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "my_test_user",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"force_destroy": false,
				"name": "my_test_user",
				"path": "/system/",
				"permissions_boundary": null,
				"tags": null,
			},
		},
		{
			"address": "aws_iam_user_policy.invalid_user_policy",
			"mode": "managed",
			"type": "aws_iam_user_policy",
			"name": "invalid_user_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "invalid_user_policy",
				"name_prefix": null,
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				"user": "my_test_user",
			},
		},
		{
			"address": "aws_iam_user_policy.valid_user_policy",
			"mode": "managed",
			"type": "aws_iam_user_policy",
			"name": "valid_user_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "valid_user_policy",
				"name_prefix": null,
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				"user": "my_test_user",
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_iam_group.my_group",
			"mode": "managed",
			"type": "aws_iam_group",
			"name": "my_group",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "my_group",
					"path": "/users/",
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_iam_group_policy.invalid_group_policy",
			"mode": "managed",
			"type": "aws_iam_group_policy",
			"name": "invalid_group_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "invalid_group_policy",
					"name_prefix": null,
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"group": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_iam_group_policy.valid_group_policy",
			"mode": "managed",
			"type": "aws_iam_group_policy",
			"name": "valid_group_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "valid_group_policy",
					"name_prefix": null,
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"group": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_iam_policy.invalid_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "invalid_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Invalid policy",
					"name": "test_invalid_policy",
					"name_prefix": null,
					"path": "/",
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_iam_policy.valid_deny_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "valid_deny_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Valid deny policy",
					"name": "test_valid_deny_policy",
					"name_prefix": null,
					"path": "/",
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Deny\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_iam_role.my_test_role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "my_test_role",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"sts:AssumeRole\",\n      \"Principal\": {\n        \"Service\": \"ec2.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "my_test_role",
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
			"address": "aws_iam_role_policy.invalid_role_policy",
			"mode": "managed",
			"type": "aws_iam_role_policy",
			"name": "invalid_role_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "invalid_role_policy",
					"name_prefix": null,
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"id": true,
					"role": true,
				},
			},
		},
		{
			"address": "aws_iam_role_policy.valid_role_policy",
			"mode": "managed",
			"type": "aws_iam_role_policy",
			"name": "valid_role_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "valid_role_policy",
					"name_prefix": null,
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"id": true,
					"role": true,
				},
			},
		},
		{
			"address": "aws_iam_user.my_test_user",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "my_test_user",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"force_destroy": false,
					"name": "my_test_user",
					"path": "/system/",
					"permissions_boundary": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_iam_user_policy.invalid_user_policy",
			"mode": "managed",
			"type": "aws_iam_user_policy",
			"name": "invalid_user_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "invalid_user_policy",
					"name_prefix": null,
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
					"user": "my_test_user",
				},
				"after_unknown": {"id": true},
			},
		},
		{
			"address": "aws_iam_user_policy.valid_user_policy",
			"mode": "managed",
			"type": "aws_iam_user_policy",
			"name": "valid_user_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "valid_user_policy",
					"name_prefix": null,
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
					"user": "my_test_user",
				},
				"after_unknown": {"id": true},
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
				"address": "aws_iam_group.my_group",
				"mode": "managed",
				"type": "aws_iam_group",
				"name": "my_group",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "my_group"},
					"path": {"constant_value": "/users/"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_group_policy.invalid_group_policy",
				"mode": "managed",
				"type": "aws_iam_group_policy",
				"name": "invalid_group_policy",
				"provider_config_key": "aws",
				"expressions": {
					"group": {"references": ["aws_iam_group.my_group"]},
					"name": {"constant_value": "invalid_group_policy"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_group_policy.valid_group_policy",
				"mode": "managed",
				"type": "aws_iam_group_policy",
				"name": "valid_group_policy",
				"provider_config_key": "aws",
				"expressions": {
					"group": {"references": ["aws_iam_group.my_group"]},
					"name": {"constant_value": "valid_group_policy"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_policy.invalid_policy",
				"mode": "managed",
				"type": "aws_iam_policy",
				"name": "invalid_policy",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "Invalid policy"},
					"name": {"constant_value": "test_invalid_policy"},
					"path": {"constant_value": "/"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_policy.valid_deny_policy",
				"mode": "managed",
				"type": "aws_iam_policy",
				"name": "valid_deny_policy",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "Valid deny policy"},
					"name": {"constant_value": "test_valid_deny_policy"},
					"path": {"constant_value": "/"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Deny\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_role.my_test_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "my_test_role",
				"provider_config_key": "aws",
				"expressions": {
					"assume_role_policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"sts:AssumeRole\",\n      \"Principal\": {\n        \"Service\": \"ec2.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n"},
					"name": {"constant_value": "my_test_role"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_role_policy.invalid_role_policy",
				"mode": "managed",
				"type": "aws_iam_role_policy",
				"name": "invalid_role_policy",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "invalid_role_policy"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
					"role": {"references": ["aws_iam_role.my_test_role"]},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_role_policy.valid_role_policy",
				"mode": "managed",
				"type": "aws_iam_role_policy",
				"name": "valid_role_policy",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "valid_role_policy"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
					"role": {"references": ["aws_iam_role.my_test_role"]},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_user.my_test_user",
				"mode": "managed",
				"type": "aws_iam_user",
				"name": "my_test_user",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "my_test_user"},
					"path": {"constant_value": "/system/"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_user_policy.invalid_user_policy",
				"mode": "managed",
				"type": "aws_iam_user_policy",
				"name": "invalid_user_policy",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "invalid_user_policy"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
					"user": {"references": ["aws_iam_user.my_test_user"]},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_user_policy.valid_user_policy",
				"mode": "managed",
				"type": "aws_iam_user_policy",
				"name": "valid_user_policy",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "valid_user_policy"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
					"user": {"references": ["aws_iam_user.my_test_user"]},
				},
				"schema_version": 0,
			},
		]},
	},
}
