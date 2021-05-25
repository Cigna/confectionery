# Rego test for IAM Deny NotActions
# Validating rule iam_deny_notactions: Deny policies that grant permissions using black-list approach

package rules.iam_deny_notactions

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_iam_notactions {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_iam_policy.invalid_test_policy"] == false
	resources["aws_iam_policy.valid_policy3"] == true
	resources["aws_iam_policy.invalid_policy_b"] == false
	resources["aws_iam_role_policy.invalid_role_policy"] == false
	resources["aws_iam_user_policy.invalid_policy_c"] == false
}

# Mock input is generated plan for iam_deny_notactions.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.29",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_iam_policy.invalid_policy_b",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "invalid_policy_b",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": null,
				"name": "invalid_policy_b",
				"name_prefix": null,
				"path": "/",
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"s3:*\"\n      ],\n      \"Effect\": \"Deny\",\n      \"Resource\": \"arn:aws:s3:::*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_policy.invalid_test_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "invalid_test_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": null,
				"name": "invalid_test_policy",
				"name_prefix": null,
				"path": "/",
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_policy.valid_policy3",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "valid_policy3",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "My test policy",
				"name": "valid_policy3",
				"name_prefix": null,
				"path": "/",
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"s3:*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_role.test_role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "test_role",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"sts:AssumeRole\",\n      \"Principal\": {\n        \"Service\": \"ec2.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n",
				"description": null,
				"force_detach_policies": false,
				"max_session_duration": 3600,
				"name": "test_role",
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
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"ec2:Delete*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_user.tester",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "tester",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"force_destroy": false,
				"name": "tester",
				"path": "/system/",
				"permissions_boundary": null,
				"tags": null,
			},
		},
		{
			"address": "aws_iam_user_policy.invalid_policy_c",
			"mode": "managed",
			"type": "aws_iam_user_policy",
			"name": "invalid_policy_c",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "invalid_policy_c",
				"name_prefix": null,
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"iam:*\",\n        \"cloudfront:*\",\n        \"route53:*\",\n\t\"ec2:*\"\n      ],\n      \"Effect\": \"Deny\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				"user": "tester",
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_iam_policy.invalid_policy_b",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "invalid_policy_b",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": null,
					"name": "invalid_policy_b",
					"name_prefix": null,
					"path": "/",
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"s3:*\"\n      ],\n      \"Effect\": \"Deny\",\n      \"Resource\": \"arn:aws:s3:::*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_iam_policy.invalid_test_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "invalid_test_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": null,
					"name": "invalid_test_policy",
					"name_prefix": null,
					"path": "/",
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_iam_policy.valid_policy3",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "valid_policy3",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "My test policy",
					"name": "valid_policy3",
					"name_prefix": null,
					"path": "/",
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"s3:*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
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
					"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"sts:AssumeRole\",\n      \"Principal\": {\n        \"Service\": \"ec2.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "test_role",
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
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"ec2:Delete*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"id": true,
					"role": true,
				},
			},
		},
		{
			"address": "aws_iam_user.tester",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "tester",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"force_destroy": false,
					"name": "tester",
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
			"address": "aws_iam_user_policy.invalid_policy_c",
			"mode": "managed",
			"type": "aws_iam_user_policy",
			"name": "invalid_policy_c",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "invalid_policy_c",
					"name_prefix": null,
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"iam:*\",\n        \"cloudfront:*\",\n        \"route53:*\",\n\t\"ec2:*\"\n      ],\n      \"Effect\": \"Deny\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
					"user": "tester",
				},
				"after_unknown": {"id": true},
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
				"address": "aws_iam_policy.invalid_policy_b",
				"mode": "managed",
				"type": "aws_iam_policy",
				"name": "invalid_policy_b",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "invalid_policy_b"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"s3:*\"\n      ],\n      \"Effect\": \"Deny\",\n      \"Resource\": \"arn:aws:s3:::*\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_policy.invalid_test_policy",
				"mode": "managed",
				"type": "aws_iam_policy",
				"name": "invalid_test_policy",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "invalid_test_policy"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"ec2:Describe*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_policy.valid_policy3",
				"mode": "managed",
				"type": "aws_iam_policy",
				"name": "valid_policy3",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "My test policy"},
					"name": {"constant_value": "valid_policy3"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"s3:*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_role.test_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "test_role",
				"provider_config_key": "aws",
				"expressions": {
					"assume_role_policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": \"sts:AssumeRole\",\n      \"Principal\": {\n        \"Service\": \"ec2.amazonaws.com\"\n      },\n      \"Effect\": \"Allow\",\n      \"Sid\": \"\"\n    }\n  ]\n}\n"},
					"name": {"constant_value": "test_role"},
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
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"ec2:Delete*\"\n      ],\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
					"role": {"references": ["aws_iam_role.test_role"]},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_user.tester",
				"mode": "managed",
				"type": "aws_iam_user",
				"name": "tester",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "tester"},
					"path": {"constant_value": "/system/"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_user_policy.invalid_policy_c",
				"mode": "managed",
				"type": "aws_iam_user_policy",
				"name": "invalid_policy_c",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "invalid_policy_c"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"NotAction\": [\n        \"iam:*\",\n        \"cloudfront:*\",\n        \"route53:*\",\n\t\"ec2:*\"\n      ],\n      \"Effect\": \"Deny\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
					"user": {"references": ["aws_iam_user.tester"]},
				},
				"schema_version": 0,
			},
		]},
	},
}
