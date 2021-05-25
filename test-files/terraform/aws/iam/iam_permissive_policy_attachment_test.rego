# Rego test for IAM Permissive Policy Attachments
# Validating rule iam_permissive_attached_policy: Deny IAM managed policies that are overly permissive

package rules.iam_permissive_attached_policy

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_iam_permissive_attached_policy {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_iam_role_policy_attachment.invalid_iamFull"] == false
	resources["aws_iam_policy_attachment.invalid_s3Full"] == false
	resources["aws_iam_policy_attachment.valid"] == true
	resources["aws_iam_user_policy_attachment.invalid_adminAccess"] == false
}

# Mock input is generated plan for iam_permissive_policy_attachment.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_iam_group.group",
			"mode": "managed",
			"type": "aws_iam_group",
			"name": "group",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "test-group",
				"path": "/",
			},
		},
		{
			"address": "aws_iam_policy_attachment.invalid_s3Full",
			"mode": "managed",
			"type": "aws_iam_policy_attachment",
			"name": "invalid_s3Full",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"groups": ["test-group"],
				"name": "test-attachment",
				"policy_arn": "arn:aws:iam::aws:policy/AmazonS3FullAccess",
				"roles": ["test-role"],
				"users": ["loadbalancer"],
			},
		},
		{
			"address": "aws_iam_policy_attachment.valid",
			"mode": "managed",
			"type": "aws_iam_policy_attachment",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"groups": ["test-group"],
				"name": "test-attachment",
				"policy_arn": "arn:aws:iam::aws:policy/ListAllMyBuckets",
				"roles": ["test-role"],
				"users": ["loadbalancer"],
			},
		},
		{
			"address": "aws_iam_role.role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "role",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"assume_role_policy": "    {\n      \"Version\": \"2012-10-17\",\n      \"Statement\": [\n        {\n          \"Action\": \"sts:AssumeRole\",\n          \"Principal\": {\n            \"Service\": \"ec2.amazonaws.com\"\n          },\n          \"Effect\": \"Allow\",\n          \"Sid\": \"\"\n        }\n      ]\n    }\n",
				"description": null,
				"force_detach_policies": false,
				"max_session_duration": 3600,
				"name": "test-role",
				"name_prefix": null,
				"path": "/",
				"permissions_boundary": null,
				"tags": null,
			},
		},
		{
			"address": "aws_iam_role_policy_attachment.invalid_iamFull",
			"mode": "managed",
			"type": "aws_iam_role_policy_attachment",
			"name": "invalid_iamFull",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"policy_arn": "arn:aws:iam::aws:policy/IAMFullAccess",
				"role": "test-role",
			},
		},
		{
			"address": "aws_iam_user.user",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "user",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"force_destroy": false,
				"name": "loadbalancer",
				"path": "/system/",
				"permissions_boundary": null,
				"tags": null,
			},
		},
		{
			"address": "aws_iam_user_policy_attachment.invalid_adminAccess",
			"mode": "managed",
			"type": "aws_iam_user_policy_attachment",
			"name": "invalid_adminAccess",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
				"user": "loadbalancer",
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_iam_group.group",
			"mode": "managed",
			"type": "aws_iam_group",
			"name": "group",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "test-group",
					"path": "/",
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_iam_policy_attachment.invalid_s3Full",
			"mode": "managed",
			"type": "aws_iam_policy_attachment",
			"name": "invalid_s3Full",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"groups": ["test-group"],
					"name": "test-attachment",
					"policy_arn": "arn:aws:iam::aws:policy/AmazonS3FullAccess",
					"roles": ["test-role"],
					"users": ["loadbalancer"],
				},
				"after_unknown": {
					"groups": [false],
					"id": true,
					"roles": [false],
					"users": [false],
				},
			},
		},
		{
			"address": "aws_iam_policy_attachment.valid",
			"mode": "managed",
			"type": "aws_iam_policy_attachment",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"groups": ["test-group"],
					"name": "test-attachment",
					"policy_arn": "arn:aws:iam::aws:policy/ListAllMyBuckets",
					"roles": ["test-role"],
					"users": ["loadbalancer"],
				},
				"after_unknown": {
					"groups": [false],
					"id": true,
					"roles": [false],
					"users": [false],
				},
			},
		},
		{
			"address": "aws_iam_role.role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "role",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"assume_role_policy": "    {\n      \"Version\": \"2012-10-17\",\n      \"Statement\": [\n        {\n          \"Action\": \"sts:AssumeRole\",\n          \"Principal\": {\n            \"Service\": \"ec2.amazonaws.com\"\n          },\n          \"Effect\": \"Allow\",\n          \"Sid\": \"\"\n        }\n      ]\n    }\n",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "test-role",
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
			"address": "aws_iam_role_policy_attachment.invalid_iamFull",
			"mode": "managed",
			"type": "aws_iam_role_policy_attachment",
			"name": "invalid_iamFull",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"policy_arn": "arn:aws:iam::aws:policy/IAMFullAccess",
					"role": "test-role",
				},
				"after_unknown": {"id": true},
			},
		},
		{
			"address": "aws_iam_user.user",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "user",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"force_destroy": false,
					"name": "loadbalancer",
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
			"address": "aws_iam_user_policy_attachment.invalid_adminAccess",
			"mode": "managed",
			"type": "aws_iam_user_policy_attachment",
			"name": "invalid_adminAccess",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
					"user": "loadbalancer",
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
				"address": "aws_iam_group.group",
				"mode": "managed",
				"type": "aws_iam_group",
				"name": "group",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "test-group"}},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_policy_attachment.invalid_s3Full",
				"mode": "managed",
				"type": "aws_iam_policy_attachment",
				"name": "invalid_s3Full",
				"provider_config_key": "aws",
				"expressions": {
					"groups": {"references": ["aws_iam_group.group"]},
					"name": {"constant_value": "test-attachment"},
					"policy_arn": {"constant_value": "arn:aws:iam::aws:policy/AmazonS3FullAccess"},
					"roles": {"references": ["aws_iam_role.role"]},
					"users": {"references": ["aws_iam_user.user"]},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_policy_attachment.valid",
				"mode": "managed",
				"type": "aws_iam_policy_attachment",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"groups": {"references": ["aws_iam_group.group"]},
					"name": {"constant_value": "test-attachment"},
					"policy_arn": {"constant_value": "arn:aws:iam::aws:policy/ListAllMyBuckets"},
					"roles": {"references": ["aws_iam_role.role"]},
					"users": {"references": ["aws_iam_user.user"]},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_role.role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "role",
				"provider_config_key": "aws",
				"expressions": {
					"assume_role_policy": {"constant_value": "    {\n      \"Version\": \"2012-10-17\",\n      \"Statement\": [\n        {\n          \"Action\": \"sts:AssumeRole\",\n          \"Principal\": {\n            \"Service\": \"ec2.amazonaws.com\"\n          },\n          \"Effect\": \"Allow\",\n          \"Sid\": \"\"\n        }\n      ]\n    }\n"},
					"name": {"constant_value": "test-role"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_role_policy_attachment.invalid_iamFull",
				"mode": "managed",
				"type": "aws_iam_role_policy_attachment",
				"name": "invalid_iamFull",
				"provider_config_key": "aws",
				"expressions": {
					"policy_arn": {"constant_value": "arn:aws:iam::aws:policy/IAMFullAccess"},
					"role": {"references": ["aws_iam_role.role"]},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_user.user",
				"mode": "managed",
				"type": "aws_iam_user",
				"name": "user",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "loadbalancer"},
					"path": {"constant_value": "/system/"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_user_policy_attachment.invalid_adminAccess",
				"mode": "managed",
				"type": "aws_iam_user_policy_attachment",
				"name": "invalid_adminAccess",
				"provider_config_key": "aws",
				"expressions": {
					"policy_arn": {"constant_value": "arn:aws:iam::aws:policy/AdministratorAccess"},
					"user": {"references": ["aws_iam_user.user"]},
				},
				"schema_version": 0,
			},
		]},
	},
}
