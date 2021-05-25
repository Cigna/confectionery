# Rego test for SNS Restricted Principal
# Validating rule sns_restricted_principal: Deny SNS topic policies that extend permissions to be made publicly accessible 
package rules.sns_restricted_principal

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_sns_restricted_principal {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_sns_topic_policy.invalid_policy_a"] == false
	resources["aws_sns_topic_policy.invalid_policy_b"] == false
	resources["aws_sns_topic_policy.valid_policy_c"] == true
	resources["aws_sns_topic_policy.invalid_policy_d"] == false
	resources["aws_sns_topic_policy.valid_policy_e"] == true
}

# Mock input is generated plan for sns_restricted_principal.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.13.2",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_sns_topic.test_a",
			"mode": "managed",
			"type": "aws_sns_topic",
			"name": "test_a",
			"provider_name": "registry.terraform.io/hashicorp/aws",
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
				"name": "test_a",
				"name_prefix": null,
				"sqs_failure_feedback_role_arn": null,
				"sqs_success_feedback_role_arn": null,
				"sqs_success_feedback_sample_rate": null,
				"tags": null,
			},
		},
		{
			"address": "aws_sns_topic.test_b",
			"mode": "managed",
			"type": "aws_sns_topic",
			"name": "test_b",
			"provider_name": "registry.terraform.io/hashicorp/aws",
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
				"name": "test_b",
				"name_prefix": null,
				"sqs_failure_feedback_role_arn": null,
				"sqs_success_feedback_role_arn": null,
				"sqs_success_feedback_sample_rate": null,
				"tags": null,
			},
		},
		{
			"address": "aws_sns_topic_policy.invalid_policy_a",
			"mode": "managed",
			"type": "aws_sns_topic_policy",
			"name": "invalid_policy_a",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\":[\n        \"sns:Publish\"\n     ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_a.arn\"\n    }\n  ]\n}\n"},
		},
		{
			"address": "aws_sns_topic_policy.invalid_policy_b",
			"mode": "managed",
			"type": "aws_sns_topic_policy",
			"name": "invalid_policy_b",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"sns:Publish\",\n        \"sns:Subscribe\"\n     ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
		},
		{
			"address": "aws_sns_topic_policy.invalid_policy_d",
			"mode": "managed",
			"type": "aws_sns_topic_policy",
			"name": "invalid_policy_d",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"sns:Publish\"\n      ],\n      \"Principal\" : { \"AWS\" : \"*\" },\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
		},
		{
			"address": "aws_sns_topic_policy.valid_policy_c",
			"mode": "managed",
			"type": "aws_sns_topic_policy",
			"name": "valid_policy_c",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [ \n        \"sns:Publish\",\n        \"sns:Subscribe\"\n      ],\n      \"Principal\":{\"AWS\":\"arn:aws:iam::965447543943:role/ACCOUNTADMIN\"},\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
		},
		{
			"address": "aws_sns_topic_policy.valid_policy_e",
			"mode": "managed",
			"type": "aws_sns_topic_policy",
			"name": "valid_policy_e",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"sns:Publish\"\n      ],\n      \"Condition\": {\"StringEquals\": \"AWS:SourceOwner\"},\n      \"Principal\": \"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_sns_topic.test_a",
			"mode": "managed",
			"type": "aws_sns_topic",
			"name": "test_a",
			"provider_name": "registry.terraform.io/hashicorp/aws",
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
					"name": "test_a",
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
			"address": "aws_sns_topic.test_b",
			"mode": "managed",
			"type": "aws_sns_topic",
			"name": "test_b",
			"provider_name": "registry.terraform.io/hashicorp/aws",
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
					"name": "test_b",
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
			"address": "aws_sns_topic_policy.invalid_policy_a",
			"mode": "managed",
			"type": "aws_sns_topic_policy",
			"name": "invalid_policy_a",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\":[\n        \"sns:Publish\"\n     ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_a.arn\"\n    }\n  ]\n}\n"},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_sns_topic_policy.invalid_policy_b",
			"mode": "managed",
			"type": "aws_sns_topic_policy",
			"name": "invalid_policy_b",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"sns:Publish\",\n        \"sns:Subscribe\"\n     ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_sns_topic_policy.invalid_policy_d",
			"mode": "managed",
			"type": "aws_sns_topic_policy",
			"name": "invalid_policy_d",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"sns:Publish\"\n      ],\n      \"Principal\" : { \"AWS\" : \"*\" },\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_sns_topic_policy.valid_policy_c",
			"mode": "managed",
			"type": "aws_sns_topic_policy",
			"name": "valid_policy_c",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [ \n        \"sns:Publish\",\n        \"sns:Subscribe\"\n      ],\n      \"Principal\":{\"AWS\":\"arn:aws:iam::965447543943:role/ACCOUNTADMIN\"},\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_sns_topic_policy.valid_policy_e",
			"mode": "managed",
			"type": "aws_sns_topic_policy",
			"name": "valid_policy_e",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"sns:Publish\"\n      ],\n      \"Condition\": {\"StringEquals\": \"AWS:SourceOwner\"},\n      \"Principal\": \"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
				"after_unknown": {
					"arn": true,
					"id": true,
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
				"shared_credentials_file": {"constant_value": "~/.aws/credentials"},
			},
		}},
		"root_module": {"resources": [
			{
				"address": "aws_sns_topic.test_a",
				"mode": "managed",
				"type": "aws_sns_topic",
				"name": "test_a",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "test_a"}},
				"schema_version": 0,
			},
			{
				"address": "aws_sns_topic.test_b",
				"mode": "managed",
				"type": "aws_sns_topic",
				"name": "test_b",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "test_b"}},
				"schema_version": 0,
			},
			{
				"address": "aws_sns_topic_policy.invalid_policy_a",
				"mode": "managed",
				"type": "aws_sns_topic_policy",
				"name": "invalid_policy_a",
				"provider_config_key": "aws",
				"expressions": {
					"arn": {"references": ["aws_sns_topic.test_a"]},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\":[\n        \"sns:Publish\"\n     ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_a.arn\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_sns_topic_policy.invalid_policy_b",
				"mode": "managed",
				"type": "aws_sns_topic_policy",
				"name": "invalid_policy_b",
				"provider_config_key": "aws",
				"expressions": {
					"arn": {"references": ["aws_sns_topic.test_b"]},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"sns:Publish\",\n        \"sns:Subscribe\"\n     ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_sns_topic_policy.invalid_policy_d",
				"mode": "managed",
				"type": "aws_sns_topic_policy",
				"name": "invalid_policy_d",
				"provider_config_key": "aws",
				"expressions": {
					"arn": {"references": ["aws_sns_topic.test_b"]},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"sns:Publish\"\n      ],\n      \"Principal\" : { \"AWS\" : \"*\" },\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_sns_topic_policy.valid_policy_c",
				"mode": "managed",
				"type": "aws_sns_topic_policy",
				"name": "valid_policy_c",
				"provider_config_key": "aws",
				"expressions": {
					"arn": {"references": ["aws_sns_topic.test_b"]},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [ \n        \"sns:Publish\",\n        \"sns:Subscribe\"\n      ],\n      \"Principal\":{\"AWS\":\"arn:aws:iam::965447543943:role/ACCOUNTADMIN\"},\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_sns_topic_policy.valid_policy_e",
				"mode": "managed",
				"type": "aws_sns_topic_policy",
				"name": "valid_policy_e",
				"provider_config_key": "aws",
				"expressions": {
					"arn": {"references": ["aws_sns_topic.test_b"]},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"sns:Publish\"\n      ],\n      \"Condition\": {\"StringEquals\": \"AWS:SourceOwner\"},\n      \"Principal\": \"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"aws_sns_topic.test_b.arn\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
		]},
	},
}
