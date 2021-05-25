# Rego test for SQS Restricted Principal
# Validating rule sqs_restricted_principal: Deny SQS policies that have wildcard principals with no limiting conditions defined.
package rules.sqs_restricted_principal

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_sqs_restricted_principal {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_sqs_queue_policy.invalid_sqs_policy"] == false
	resources["aws_sqs_queue_policy.valid_sqs_policy_condition"] == true
	resources["aws_sqs_queue_policy.valid_sqs_policy_non_star_principal"] == true
}

# Mock input is generated plan for sqs_restricted_principal.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_sqs_queue_policy.invalid_sqs_policy",
			"mode": "managed",
			"type": "aws_sqs_queue_policy",
			"name": "invalid_sqs_policy",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				"queue_url": "SampleQueue",
			},
		},
		{
			"address": "aws_sqs_queue_policy.valid_sqs_policy_condition",
			"mode": "managed",
			"type": "aws_sqs_queue_policy",
			"name": "valid_sqs_policy_condition",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\",\n      \"Condition\": {\"ArnEquals\": {\n          \"aws:SourceArn\": \"example_arn\"}\n          }\n    }\n  ]\n}\n",
				"queue_url": "SampleQueue",
			},
		},
		{
			"address": "aws_sqs_queue_policy.valid_sqs_policy_non_star_principal",
			"mode": "managed",
			"type": "aws_sqs_queue_policy",
			"name": "valid_sqs_policy_non_star_principal",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Principal\":\"Tom\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				"queue_url": "SampleQueue",
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_sqs_queue_policy.invalid_sqs_policy",
			"mode": "managed",
			"type": "aws_sqs_queue_policy",
			"name": "invalid_sqs_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
					"queue_url": "SampleQueue",
				},
				"after_unknown": {"id": true},
			},
		},
		{
			"address": "aws_sqs_queue_policy.valid_sqs_policy_condition",
			"mode": "managed",
			"type": "aws_sqs_queue_policy",
			"name": "valid_sqs_policy_condition",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\",\n      \"Condition\": {\"ArnEquals\": {\n          \"aws:SourceArn\": \"example_arn\"}\n          }\n    }\n  ]\n}\n",
					"queue_url": "SampleQueue",
				},
				"after_unknown": {"id": true},
			},
		},
		{
			"address": "aws_sqs_queue_policy.valid_sqs_policy_non_star_principal",
			"mode": "managed",
			"type": "aws_sqs_queue_policy",
			"name": "valid_sqs_policy_non_star_principal",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Principal\":\"Tom\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
					"queue_url": "SampleQueue",
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
				"address": "aws_sqs_queue_policy.invalid_sqs_policy",
				"mode": "managed",
				"type": "aws_sqs_queue_policy",
				"name": "invalid_sqs_policy",
				"provider_config_key": "aws",
				"expressions": {
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
					"queue_url": {"constant_value": "SampleQueue"},
				},
				"schema_version": 1,
			},
			{
				"address": "aws_sqs_queue_policy.valid_sqs_policy_condition",
				"mode": "managed",
				"type": "aws_sqs_queue_policy",
				"name": "valid_sqs_policy_condition",
				"provider_config_key": "aws",
				"expressions": {
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Principal\":\"*\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\",\n      \"Condition\": {\"ArnEquals\": {\n          \"aws:SourceArn\": \"example_arn\"}\n          }\n    }\n  ]\n}\n"},
					"queue_url": {"constant_value": "SampleQueue"},
				},
				"schema_version": 1,
			},
			{
				"address": "aws_sqs_queue_policy.valid_sqs_policy_non_star_principal",
				"mode": "managed",
				"type": "aws_sqs_queue_policy",
				"name": "valid_sqs_policy_non_star_principal",
				"provider_config_key": "aws",
				"expressions": {
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Action\": [\n        \"*\"\n      ],\n      \"Principal\":\"Tom\",\n      \"Effect\": \"Allow\",\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
					"queue_url": {"constant_value": "SampleQueue"},
				},
				"schema_version": 1,
			},
		]},
	},
}
