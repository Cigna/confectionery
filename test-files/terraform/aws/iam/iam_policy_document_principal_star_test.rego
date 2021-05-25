# Rego test for IAM Policy Document Principal Star
# Validating rule iam_policy_document_principal_star: Deny IAM Policy Documents that allow a resource to be publicly exposed

package rules.iam_policy_document_principal_star

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_iam_policy_document_principal_star {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["data.aws_iam_policy_document.invalid"] == false
	resources["data.aws_iam_policy_document.valid_condition"] == true
	resources["data.aws_iam_policy_document.valid_principal"] == true
}

# Mock input is generated plan for iam_policy_document_principal_star.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.13.4",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "data.aws_iam_policy_document.invalid",
			"mode": "data",
			"type": "aws_iam_policy_document",
			"name": "invalid",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {
				"id": "3513856536",
				"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"AWS\": \"*\"\n      }\n    }\n  ]\n}",
				"override_json": null,
				"override_policy_documents": null,
				"policy_id": null,
				"source_json": null,
				"source_policy_documents": null,
				"statement": [{
					"actions": [
						"SNS:SetTopicAttributes",
						"SNS:Subscribe",
					],
					"condition": [],
					"effect": "Allow",
					"not_actions": [],
					"not_principals": [],
					"not_resources": [],
					"principals": [{
						"identifiers": ["*"],
						"type": "AWS",
					}],
					"resources": [],
					"sid": "",
				}],
				"version": "2012-10-17",
			},
		},
		{
			"address": "data.aws_iam_policy_document.valid_condition",
			"mode": "data",
			"type": "aws_iam_policy_document",
			"name": "valid_condition",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {
				"id": "3245121603",
				"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"AWS\": \"*\"\n      },\n      \"Condition\": {\n        \"StringEquals\": {\n          \"SNS:Protocol\": [\n            \"email\"\n          ]\n        }\n      }\n    }\n  ]\n}",
				"override_json": null,
				"override_policy_documents": null,
				"policy_id": null,
				"source_json": null,
				"source_policy_documents": null,
				"statement": [{
					"actions": [
						"SNS:SetTopicAttributes",
						"SNS:Subscribe",
					],
					"condition": [{
						"test": "StringEquals",
						"values": ["email"],
						"variable": "SNS:Protocol",
					}],
					"effect": "Allow",
					"not_actions": [],
					"not_principals": [],
					"not_resources": [],
					"principals": [{
						"identifiers": ["*"],
						"type": "AWS",
					}],
					"resources": [],
					"sid": "",
				}],
				"version": "2012-10-17",
			},
		},
		{
			"address": "data.aws_iam_policy_document.valid_principal",
			"mode": "data",
			"type": "aws_iam_policy_document",
			"name": "valid_principal",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {
				"id": "2671198548",
				"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"Service\": \"firehose.amazonaws.com\"\n      },\n      \"Condition\": {\n        \"StringEquals\": {\n          \"sns:protocol\": [\n            \"email\"\n          ]\n        }\n      }\n    }\n  ]\n}",
				"override_json": null,
				"override_policy_documents": null,
				"policy_id": null,
				"source_json": null,
				"source_policy_documents": null,
				"statement": [{
					"actions": [
						"SNS:SetTopicAttributes",
						"SNS:Subscribe",
					],
					"condition": [{
						"test": "StringEquals",
						"values": ["email"],
						"variable": "sns:protocol",
					}],
					"effect": "Allow",
					"not_actions": [],
					"not_principals": [],
					"not_resources": [],
					"principals": [{
						"identifiers": ["firehose.amazonaws.com"],
						"type": "Service",
					}],
					"resources": [],
					"sid": "",
				}],
				"version": "2012-10-17",
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "data.aws_iam_policy_document.invalid",
			"mode": "data",
			"type": "aws_iam_policy_document",
			"name": "invalid",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["no-op"],
				"before": {
					"id": "3513856536",
					"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"AWS\": \"*\"\n      }\n    }\n  ]\n}",
					"override_json": null,
					"override_policy_documents": null,
					"policy_id": null,
					"source_json": null,
					"source_policy_documents": null,
					"statement": [{
						"actions": [
							"SNS:SetTopicAttributes",
							"SNS:Subscribe",
						],
						"condition": [],
						"effect": "Allow",
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [{
							"identifiers": ["*"],
							"type": "AWS",
						}],
						"resources": [],
						"sid": "",
					}],
					"version": "2012-10-17",
				},
				"after": {
					"id": "3513856536",
					"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"AWS\": \"*\"\n      }\n    }\n  ]\n}",
					"override_json": null,
					"override_policy_documents": null,
					"policy_id": null,
					"source_json": null,
					"source_policy_documents": null,
					"statement": [{
						"actions": [
							"SNS:SetTopicAttributes",
							"SNS:Subscribe",
						],
						"condition": [],
						"effect": "Allow",
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [{
							"identifiers": ["*"],
							"type": "AWS",
						}],
						"resources": [],
						"sid": "",
					}],
					"version": "2012-10-17",
				},
				"after_unknown": {},
			},
		},
		{
			"address": "data.aws_iam_policy_document.valid_condition",
			"mode": "data",
			"type": "aws_iam_policy_document",
			"name": "valid_condition",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["no-op"],
				"before": {
					"id": "3245121603",
					"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"AWS\": \"*\"\n      },\n      \"Condition\": {\n        \"StringEquals\": {\n          \"SNS:Protocol\": [\n            \"email\"\n          ]\n        }\n      }\n    }\n  ]\n}",
					"override_json": null,
					"override_policy_documents": null,
					"policy_id": null,
					"source_json": null,
					"source_policy_documents": null,
					"statement": [{
						"actions": [
							"SNS:SetTopicAttributes",
							"SNS:Subscribe",
						],
						"condition": [{
							"test": "StringEquals",
							"values": ["email"],
							"variable": "SNS:Protocol",
						}],
						"effect": "Allow",
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [{
							"identifiers": ["*"],
							"type": "AWS",
						}],
						"resources": [],
						"sid": "",
					}],
					"version": "2012-10-17",
				},
				"after": {
					"id": "3245121603",
					"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"AWS\": \"*\"\n      },\n      \"Condition\": {\n        \"StringEquals\": {\n          \"SNS:Protocol\": [\n            \"email\"\n          ]\n        }\n      }\n    }\n  ]\n}",
					"override_json": null,
					"override_policy_documents": null,
					"policy_id": null,
					"source_json": null,
					"source_policy_documents": null,
					"statement": [{
						"actions": [
							"SNS:SetTopicAttributes",
							"SNS:Subscribe",
						],
						"condition": [{
							"test": "StringEquals",
							"values": ["email"],
							"variable": "SNS:Protocol",
						}],
						"effect": "Allow",
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [{
							"identifiers": ["*"],
							"type": "AWS",
						}],
						"resources": [],
						"sid": "",
					}],
					"version": "2012-10-17",
				},
				"after_unknown": {},
			},
		},
		{
			"address": "data.aws_iam_policy_document.valid_principal",
			"mode": "data",
			"type": "aws_iam_policy_document",
			"name": "valid_principal",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["no-op"],
				"before": {
					"id": "2671198548",
					"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"Service\": \"firehose.amazonaws.com\"\n      },\n      \"Condition\": {\n        \"StringEquals\": {\n          \"sns:protocol\": [\n            \"email\"\n          ]\n        }\n      }\n    }\n  ]\n}",
					"override_json": null,
					"override_policy_documents": null,
					"policy_id": null,
					"source_json": null,
					"source_policy_documents": null,
					"statement": [{
						"actions": [
							"SNS:SetTopicAttributes",
							"SNS:Subscribe",
						],
						"condition": [{
							"test": "StringEquals",
							"values": ["email"],
							"variable": "sns:protocol",
						}],
						"effect": "Allow",
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [{
							"identifiers": ["firehose.amazonaws.com"],
							"type": "Service",
						}],
						"resources": [],
						"sid": "",
					}],
					"version": "2012-10-17",
				},
				"after": {
					"id": "2671198548",
					"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"Service\": \"firehose.amazonaws.com\"\n      },\n      \"Condition\": {\n        \"StringEquals\": {\n          \"sns:protocol\": [\n            \"email\"\n          ]\n        }\n      }\n    }\n  ]\n}",
					"override_json": null,
					"override_policy_documents": null,
					"policy_id": null,
					"source_json": null,
					"source_policy_documents": null,
					"statement": [{
						"actions": [
							"SNS:SetTopicAttributes",
							"SNS:Subscribe",
						],
						"condition": [{
							"test": "StringEquals",
							"values": ["email"],
							"variable": "sns:protocol",
						}],
						"effect": "Allow",
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [{
							"identifiers": ["firehose.amazonaws.com"],
							"type": "Service",
						}],
						"resources": [],
						"sid": "",
					}],
					"version": "2012-10-17",
				},
				"after_unknown": {},
			},
		},
	],
	"prior_state": {
		"format_version": "0.1",
		"terraform_version": "0.13.4",
		"values": {"root_module": {"resources": [
			{
				"address": "data.aws_iam_policy_document.invalid",
				"mode": "data",
				"type": "aws_iam_policy_document",
				"name": "invalid",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"id": "3513856536",
					"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"AWS\": \"*\"\n      }\n    }\n  ]\n}",
					"override_json": null,
					"override_policy_documents": null,
					"policy_id": null,
					"source_json": null,
					"source_policy_documents": null,
					"statement": [{
						"actions": [
							"SNS:SetTopicAttributes",
							"SNS:Subscribe",
						],
						"condition": [],
						"effect": "Allow",
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [{
							"identifiers": ["*"],
							"type": "AWS",
						}],
						"resources": [],
						"sid": "",
					}],
					"version": "2012-10-17",
				},
			},
			{
				"address": "data.aws_iam_policy_document.valid_condition",
				"mode": "data",
				"type": "aws_iam_policy_document",
				"name": "valid_condition",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"id": "3245121603",
					"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"AWS\": \"*\"\n      },\n      \"Condition\": {\n        \"StringEquals\": {\n          \"SNS:Protocol\": [\n            \"email\"\n          ]\n        }\n      }\n    }\n  ]\n}",
					"override_json": null,
					"override_policy_documents": null,
					"policy_id": null,
					"source_json": null,
					"source_policy_documents": null,
					"statement": [{
						"actions": [
							"SNS:SetTopicAttributes",
							"SNS:Subscribe",
						],
						"condition": [{
							"test": "StringEquals",
							"values": ["email"],
							"variable": "SNS:Protocol",
						}],
						"effect": "Allow",
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [{
							"identifiers": ["*"],
							"type": "AWS",
						}],
						"resources": [],
						"sid": "",
					}],
					"version": "2012-10-17",
				},
			},
			{
				"address": "data.aws_iam_policy_document.valid_principal",
				"mode": "data",
				"type": "aws_iam_policy_document",
				"name": "valid_principal",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"schema_version": 0,
				"values": {
					"id": "2671198548",
					"json": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"\",\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"SNS:Subscribe\",\n        \"SNS:SetTopicAttributes\"\n      ],\n      \"Principal\": {\n        \"Service\": \"firehose.amazonaws.com\"\n      },\n      \"Condition\": {\n        \"StringEquals\": {\n          \"sns:protocol\": [\n            \"email\"\n          ]\n        }\n      }\n    }\n  ]\n}",
					"override_json": null,
					"override_policy_documents": null,
					"policy_id": null,
					"source_json": null,
					"source_policy_documents": null,
					"statement": [{
						"actions": [
							"SNS:SetTopicAttributes",
							"SNS:Subscribe",
						],
						"condition": [{
							"test": "StringEquals",
							"values": ["email"],
							"variable": "sns:protocol",
						}],
						"effect": "Allow",
						"not_actions": [],
						"not_principals": [],
						"not_resources": [],
						"principals": [{
							"identifiers": ["firehose.amazonaws.com"],
							"type": "Service",
						}],
						"resources": [],
						"sid": "",
					}],
					"version": "2012-10-17",
				},
			},
		]}},
	},
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
				"address": "data.aws_iam_policy_document.invalid",
				"mode": "data",
				"type": "aws_iam_policy_document",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {"statement": [{
					"actions": {"constant_value": [
						"SNS:Subscribe",
						"SNS:SetTopicAttributes",
					]},
					"effect": {"constant_value": "Allow"},
					"principals": [{
						"identifiers": {"constant_value": ["*"]},
						"type": {"constant_value": "AWS"},
					}],
				}]},
				"schema_version": 0,
			},
			{
				"address": "data.aws_iam_policy_document.valid_condition",
				"mode": "data",
				"type": "aws_iam_policy_document",
				"name": "valid_condition",
				"provider_config_key": "aws",
				"expressions": {"statement": [{
					"actions": {"constant_value": [
						"SNS:Subscribe",
						"SNS:SetTopicAttributes",
					]},
					"condition": [{
						"test": {"constant_value": "StringEquals"},
						"values": {"constant_value": ["email"]},
						"variable": {"constant_value": "SNS:Protocol"},
					}],
					"effect": {"constant_value": "Allow"},
					"principals": [{
						"identifiers": {"constant_value": ["*"]},
						"type": {"constant_value": "AWS"},
					}],
				}]},
				"schema_version": 0,
			},
			{
				"address": "data.aws_iam_policy_document.valid_principal",
				"mode": "data",
				"type": "aws_iam_policy_document",
				"name": "valid_principal",
				"provider_config_key": "aws",
				"expressions": {"statement": [{
					"actions": {"constant_value": [
						"SNS:Subscribe",
						"SNS:SetTopicAttributes",
					]},
					"condition": [{
						"test": {"constant_value": "StringEquals"},
						"values": {"constant_value": ["email"]},
						"variable": {"constant_value": "sns:protocol"},
					}],
					"effect": {"constant_value": "Allow"},
					"principals": [{
						"identifiers": {"constant_value": ["firehose.amazonaws.com"]},
						"type": {"constant_value": "Service"},
					}],
				}]},
				"schema_version": 0,
			},
		]},
	},
}
