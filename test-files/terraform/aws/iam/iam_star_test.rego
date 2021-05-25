# Rego test for IAM Service Star Policy
# Validating rule iam_service_star: Deny Iam policies that use the wildcard "*" attribute  with service actions 

package rules.iam_service_star

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_iam_service_star {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_iam_policy.valid_policy"] == true
	resources["aws_iam_policy.invalid_policy"] == false
}

# Mock input is generated plan for iam_star.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_iam_policy.invalid_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "invalid_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "My test policy",
				"name": "test_policy",
				"name_prefix": null,
				"path": "/",
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"sts:*\"\n      ],\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_iam_policy.valid_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "valid_policy",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "My test policy",
				"name": "test_policy",
				"name_prefix": null,
				"path": "/",
				"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"sts:AssumeRole\"\n      ],\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
			},
		},
		{
			"address": "aws_s3_bucket.example",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "example",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"acl": "private",
				"bucket": "my-tf-test-bucket",
				"bucket_prefix": null,
				"cors_rule": [],
				"force_destroy": false,
				"grant": [],
				"lifecycle_rule": [],
				"logging": [],
				"object_lock_configuration": [],
				"policy": null,
				"replication_configuration": [],
				"server_side_encryption_configuration": [],
				"tags": {
					"Environment": "Dev",
					"Name": "My bucket",
				},
				"website": [],
			},
		},
	]}},
	"resource_changes": [
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
					"description": "My test policy",
					"name": "test_policy",
					"name_prefix": null,
					"path": "/",
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"sts:*\"\n      ],\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_iam_policy.valid_policy",
			"mode": "managed",
			"type": "aws_iam_policy",
			"name": "valid_policy",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "My test policy",
					"name": "test_policy",
					"name_prefix": null,
					"path": "/",
					"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"sts:AssumeRole\"\n      ],\n      \"Resource\": \"*\"\n    }\n  ]\n}\n",
				},
				"after_unknown": {
					"arn": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_s3_bucket.example",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "example",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"acl": "private",
					"bucket": "my-tf-test-bucket",
					"bucket_prefix": null,
					"cors_rule": [],
					"force_destroy": false,
					"grant": [],
					"lifecycle_rule": [],
					"logging": [],
					"object_lock_configuration": [],
					"policy": null,
					"replication_configuration": [],
					"server_side_encryption_configuration": [],
					"tags": {
						"Environment": "Dev",
						"Name": "My bucket",
					},
					"website": [],
				},
				"after_unknown": {
					"acceleration_status": true,
					"arn": true,
					"bucket_domain_name": true,
					"bucket_regional_domain_name": true,
					"cors_rule": [],
					"grant": [],
					"hosted_zone_id": true,
					"id": true,
					"lifecycle_rule": [],
					"logging": [],
					"object_lock_configuration": [],
					"region": true,
					"replication_configuration": [],
					"request_payer": true,
					"server_side_encryption_configuration": [],
					"tags": {},
					"versioning": true,
					"website": [],
					"website_domain": true,
					"website_endpoint": true,
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
				"address": "aws_iam_policy.invalid_policy",
				"mode": "managed",
				"type": "aws_iam_policy",
				"name": "invalid_policy",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "My test policy"},
					"name": {"constant_value": "test_policy"},
					"path": {"constant_value": "/"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"sts:*\"\n      ],\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_policy.valid_policy",
				"mode": "managed",
				"type": "aws_iam_policy",
				"name": "valid_policy",
				"provider_config_key": "aws",
				"expressions": {
					"description": {"constant_value": "My test policy"},
					"name": {"constant_value": "test_policy"},
					"path": {"constant_value": "/"},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Effect\": \"Allow\",\n      \"Action\": [\n        \"sts:AssumeRole\"\n      ],\n      \"Resource\": \"*\"\n    }\n  ]\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_s3_bucket.example",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "example",
				"provider_config_key": "aws",
				"expressions": {
					"acl": {"constant_value": "private"},
					"bucket": {"constant_value": "my-tf-test-bucket"},
					"tags": {"constant_value": {
						"Environment": "Dev",
						"Name": "My bucket",
					}},
				},
				"schema_version": 0,
			},
		]},
	},
}
