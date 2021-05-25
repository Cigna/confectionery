# Rego test for S3 Public ACL
# Validating rule s3_public_access_acl: Deny S3 Buckets with ACL set to public (ACL value beginning with "public-" or "authenticated-"
package rules.s3_public_access_acl

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_s3_private {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_s3_bucket.public"] == false
	resources["aws_s3_bucket.private"] == true
}

# Mock input is generated plan for s3_public_access_acl.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.20",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.private",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "private",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"acl": "private",
				"bucket": "private",
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
					"Name": "My private",
				},
				"website": [],
			},
		},
		{
			"address": "aws_s3_bucket.public",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "public",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"acl": "public-read",
				"bucket": "public",
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
					"Name": "My public bucket",
				},
				"website": [],
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_s3_bucket.private",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "private",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"acl": "private",
					"bucket": "private",
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
						"Name": "My private",
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
		{
			"address": "aws_s3_bucket.public",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "public",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"acl": "public-read",
					"bucket": "public",
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
						"Name": "My public bucket",
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
				"address": "aws_s3_bucket.private",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "private",
				"provider_config_key": "aws",
				"expressions": {
					"acl": {"constant_value": "private"},
					"bucket": {"constant_value": "private"},
					"tags": {"constant_value": {
						"Environment": "Dev",
						"Name": "My private",
					}},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_s3_bucket.public",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "public",
				"provider_config_key": "aws",
				"expressions": {
					"acl": {"constant_value": "public-read"},
					"bucket": {"constant_value": "public"},
					"tags": {"constant_value": {
						"Environment": "Dev",
						"Name": "My public bucket",
					}},
				},
				"schema_version": 0,
			},
		]},
	},
}
