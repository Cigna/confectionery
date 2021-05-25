# Rego test for S3 Bucket exposed via Bucket Policy
# Validating rule s3_public_policy: Deny S3 Buckets Policies that have Principal:* without aws:SourceVPC or aws:PrincipalOrgID as a condition.
package rules.s3_public_policy

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_s3_public_policy {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_s3_bucket_policy.valid"] == true
	resources["aws_s3_bucket_policy.invalid"] == false
	resources["aws_s3_bucket_policy.valid_deny"] == true
}

mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.19",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_s3_bucket.b",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "b",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"acl": "private",
				"bucket": "my_tf_test_bucket",
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
				"tags": null,
				"website": [],
			},
		},
		{
			"address": "aws_s3_bucket_policy.invalid",
			"mode": "managed",
			"type": "aws_s3_bucket_policy",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": {\n    \"Sid\": \"AllowPutObject\",\n    \"Effect\": \"Allow\",\n    \"Principal\" : { \"AWS\" : \"*\" },\n    \"Action\": \"s3:PutObject\",\n    \"Resource\": \"arn:aws:s3:::example-bucket-dev/*\"\n  }\n}\n"},
		},
		{
			"address": "aws_s3_bucket_policy.valid",
			"mode": "managed",
			"type": "aws_s3_bucket_policy",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": {\n    \"Sid\": \"AllowPutObject\",\n    \"Effect\": \"Allow\",\n    \"Principal\": \"*\",\n    \"Action\": \"s3:PutObject\",\n    \"Resource\": \"arn:aws:s3:::example-bucket-dev/*\",\n    \"Condition\": {\"StringEquals\":\n      {\"aws:PrincipalOrgID\": \"o-xxxxxxxxxxx\"}\n    }\n  }\n}\n"},
		},
		{
			"address": "aws_s3_bucket_policy.valid_deny",
			"mode": "managed",
			"type": "aws_s3_bucket_policy",
			"name": "valid_deny",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {"policy": "{\n    \"Version\": \"2012-10-17\",\n    \"Id\": \"DefaultBucketPolicy\",\n    \"Statement\": [\n        {\n          \"Sid\": \"DefaultDenyNonSecure\",\n          \"Effect\": \"Deny\",\n          \"Principal\": { \"AWS\": [\"arn:aws:iam::123456789012:root\"] },\n          \"Action\": \"*\",\n          \"Condition\": {\n            \"Bool\": {\n              \"aws:SecureTransport\": \"false\"\n            },\n            \"StringEquals\": {\n              \"aws:PrincipalOrgID\": \"o-xxxxxxxxxxx\"\n            }            \n          },\n          \"Resource\": \"arn:aws:s3:::example-bucket-dev/*\"\n        }\n    ]\n}\n"},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_s3_bucket.b",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "b",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"acl": "private",
					"bucket": "my_tf_test_bucket",
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
					"tags": null,
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
					"versioning": true,
					"website": [],
					"website_domain": true,
					"website_endpoint": true,
				},
			},
		},
		{
			"address": "aws_s3_bucket_policy.invalid",
			"mode": "managed",
			"type": "aws_s3_bucket_policy",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": {\n    \"Sid\": \"AllowPutObject\",\n    \"Effect\": \"Allow\",\n    \"Principal\" : { \"AWS\" : \"*\" },\n    \"Action\": \"s3:PutObject\",\n    \"Resource\": \"arn:aws:s3:::example-bucket-dev/*\"\n  }\n}\n"},
				"after_unknown": {
					"bucket": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_s3_bucket_policy.valid",
			"mode": "managed",
			"type": "aws_s3_bucket_policy",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": {\n    \"Sid\": \"AllowPutObject\",\n    \"Effect\": \"Allow\",\n    \"Principal\": \"*\",\n    \"Action\": \"s3:PutObject\",\n    \"Resource\": \"arn:aws:s3:::example-bucket-dev/*\",\n    \"Condition\": {\"StringEquals\":\n      {\"aws:PrincipalOrgID\": \"o-xxxxxxxxxxx\"}\n    }\n  }\n}\n"},
				"after_unknown": {
					"bucket": true,
					"id": true,
				},
			},
		},
		{
			"address": "aws_s3_bucket_policy.valid_deny",
			"mode": "managed",
			"type": "aws_s3_bucket_policy",
			"name": "valid_deny",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"policy": "{\n    \"Version\": \"2012-10-17\",\n    \"Id\": \"DefaultBucketPolicy\",\n    \"Statement\": [\n        {\n          \"Sid\": \"DefaultDenyNonSecure\",\n          \"Effect\": \"Deny\",\n          \"Principal\": { \"AWS\": [\"arn:aws:iam::123456789012:root\"] },\n          \"Action\": \"*\",\n          \"Condition\": {\n            \"Bool\": {\n              \"aws:SecureTransport\": \"false\"\n            },\n            \"StringEquals\": {\n              \"aws:PrincipalOrgID\": \"o-xxxxxxxxxxx\"\n            }            \n          },\n          \"Resource\": \"arn:aws:s3:::example-bucket-dev/*\"\n        }\n    ]\n}\n"},
				"after_unknown": {
					"bucket": true,
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
				"shared_credentials_file": {"constant_value": "~/.aws/creds"},
			},
		}},
		"root_module": {"resources": [
			{
				"address": "aws_s3_bucket.b",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "b",
				"provider_config_key": "aws",
				"expressions": {"bucket": {"constant_value": "my_tf_test_bucket"}},
				"schema_version": 0,
			},
			{
				"address": "aws_s3_bucket_policy.invalid",
				"mode": "managed",
				"type": "aws_s3_bucket_policy",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"bucket": {"references": ["aws_s3_bucket.b"]},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": {\n    \"Sid\": \"AllowPutObject\",\n    \"Effect\": \"Allow\",\n    \"Principal\" : { \"AWS\" : \"*\" },\n    \"Action\": \"s3:PutObject\",\n    \"Resource\": \"arn:aws:s3:::example-bucket-dev/*\"\n  }\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_s3_bucket_policy.valid",
				"mode": "managed",
				"type": "aws_s3_bucket_policy",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"bucket": {"references": ["aws_s3_bucket.b"]},
					"policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": {\n    \"Sid\": \"AllowPutObject\",\n    \"Effect\": \"Allow\",\n    \"Principal\": \"*\",\n    \"Action\": \"s3:PutObject\",\n    \"Resource\": \"arn:aws:s3:::example-bucket-dev/*\",\n    \"Condition\": {\"StringEquals\":\n      {\"aws:PrincipalOrgID\": \"o-xxxxxxxxxxx\"}\n    }\n  }\n}\n"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_s3_bucket_policy.valid_deny",
				"mode": "managed",
				"type": "aws_s3_bucket_policy",
				"name": "valid_deny",
				"provider_config_key": "aws",
				"expressions": {
					"bucket": {"references": ["aws_s3_bucket.b"]},
					"policy": {"constant_value": "{\n    \"Version\": \"2012-10-17\",\n    \"Id\": \"DefaultBucketPolicy\",\n    \"Statement\": [\n        {\n          \"Sid\": \"DefaultDenyNonSecure\",\n          \"Effect\": \"Deny\",\n          \"Principal\": { \"AWS\": [\"arn:aws:iam::123456789012:root\"] },\n          \"Action\": \"*\",\n          \"Condition\": {\n            \"Bool\": {\n              \"aws:SecureTransport\": \"false\"\n            },\n            \"StringEquals\": {\n              \"aws:PrincipalOrgID\": \"o-xl5jimff3q\"\n            }            \n          },\n          \"Resource\": \"arn:aws:s3:::example-bucket-dev/*\"\n        }\n    ]\n}\n"},
				},
				"schema_version": 0,
			},
		]},
	},
}
