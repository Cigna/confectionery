# Rego test for Cloudtrail Creation
# Validating rule cloudtrail_creation: Deny all Cloudtrails.
package rules.cloudtrail_creation

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_cloudtrail_creation {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_cloudtrail.invalid"] == false
}

# Mock input is generated plan for cloudtrail_creation.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_cloudtrail.invalid",
			"mode": "managed",
			"type": "aws_cloudtrail",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"cloud_watch_logs_group_arn": null,
				"cloud_watch_logs_role_arn": null,
				"enable_log_file_validation": false,
				"enable_logging": true,
				"event_selector": [],
				"include_global_service_events": false,
				"is_multi_region_trail": false,
				"is_organization_trail": false,
				"kms_key_id": null,
				"name": "tf-trail-foobar",
				"s3_key_prefix": "prefix",
				"sns_topic_name": null,
				"tags": null,
			},
		},
		{
			"address": "aws_s3_bucket.foo",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "foo",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"acl": "private",
				"bucket": "tf-test-trail",
				"bucket_prefix": null,
				"cors_rule": [],
				"force_destroy": true,
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
	]}},
	"resource_changes": [
		{
			"address": "aws_cloudtrail.invalid",
			"mode": "managed",
			"type": "aws_cloudtrail",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"cloud_watch_logs_group_arn": null,
					"cloud_watch_logs_role_arn": null,
					"enable_log_file_validation": false,
					"enable_logging": true,
					"event_selector": [],
					"include_global_service_events": false,
					"is_multi_region_trail": false,
					"is_organization_trail": false,
					"kms_key_id": null,
					"name": "tf-trail-foobar",
					"s3_key_prefix": "prefix",
					"sns_topic_name": null,
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"event_selector": [],
					"home_region": true,
					"id": true,
					"s3_bucket_name": true,
				},
			},
		},
		{
			"address": "aws_s3_bucket.foo",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"name": "foo",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"acl": "private",
					"bucket": "tf-test-trail",
					"bucket_prefix": null,
					"cors_rule": [],
					"force_destroy": true,
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
				"address": "aws_cloudtrail.invalid",
				"mode": "managed",
				"type": "aws_cloudtrail",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"include_global_service_events": {"constant_value": false},
					"name": {"constant_value": "tf-trail-foobar"},
					"s3_bucket_name": {"references": ["aws_s3_bucket.foo"]},
					"s3_key_prefix": {"constant_value": "prefix"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_s3_bucket.foo",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "foo",
				"provider_config_key": "aws",
				"expressions": {
					"bucket": {"constant_value": "tf-test-trail"},
					"force_destroy": {"constant_value": true},
				},
				"schema_version": 0,
			},
		]},
	},
}
