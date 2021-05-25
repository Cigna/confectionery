# Rego test file for elasticache encryption
# Validating rule ensures that elasticache encryption is enabled at rest and in transit
package rules.elasticache_encryption

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_elasticache_encryption {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_elasticache_replication_group.valid"] == true
	resources["aws_elasticache_replication_group.invalid"] == false
}

# Mock input is generated from elasticache_encryption.tf
# Valid if encryption at rest and in transit is enabled
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_elasticache_replication_group.invalid",
			"mode": "managed",
			"type": "aws_elasticache_replication_group",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"at_rest_encryption_enabled": false,
				"auth_token": null,
				"auto_minor_version_upgrade": true,
				"automatic_failover_enabled": true,
				"availability_zones": [
					"us-west-2a",
					"us-west-2b",
				],
				"engine": "redis",
				"kms_key_id": null,
				"node_type": "cache.m4.large",
				"notification_topic_arn": null,
				"number_cache_clusters": 2,
				"parameter_group_name": "default.redis3.2",
				"port": 6379,
				"replication_group_description": "test description",
				"replication_group_id": "tf-rep-group-1",
				"snapshot_arns": null,
				"snapshot_name": null,
				"snapshot_retention_limit": null,
				"tags": null,
				"timeouts": null,
				"transit_encryption_enabled": false,
			},
		},
		{
			"address": "aws_elasticache_replication_group.valid",
			"mode": "managed",
			"type": "aws_elasticache_replication_group",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"at_rest_encryption_enabled": true,
				"auth_token": null,
				"auto_minor_version_upgrade": true,
				"automatic_failover_enabled": true,
				"availability_zones": [
					"us-west-2a",
					"us-west-2b",
				],
				"engine": "redis",
				"kms_key_id": null,
				"node_type": "cache.m4.large",
				"notification_topic_arn": null,
				"number_cache_clusters": 2,
				"parameter_group_name": "default.redis3.2",
				"port": 6379,
				"replication_group_description": "test description",
				"replication_group_id": "tf-rep-group-1",
				"snapshot_arns": null,
				"snapshot_name": null,
				"snapshot_retention_limit": null,
				"tags": null,
				"timeouts": null,
				"transit_encryption_enabled": true,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_elasticache_replication_group.invalid",
			"mode": "managed",
			"type": "aws_elasticache_replication_group",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"at_rest_encryption_enabled": false,
					"auth_token": null,
					"auto_minor_version_upgrade": true,
					"automatic_failover_enabled": true,
					"availability_zones": [
						"us-west-2a",
						"us-west-2b",
					],
					"engine": "redis",
					"kms_key_id": null,
					"node_type": "cache.m4.large",
					"notification_topic_arn": null,
					"number_cache_clusters": 2,
					"parameter_group_name": "default.redis3.2",
					"port": 6379,
					"replication_group_description": "test description",
					"replication_group_id": "tf-rep-group-1",
					"snapshot_arns": null,
					"snapshot_name": null,
					"snapshot_retention_limit": null,
					"tags": null,
					"timeouts": null,
					"transit_encryption_enabled": false,
				},
				"after_unknown": {
					"apply_immediately": true,
					"availability_zones": [
						false,
						false,
					],
					"cluster_mode": true,
					"configuration_endpoint_address": true,
					"engine_version": true,
					"id": true,
					"maintenance_window": true,
					"member_clusters": true,
					"primary_endpoint_address": true,
					"security_group_ids": true,
					"security_group_names": true,
					"snapshot_window": true,
					"subnet_group_name": true,
				},
			},
		},
		{
			"address": "aws_elasticache_replication_group.valid",
			"mode": "managed",
			"type": "aws_elasticache_replication_group",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"at_rest_encryption_enabled": true,
					"auth_token": null,
					"auto_minor_version_upgrade": true,
					"automatic_failover_enabled": true,
					"availability_zones": [
						"us-west-2a",
						"us-west-2b",
					],
					"engine": "redis",
					"kms_key_id": null,
					"node_type": "cache.m4.large",
					"notification_topic_arn": null,
					"number_cache_clusters": 2,
					"parameter_group_name": "default.redis3.2",
					"port": 6379,
					"replication_group_description": "test description",
					"replication_group_id": "tf-rep-group-1",
					"snapshot_arns": null,
					"snapshot_name": null,
					"snapshot_retention_limit": null,
					"tags": null,
					"timeouts": null,
					"transit_encryption_enabled": true,
				},
				"after_unknown": {
					"apply_immediately": true,
					"availability_zones": [
						false,
						false,
					],
					"cluster_mode": true,
					"configuration_endpoint_address": true,
					"engine_version": true,
					"id": true,
					"maintenance_window": true,
					"member_clusters": true,
					"primary_endpoint_address": true,
					"security_group_ids": true,
					"security_group_names": true,
					"snapshot_window": true,
					"subnet_group_name": true,
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
				"address": "aws_elasticache_replication_group.invalid",
				"mode": "managed",
				"type": "aws_elasticache_replication_group",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"automatic_failover_enabled": {"constant_value": true},
					"availability_zones": {"constant_value": [
						"us-west-2a",
						"us-west-2b",
					]},
					"node_type": {"constant_value": "cache.m4.large"},
					"number_cache_clusters": {"constant_value": 2},
					"parameter_group_name": {"constant_value": "default.redis3.2"},
					"port": {"constant_value": 6379},
					"replication_group_description": {"constant_value": "test description"},
					"replication_group_id": {"constant_value": "tf-rep-group-1"},
				},
				"schema_version": 1,
			},
			{
				"address": "aws_elasticache_replication_group.valid",
				"mode": "managed",
				"type": "aws_elasticache_replication_group",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"at_rest_encryption_enabled": {"constant_value": true},
					"automatic_failover_enabled": {"constant_value": true},
					"availability_zones": {"constant_value": [
						"us-west-2a",
						"us-west-2b",
					]},
					"node_type": {"constant_value": "cache.m4.large"},
					"number_cache_clusters": {"constant_value": 2},
					"parameter_group_name": {"constant_value": "default.redis3.2"},
					"port": {"constant_value": 6379},
					"replication_group_description": {"constant_value": "test description"},
					"replication_group_id": {"constant_value": "tf-rep-group-1"},
					"transit_encryption_enabled": {"constant_value": true},
				},
				"schema_version": 1,
			},
		]},
	},
}
