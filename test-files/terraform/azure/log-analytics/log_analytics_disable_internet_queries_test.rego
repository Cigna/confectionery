# Rego test for Log Analytics Disable Internet Queries
# This rule denies Log Analytics Workspace resources from being created that do not disable internet queries
package rules.log_analytics_disable_internet_queries

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_internet_queries_requirement {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["azurerm_log_analytics_workspace.valid"] == true
	resources["azurerm_log_analytics_workspace.invalid"] == false
}

# Mock input is generated plan for log_analytics_internet_queries.tf
mock_plan_input = {
	"format_version": "0.2",
	"terraform_version": "1.0.11",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "azurerm_log_analytics_workspace.invalid",
			"mode": "managed",
			"type": "azurerm_log_analytics_workspace",
			"name": "invalid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 2,
			"values": {
				"daily_quota_gb": -1,
				"internet_ingestion_enabled": true,
				"internet_query_enabled": true,
				"location": "eastus",
				"name": "acctest-01-invalid",
				"reservation_capcity_in_gb_per_day": null,
				"resource_group_name": "terraform-example-resources",
				"retention_in_days": 30,
				"sku": "PerGB2018",
				"tags": null,
				"timeouts": null,
			},
			"sensitive_values": {},
		},
		{
			"address": "azurerm_log_analytics_workspace.valid",
			"mode": "managed",
			"type": "azurerm_log_analytics_workspace",
			"name": "valid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 2,
			"values": {
				"daily_quota_gb": -1,
				"internet_ingestion_enabled": true,
				"internet_query_enabled": false,
				"location": "eastus",
				"name": "acctest-01-valid",
				"reservation_capcity_in_gb_per_day": null,
				"resource_group_name": "terraform-example-resources",
				"retention_in_days": 30,
				"sku": "PerGB2018",
				"tags": null,
				"timeouts": null,
			},
			"sensitive_values": {},
		},
		{
			"address": "azurerm_resource_group.example",
			"mode": "managed",
			"type": "azurerm_resource_group",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 0,
			"values": {
				"location": "eastus",
				"name": "terraform-example-resources",
				"tags": null,
				"timeouts": null,
			},
			"sensitive_values": {},
		},
	]}},
	"resource_changes": [
		{
			"address": "azurerm_log_analytics_workspace.invalid",
			"mode": "managed",
			"type": "azurerm_log_analytics_workspace",
			"name": "invalid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"daily_quota_gb": -1,
					"internet_ingestion_enabled": true,
					"internet_query_enabled": true,
					"location": "eastus",
					"name": "acctest-01-invalid",
					"reservation_capcity_in_gb_per_day": null,
					"resource_group_name": "terraform-example-resources",
					"retention_in_days": 30,
					"sku": "PerGB2018",
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"id": true,
					"portal_url": true,
					"primary_shared_key": true,
					"secondary_shared_key": true,
					"workspace_id": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"primary_shared_key": true,
					"secondary_shared_key": true,
				},
			},
		},
		{
			"address": "azurerm_log_analytics_workspace.valid",
			"mode": "managed",
			"type": "azurerm_log_analytics_workspace",
			"name": "valid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"daily_quota_gb": -1,
					"internet_ingestion_enabled": true,
					"internet_query_enabled": false,
					"location": "eastus",
					"name": "acctest-01-valid",
					"reservation_capcity_in_gb_per_day": null,
					"resource_group_name": "terraform-example-resources",
					"retention_in_days": 30,
					"sku": "PerGB2018",
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"id": true,
					"portal_url": true,
					"primary_shared_key": true,
					"secondary_shared_key": true,
					"workspace_id": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"primary_shared_key": true,
					"secondary_shared_key": true,
				},
			},
		},
		{
			"address": "azurerm_resource_group.example",
			"mode": "managed",
			"type": "azurerm_resource_group",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"location": "eastus",
					"name": "terraform-example-resources",
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {"id": true},
				"before_sensitive": false,
				"after_sensitive": {},
			},
		},
	],
	"configuration": {
		"provider_config": {"azurerm": {
			"name": "azurerm",
			"version_constraint": "~> 2.0",
			"expressions": {"features": [{}]},
		}},
		"root_module": {"resources": [
			{
				"address": "azurerm_log_analytics_workspace.invalid",
				"mode": "managed",
				"type": "azurerm_log_analytics_workspace",
				"name": "invalid",
				"provider_config_key": "azurerm",
				"expressions": {
					"internet_query_enabled": {"constant_value": true},
					"location": {"references": [
						"azurerm_resource_group.example.location",
						"azurerm_resource_group.example",
					]},
					"name": {"constant_value": "acctest-01-invalid"},
					"resource_group_name": {"references": [
						"azurerm_resource_group.example.name",
						"azurerm_resource_group.example",
					]},
					"retention_in_days": {"constant_value": 30},
					"sku": {"constant_value": "PerGB2018"},
				},
				"schema_version": 2,
			},
			{
				"address": "azurerm_log_analytics_workspace.valid",
				"mode": "managed",
				"type": "azurerm_log_analytics_workspace",
				"name": "valid",
				"provider_config_key": "azurerm",
				"expressions": {
					"internet_query_enabled": {"constant_value": false},
					"location": {"references": [
						"azurerm_resource_group.example.location",
						"azurerm_resource_group.example",
					]},
					"name": {"constant_value": "acctest-01-valid"},
					"resource_group_name": {"references": [
						"azurerm_resource_group.example.name",
						"azurerm_resource_group.example",
					]},
					"retention_in_days": {"constant_value": 30},
					"sku": {"constant_value": "PerGB2018"},
				},
				"schema_version": 2,
			},
			{
				"address": "azurerm_resource_group.example",
				"mode": "managed",
				"type": "azurerm_resource_group",
				"name": "example",
				"provider_config_key": "azurerm",
				"expressions": {
					"location": {"constant_value": "eastus"},
					"name": {"constant_value": "terraform-example-resources"},
				},
				"schema_version": 0,
			},
		]},
	},
}
