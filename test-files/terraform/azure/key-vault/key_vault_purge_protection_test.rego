# Rego test for Key Vault Purge Protection
# Validating rule key_vault_purge_protection: Key Vault should have purge protection enabled.
package rules.key_vault_purge_protection

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_purge_protection_kv {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["azurerm_key_vault.invalid_purge_protection"] == false
	resources["azurerm_key_vault.valid"] == true
}

# Mock input is generated plan for purge_protection_key_vault.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "1.0.0",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "azurerm_key_vault.invalid_purge_protection",
			"mode": "managed",
			"type": "azurerm_key_vault",
			"name": "invalid_purge_protection",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 2,
			"values": {
				"contact": [],
				"enable_rbac_authorization": null,
				"enabled_for_deployment": null,
				"enabled_for_disk_encryption": null,
				"enabled_for_template_deployment": null,
				"location": "eastus",
				"name": "examplekeyvault",
				"purge_protection_enabled": false,
				"resource_group_name": "example-resources",
				"sku_name": "standard",
				"soft_delete_retention_days": 7,
				"tags": null,
				"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
				"timeouts": null,
			},
		},
		{
			"address": "azurerm_key_vault.valid",
			"mode": "managed",
			"type": "azurerm_key_vault",
			"name": "valid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 2,
			"values": {
				"contact": [],
				"enable_rbac_authorization": null,
				"enabled_for_deployment": null,
				"enabled_for_disk_encryption": null,
				"enabled_for_template_deployment": null,
				"location": "eastus",
				"name": "examplekeyvault",
				"purge_protection_enabled": true,
				"resource_group_name": "example-resources",
				"sku_name": "standard",
				"soft_delete_retention_days": 7,
				"tags": null,
				"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
				"timeouts": null,
			},
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
				"name": "example-resources",
				"tags": null,
				"timeouts": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "azurerm_key_vault.invalid_purge_protection",
			"mode": "managed",
			"type": "azurerm_key_vault",
			"name": "invalid_purge_protection",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"contact": [],
					"enable_rbac_authorization": null,
					"enabled_for_deployment": null,
					"enabled_for_disk_encryption": null,
					"enabled_for_template_deployment": null,
					"location": "eastus",
					"name": "examplekeyvault",
					"purge_protection_enabled": false,
					"resource_group_name": "example-resources",
					"sku_name": "standard",
					"soft_delete_retention_days": 7,
					"tags": null,
					"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					"timeouts": null,
				},
				"after_unknown": {
					"access_policy": true,
					"contact": [],
					"id": true,
					"network_acls": true,
					"soft_delete_enabled": true,
					"vault_uri": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"access_policy": [],
					"contact": [],
					"network_acls": [],
				},
			},
		},
		{
			"address": "azurerm_key_vault.valid",
			"mode": "managed",
			"type": "azurerm_key_vault",
			"name": "valid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"contact": [],
					"enable_rbac_authorization": null,
					"enabled_for_deployment": null,
					"enabled_for_disk_encryption": null,
					"enabled_for_template_deployment": null,
					"location": "eastus",
					"name": "examplekeyvault",
					"purge_protection_enabled": true,
					"resource_group_name": "example-resources",
					"sku_name": "standard",
					"soft_delete_retention_days": 7,
					"tags": null,
					"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					"timeouts": null,
				},
				"after_unknown": {
					"access_policy": true,
					"contact": [],
					"id": true,
					"network_acls": true,
					"soft_delete_enabled": true,
					"vault_uri": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"access_policy": [],
					"contact": [],
					"network_acls": [],
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
					"name": "example-resources",
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
			"expressions": {"features": [{}]},
		}},
		"root_module": {"resources": [
			{
				"address": "azurerm_key_vault.invalid_purge_protection",
				"mode": "managed",
				"type": "azurerm_key_vault",
				"name": "invalid_purge_protection",
				"provider_config_key": "azurerm",
				"expressions": {
					"location": {"references": ["azurerm_resource_group.example"]},
					"name": {"constant_value": "examplekeyvault"},
					"purge_protection_enabled": {"constant_value": false},
					"resource_group_name": {"references": ["azurerm_resource_group.example"]},
					"sku_name": {"constant_value": "standard"},
					"soft_delete_retention_days": {"constant_value": 7},
					"tenant_id": {"constant_value": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"},
				},
				"schema_version": 2,
			},
			{
				"address": "azurerm_key_vault.valid",
				"mode": "managed",
				"type": "azurerm_key_vault",
				"name": "valid",
				"provider_config_key": "azurerm",
				"expressions": {
					"location": {"references": ["azurerm_resource_group.example"]},
					"name": {"constant_value": "examplekeyvault"},
					"purge_protection_enabled": {"constant_value": true},
					"resource_group_name": {"references": ["azurerm_resource_group.example"]},
					"sku_name": {"constant_value": "standard"},
					"soft_delete_retention_days": {"constant_value": 7},
					"tenant_id": {"constant_value": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"},
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
					"location": {"constant_value": "East Us"},
					"name": {"constant_value": "example-resources"},
				},
				"schema_version": 0,
			},
		]},
	},
}
