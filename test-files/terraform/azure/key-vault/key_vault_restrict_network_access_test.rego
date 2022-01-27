# Rego test for Key Vault Restrict Network Access
# Validating rule key_vault_restrict_network_access.rego: Deny Key vault resources that allow public IP access
package rules.key_vault_restrict_network_access

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_restrict_network_access_kv {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["azurerm_key_vault.invalid"] == false
	resources["azurerm_key_vault.valid"] == true
}

# Mock input is generated plan for purge_protection_key_vault.tf
mock_plan_input = {
	"format_version": "0.2",
	"terraform_version": "1.0.11",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "azurerm_key_vault.invalid",
			"mode": "managed",
			"type": "azurerm_key_vault",
			"name": "invalid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 2,
			"values": {
				"access_policy": [{
					"application_id": null,
					"certificate_permissions": null,
					"key_permissions": ["Get"],
					"object_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					"secret_permissions": ["Get"],
					"storage_permissions": ["Get"],
					"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
				}],
				"contact": [],
				"enable_rbac_authorization": null,
				"enabled_for_deployment": null,
				"enabled_for_disk_encryption": null,
				"enabled_for_template_deployment": null,
				"location": "eastus",
				"name": "examplekeyvault-invalid",
				"network_acls": [{
					"bypass": "None",
					"default_action": "Allow",
					"ip_rules": null,
					"virtual_network_subnet_ids": null,
				}],
				"purge_protection_enabled": true,
				"resource_group_name": "terraform-example-resources",
				"sku_name": "standard",
				"soft_delete_retention_days": 7,
				"tags": null,
				"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
				"timeouts": null,
			},
			"sensitive_values": {
				"access_policy": [{
					"key_permissions": [false],
					"secret_permissions": [false],
					"storage_permissions": [false],
				}],
				"contact": [],
				"network_acls": [{}],
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
				"access_policy": [{
					"application_id": null,
					"certificate_permissions": null,
					"key_permissions": ["Get"],
					"object_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					"secret_permissions": ["Get"],
					"storage_permissions": ["Get"],
					"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
				}],
				"contact": [],
				"enable_rbac_authorization": null,
				"enabled_for_deployment": null,
				"enabled_for_disk_encryption": null,
				"enabled_for_template_deployment": null,
				"location": "eastus",
				"name": "examplekeyvault-valid",
				"network_acls": [{
					"bypass": "None",
					"default_action": "Deny",
					"ip_rules": ["10.0.0.0/16"],
					"virtual_network_subnet_ids": null,
				}],
				"purge_protection_enabled": true,
				"resource_group_name": "terraform-example-resources",
				"sku_name": "standard",
				"soft_delete_retention_days": 7,
				"tags": null,
				"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
				"timeouts": null,
			},
			"sensitive_values": {
				"access_policy": [{
					"key_permissions": [false],
					"secret_permissions": [false],
					"storage_permissions": [false],
				}],
				"contact": [],
				"network_acls": [{"ip_rules": [false]}],
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
				"name": "terraform-example-resources",
				"tags": null,
				"timeouts": null,
			},
			"sensitive_values": {},
		},
	]}},
	"resource_changes": [
		{
			"address": "azurerm_key_vault.invalid",
			"mode": "managed",
			"type": "azurerm_key_vault",
			"name": "invalid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access_policy": [{
						"application_id": null,
						"certificate_permissions": null,
						"key_permissions": ["Get"],
						"object_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
						"secret_permissions": ["Get"],
						"storage_permissions": ["Get"],
						"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					}],
					"contact": [],
					"enable_rbac_authorization": null,
					"enabled_for_deployment": null,
					"enabled_for_disk_encryption": null,
					"enabled_for_template_deployment": null,
					"location": "eastus",
					"name": "examplekeyvault-invalid",
					"network_acls": [{
						"bypass": "None",
						"default_action": "Allow",
						"ip_rules": null,
						"virtual_network_subnet_ids": null,
					}],
					"purge_protection_enabled": true,
					"resource_group_name": "terraform-example-resources",
					"sku_name": "standard",
					"soft_delete_retention_days": 7,
					"tags": null,
					"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					"timeouts": null,
				},
				"after_unknown": {
					"access_policy": [{
						"key_permissions": [false],
						"secret_permissions": [false],
						"storage_permissions": [false],
					}],
					"contact": [],
					"id": true,
					"network_acls": [{}],
					"soft_delete_enabled": true,
					"vault_uri": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"access_policy": [{
						"key_permissions": [false],
						"secret_permissions": [false],
						"storage_permissions": [false],
					}],
					"contact": [],
					"network_acls": [{}],
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
					"access_policy": [{
						"application_id": null,
						"certificate_permissions": null,
						"key_permissions": ["Get"],
						"object_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
						"secret_permissions": ["Get"],
						"storage_permissions": ["Get"],
						"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					}],
					"contact": [],
					"enable_rbac_authorization": null,
					"enabled_for_deployment": null,
					"enabled_for_disk_encryption": null,
					"enabled_for_template_deployment": null,
					"location": "eastus",
					"name": "examplekeyvault-valid",
					"network_acls": [{
						"bypass": "None",
						"default_action": "Deny",
						"ip_rules": ["10.0.0.0/16"],
						"virtual_network_subnet_ids": null,
					}],
					"purge_protection_enabled": true,
					"resource_group_name": "terraform-example-resources",
					"sku_name": "standard",
					"soft_delete_retention_days": 7,
					"tags": null,
					"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					"timeouts": null,
				},
				"after_unknown": {
					"access_policy": [{
						"key_permissions": [false],
						"secret_permissions": [false],
						"storage_permissions": [false],
					}],
					"contact": [],
					"id": true,
					"network_acls": [{"ip_rules": [false]}],
					"soft_delete_enabled": true,
					"vault_uri": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"access_policy": [{
						"key_permissions": [false],
						"secret_permissions": [false],
						"storage_permissions": [false],
					}],
					"contact": [],
					"network_acls": [{"ip_rules": [false]}],
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
			"expressions": {"features": [{"key_vault": [{"purge_soft_delete_on_destroy": {"constant_value": true}}]}]},
		}},
		"root_module": {"resources": [
			{
				"address": "azurerm_key_vault.invalid",
				"mode": "managed",
				"type": "azurerm_key_vault",
				"name": "invalid",
				"provider_config_key": "azurerm",
				"expressions": {
					"location": {"references": [
						"azurerm_resource_group.example.location",
						"azurerm_resource_group.example",
					]},
					"name": {"constant_value": "examplekeyvault-invalid"},
					"network_acls": [{
						"bypass": {"constant_value": "None"},
						"default_action": {"constant_value": "Allow"},
					}],
					"purge_protection_enabled": {"constant_value": true},
					"resource_group_name": {"references": [
						"azurerm_resource_group.example.name",
						"azurerm_resource_group.example",
					]},
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
					"location": {"references": [
						"azurerm_resource_group.example.location",
						"azurerm_resource_group.example",
					]},
					"name": {"constant_value": "examplekeyvault-valid"},
					"network_acls": [{
						"bypass": {"constant_value": "None"},
						"default_action": {"constant_value": "Deny"},
						"ip_rules": {"constant_value": ["10.0.0.0/16"]},
					}],
					"purge_protection_enabled": {"constant_value": true},
					"resource_group_name": {"references": [
						"azurerm_resource_group.example.name",
						"azurerm_resource_group.example",
					]},
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
					"location": {"constant_value": "eastus"},
					"name": {"constant_value": "terraform-example-resources"},
				},
				"schema_version": 0,
			},
		]},
	},
}
