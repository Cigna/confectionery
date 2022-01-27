# Rego test for Cognitive Services CMK Encryption
# Validating rule cognitive_services_cmk: Azure Cognitive Services should encrypt with customer-managed-key.
package rules.cognitive_services_cmk

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_cmk_cognitive_services {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["azurerm_cognitive_account.invalid"] == false
	resources["azurerm_cognitive_account.valid"] == true
}

# Mock input is generated plan for cognitive_services_cmk.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "1.0.0",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "azurerm_cognitive_account.invalid",
			"mode": "managed",
			"type": "azurerm_cognitive_account",
			"name": "invalid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 0,
			"values": {
				"custom_subdomain_name": null,
				"fqdns": null,
				"identity": [],
				"kind": "Face",
				"local_auth_enabled": true,
				"location": "westeurope",
				"metrics_advisor_aad_client_id": null,
				"metrics_advisor_aad_tenant_id": null,
				"metrics_advisor_super_user_name": null,
				"metrics_advisor_website_name": null,
				"name": "example-account-invalid",
				"network_acls": [],
				"outbound_network_access_restrited": false,
				"public_network_access_enabled": true,
				"qna_runtime_endpoint": null,
				"resource_group_name": "example-resources",
				"sku_name": "S0",
				"storage": [],
				"tags": {"Acceptance": "Test"},
				"timeouts": null,
			},
		},
		{
			"address": "azurerm_cognitive_account.valid",
			"mode": "managed",
			"type": "azurerm_cognitive_account",
			"name": "valid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 0,
			"values": {
				"custom_subdomain_name": "example-account",
				"fqdns": null,
				"identity": [{"type": "SystemAssigned, UserAssigned"}],
				"kind": "Face",
				"local_auth_enabled": true,
				"location": "westeurope",
				"metrics_advisor_aad_client_id": null,
				"metrics_advisor_aad_tenant_id": null,
				"metrics_advisor_super_user_name": null,
				"metrics_advisor_website_name": null,
				"name": "example-account-valid",
				"network_acls": [],
				"outbound_network_access_restrited": false,
				"public_network_access_enabled": true,
				"qna_runtime_endpoint": null,
				"resource_group_name": "example-resources",
				"sku_name": "E0",
				"storage": [],
				"tags": null,
				"timeouts": null,
			},
		},
		{
			"address": "azurerm_cognitive_account_customer_managed_key.example",
			"mode": "managed",
			"type": "azurerm_cognitive_account_customer_managed_key",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 0,
			"values": {"timeouts": null},
		},
		{
			"address": "azurerm_key_vault.example",
			"mode": "managed",
			"type": "azurerm_key_vault",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 2,
			"values": {
				"access_policy": [{
					"application_id": null,
					"certificate_permissions": null,
					"key_permissions": [
						"Get",
						"Create",
						"List",
						"Restore",
						"Recover",
						"UnwrapKey",
						"WrapKey",
						"Purge",
						"Encrypt",
						"Decrypt",
						"Sign",
						"Verify",
					],
					"object_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					"secret_permissions": ["Get"],
					"storage_permissions": null,
					"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
				}],
				"contact": [],
				"enable_rbac_authorization": null,
				"enabled_for_deployment": null,
				"enabled_for_disk_encryption": null,
				"enabled_for_template_deployment": null,
				"location": "westeurope",
				"name": "example-vault",
				"purge_protection_enabled": true,
				"resource_group_name": "example-resources",
				"sku_name": "standard",
				"soft_delete_enabled": true,
				"soft_delete_retention_days": 90,
				"tags": null,
				"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
				"timeouts": null,
			},
		},
		{
			"address": "azurerm_key_vault_key.example",
			"mode": "managed",
			"type": "azurerm_key_vault_key",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 0,
			"values": {
				"expiration_date": null,
				"key_opts": [
					"decrypt",
					"encrypt",
					"sign",
					"unwrapKey",
					"verify",
					"wrapKey",
				],
				"key_size": 2048,
				"key_type": "RSA",
				"name": "example-key",
				"not_before_date": null,
				"tags": null,
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
				"location": "westeurope",
				"name": "example-resources",
				"tags": null,
				"timeouts": null,
			},
		},
		{
			"address": "azurerm_user_assigned_identity.example",
			"mode": "managed",
			"type": "azurerm_user_assigned_identity",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 1,
			"values": {
				"location": "westeurope",
				"name": "example-identity",
				"resource_group_name": "example-resources",
				"tags": null,
				"timeouts": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "azurerm_cognitive_account.invalid",
			"mode": "managed",
			"type": "azurerm_cognitive_account",
			"name": "invalid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"custom_subdomain_name": null,
					"fqdns": null,
					"identity": [],
					"kind": "Face",
					"local_auth_enabled": true,
					"location": "westeurope",
					"metrics_advisor_aad_client_id": null,
					"metrics_advisor_aad_tenant_id": null,
					"metrics_advisor_super_user_name": null,
					"metrics_advisor_website_name": null,
					"name": "example-account-invalid",
					"network_acls": [],
					"outbound_network_access_restrited": false,
					"public_network_access_enabled": true,
					"qna_runtime_endpoint": null,
					"resource_group_name": "example-resources",
					"sku_name": "S0",
					"storage": [],
					"tags": {"Acceptance": "Test"},
					"timeouts": null,
				},
				"after_unknown": {
					"endpoint": true,
					"id": true,
					"identity": [],
					"network_acls": [],
					"primary_access_key": true,
					"secondary_access_key": true,
					"storage": [],
					"tags": {},
				},
				"before_sensitive": false,
				"after_sensitive": {
					"identity": [],
					"network_acls": [],
					"primary_access_key": true,
					"secondary_access_key": true,
					"storage": [],
					"tags": {},
				},
			},
		},
		{
			"address": "azurerm_cognitive_account.valid",
			"mode": "managed",
			"type": "azurerm_cognitive_account",
			"name": "valid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"custom_subdomain_name": "example-account",
					"fqdns": null,
					"identity": [{"type": "SystemAssigned, UserAssigned"}],
					"kind": "Face",
					"local_auth_enabled": true,
					"location": "westeurope",
					"metrics_advisor_aad_client_id": null,
					"metrics_advisor_aad_tenant_id": null,
					"metrics_advisor_super_user_name": null,
					"metrics_advisor_website_name": null,
					"name": "example-account-valid",
					"network_acls": [],
					"outbound_network_access_restrited": false,
					"public_network_access_enabled": true,
					"qna_runtime_endpoint": null,
					"resource_group_name": "example-resources",
					"sku_name": "E0",
					"storage": [],
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"endpoint": true,
					"id": true,
					"identity": [{
						"identity_ids": true,
						"principal_id": true,
						"tenant_id": true,
					}],
					"network_acls": [],
					"primary_access_key": true,
					"secondary_access_key": true,
					"storage": [],
				},
				"before_sensitive": false,
				"after_sensitive": {
					"identity": [{"identity_ids": []}],
					"network_acls": [],
					"primary_access_key": true,
					"secondary_access_key": true,
					"storage": [],
				},
			},
		},
		{
			"address": "azurerm_cognitive_account_customer_managed_key.example",
			"mode": "managed",
			"type": "azurerm_cognitive_account_customer_managed_key",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {"timeouts": null},
				"after_unknown": {
					"cognitive_account_id": true,
					"id": true,
					"identity_client_id": true,
					"key_vault_key_id": true,
				},
				"before_sensitive": false,
				"after_sensitive": {},
			},
		},
		{
			"address": "azurerm_key_vault.example",
			"mode": "managed",
			"type": "azurerm_key_vault",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access_policy": [{
						"application_id": null,
						"certificate_permissions": null,
						"key_permissions": [
							"Get",
							"Create",
							"List",
							"Restore",
							"Recover",
							"UnwrapKey",
							"WrapKey",
							"Purge",
							"Encrypt",
							"Decrypt",
							"Sign",
							"Verify",
						],
						"object_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
						"secret_permissions": ["Get"],
						"storage_permissions": null,
						"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					}],
					"contact": [],
					"enable_rbac_authorization": null,
					"enabled_for_deployment": null,
					"enabled_for_disk_encryption": null,
					"enabled_for_template_deployment": null,
					"location": "westeurope",
					"name": "example-vault",
					"purge_protection_enabled": true,
					"resource_group_name": "example-resources",
					"sku_name": "standard",
					"soft_delete_enabled": true,
					"soft_delete_retention_days": 90,
					"tags": null,
					"tenant_id": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f",
					"timeouts": null,
				},
				"after_unknown": {
					"access_policy": [{
						"key_permissions": [
							false,
							false,
							false,
							false,
							false,
							false,
							false,
							false,
							false,
							false,
							false,
							false,
						],
						"secret_permissions": [false],
					}],
					"contact": [],
					"id": true,
					"network_acls": true,
					"vault_uri": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"access_policy": [{
						"key_permissions": [
							false,
							false,
							false,
							false,
							false,
							false,
							false,
							false,
							false,
							false,
							false,
							false,
						],
						"secret_permissions": [false],
					}],
					"contact": [],
					"network_acls": [],
				},
			},
		},
		{
			"address": "azurerm_key_vault_key.example",
			"mode": "managed",
			"type": "azurerm_key_vault_key",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"expiration_date": null,
					"key_opts": [
						"decrypt",
						"encrypt",
						"sign",
						"unwrapKey",
						"verify",
						"wrapKey",
					],
					"key_size": 2048,
					"key_type": "RSA",
					"name": "example-key",
					"not_before_date": null,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"curve": true,
					"e": true,
					"id": true,
					"key_opts": [
						false,
						false,
						false,
						false,
						false,
						false,
					],
					"key_vault_id": true,
					"n": true,
					"version": true,
					"versionless_id": true,
					"x": true,
					"y": true,
				},
				"before_sensitive": false,
				"after_sensitive": {"key_opts": [
					false,
					false,
					false,
					false,
					false,
					false,
				]},
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
					"location": "westeurope",
					"name": "example-resources",
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {"id": true},
				"before_sensitive": false,
				"after_sensitive": {},
			},
		},
		{
			"address": "azurerm_user_assigned_identity.example",
			"mode": "managed",
			"type": "azurerm_user_assigned_identity",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"location": "westeurope",
					"name": "example-identity",
					"resource_group_name": "example-resources",
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"client_id": true,
					"id": true,
					"principal_id": true,
					"tenant_id": true,
				},
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
				"address": "azurerm_cognitive_account.invalid",
				"mode": "managed",
				"type": "azurerm_cognitive_account",
				"name": "invalid",
				"provider_config_key": "azurerm",
				"expressions": {
					"kind": {"constant_value": "Face"},
					"location": {"references": ["azurerm_resource_group.example"]},
					"name": {"constant_value": "example-account-invalid"},
					"resource_group_name": {"references": ["azurerm_resource_group.example"]},
					"sku_name": {"constant_value": "S0"},
					"tags": {"constant_value": {"Acceptance": "Test"}},
				},
				"schema_version": 0,
			},
			{
				"address": "azurerm_cognitive_account.valid",
				"mode": "managed",
				"type": "azurerm_cognitive_account",
				"name": "valid",
				"provider_config_key": "azurerm",
				"expressions": {
					"custom_subdomain_name": {"constant_value": "example-account"},
					"identity": [{
						"identity_ids": {"references": ["azurerm_user_assigned_identity.example"]},
						"type": {"constant_value": "SystemAssigned, UserAssigned"},
					}],
					"kind": {"constant_value": "Face"},
					"location": {"references": ["azurerm_resource_group.example"]},
					"name": {"constant_value": "example-account-valid"},
					"resource_group_name": {"references": ["azurerm_resource_group.example"]},
					"sku_name": {"constant_value": "E0"},
				},
				"schema_version": 0,
			},
			{
				"address": "azurerm_cognitive_account_customer_managed_key.example",
				"mode": "managed",
				"type": "azurerm_cognitive_account_customer_managed_key",
				"name": "example",
				"provider_config_key": "azurerm",
				"expressions": {
					"cognitive_account_id": {"references": ["azurerm_cognitive_account.valid"]},
					"identity_client_id": {"references": ["azurerm_user_assigned_identity.example"]},
					"key_vault_key_id": {"references": ["azurerm_key_vault_key.example"]},
				},
				"schema_version": 0,
			},
			{
				"address": "azurerm_key_vault.example",
				"mode": "managed",
				"type": "azurerm_key_vault",
				"name": "example",
				"provider_config_key": "azurerm",
				"expressions": {
					"location": {"references": ["azurerm_resource_group.example"]},
					"name": {"constant_value": "example-vault"},
					"purge_protection_enabled": {"constant_value": true},
					"resource_group_name": {"references": ["azurerm_resource_group.example"]},
					"sku_name": {"constant_value": "standard"},
					"soft_delete_enabled": {"constant_value": true},
					"tenant_id": {"constant_value": "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"},
				},
				"schema_version": 2,
			},
			{
				"address": "azurerm_key_vault_key.example",
				"mode": "managed",
				"type": "azurerm_key_vault_key",
				"name": "example",
				"provider_config_key": "azurerm",
				"expressions": {
					"key_opts": {"constant_value": [
						"decrypt",
						"encrypt",
						"sign",
						"unwrapKey",
						"verify",
						"wrapKey",
					]},
					"key_size": {"constant_value": 2048},
					"key_type": {"constant_value": "RSA"},
					"key_vault_id": {"references": ["azurerm_key_vault.example"]},
					"name": {"constant_value": "example-key"},
				},
				"schema_version": 0,
			},
			{
				"address": "azurerm_resource_group.example",
				"mode": "managed",
				"type": "azurerm_resource_group",
				"name": "example",
				"provider_config_key": "azurerm",
				"expressions": {
					"location": {"constant_value": "West Europe"},
					"name": {"constant_value": "example-resources"},
				},
				"schema_version": 0,
			},
			{
				"address": "azurerm_user_assigned_identity.example",
				"mode": "managed",
				"type": "azurerm_user_assigned_identity",
				"name": "example",
				"provider_config_key": "azurerm",
				"expressions": {
					"location": {"references": ["azurerm_resource_group.example"]},
					"name": {"constant_value": "example-identity"},
					"resource_group_name": {"references": ["azurerm_resource_group.example"]},
				},
				"schema_version": 1,
			},
		]},
	},
}