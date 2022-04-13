# Rego test for Web App HTTPS Requirement
# This rule denies Web App resources from being created that do not require HTTPS protocol for app endpoint access
package rules.web_app_https_requirement

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_https_requirement {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["azurerm_app_service.valid"] == true
	resources["azurerm_app_service.invalid"] == false
}

# Mock input is generated plan for web_app_https_requirement.tf
mock_plan_input = {
	"format_version": "0.2",
	"terraform_version": "1.0.11",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "azurerm_app_service.invalid",
			"mode": "managed",
			"type": "azurerm_app_service",
			"name": "invalid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 0,
			"values": {
				"app_settings": {"SOME_KEY": "some-value"},
				"backup": [],
				"client_affinity_enabled": false,
				"client_cert_enabled": false,
				"connection_string": [{
					"name": "Database",
					"type": "SQLServer",
					"value": "Server=some-server.mydomain.com;Integrated Security=SSPI",
				}],
				"enabled": true,
				"https_only": false,
				"location": "eastus",
				"name": "example-app-service",
				"resource_group_name": "terraform-example-resources",
				"tags": null,
				"timeouts": null,
			},
			"sensitive_values": {
				"app_settings": {},
				"auth_settings": [],
				"backup": [],
				"connection_string": [{}],
				"identity": [],
				"logs": [],
				"outbound_ip_address_list": [],
				"possible_outbound_ip_address_list": [],
				"site_config": [],
				"site_credential": [],
				"source_control": [],
				"storage_account": [],
			},
		},
		{
			"address": "azurerm_app_service.valid",
			"mode": "managed",
			"type": "azurerm_app_service",
			"name": "valid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 0,
			"values": {
				"app_settings": {"SOME_KEY": "some-value"},
				"backup": [],
				"client_affinity_enabled": false,
				"client_cert_enabled": false,
				"connection_string": [{
					"name": "Database",
					"type": "SQLServer",
					"value": "Server=some-server.mydomain.com;Integrated Security=SSPI",
				}],
				"enabled": true,
				"https_only": true,
				"location": "eastus",
				"name": "example-app-service",
				"resource_group_name": "terraform-example-resources",
				"tags": null,
				"timeouts": null,
			},
			"sensitive_values": {
				"app_settings": {},
				"auth_settings": [],
				"backup": [],
				"connection_string": [{}],
				"identity": [],
				"logs": [],
				"outbound_ip_address_list": [],
				"possible_outbound_ip_address_list": [],
				"site_config": [],
				"site_credential": [],
				"source_control": [],
				"storage_account": [],
			},
		},
		{
			"address": "azurerm_app_service_plan.example",
			"mode": "managed",
			"type": "azurerm_app_service_plan",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"schema_version": 0,
			"values": {
				"app_service_environment_id": null,
				"is_xenon": null,
				"kind": "Windows",
				"location": "eastus",
				"name": "example-appserviceplan",
				"per_site_scaling": null,
				"reserved": null,
				"resource_group_name": "terraform-example-resources",
				"sku": [{
					"size": "S1",
					"tier": "Standard",
				}],
				"tags": null,
				"timeouts": null,
				"zone_redundant": null,
			},
			"sensitive_values": {"sku": [{}]},
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
			"address": "azurerm_app_service.invalid",
			"mode": "managed",
			"type": "azurerm_app_service",
			"name": "invalid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"app_settings": {"SOME_KEY": "some-value"},
					"backup": [],
					"client_affinity_enabled": false,
					"client_cert_enabled": false,
					"connection_string": [{
						"name": "Database",
						"type": "SQLServer",
						"value": "Server=some-server.mydomain.com;Integrated Security=SSPI",
					}],
					"enabled": true,
					"https_only": false,
					"location": "eastus",
					"name": "example-app-service",
					"resource_group_name": "terraform-example-resources",
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"app_service_plan_id": true,
					"app_settings": {},
					"auth_settings": true,
					"backup": [],
					"connection_string": [{}],
					"custom_domain_verification_id": true,
					"default_site_hostname": true,
					"id": true,
					"identity": true,
					"key_vault_reference_identity_id": true,
					"logs": true,
					"outbound_ip_address_list": true,
					"outbound_ip_addresses": true,
					"possible_outbound_ip_address_list": true,
					"possible_outbound_ip_addresses": true,
					"site_config": true,
					"site_credential": true,
					"source_control": true,
					"storage_account": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"app_settings": {},
					"auth_settings": [],
					"backup": [],
					"connection_string": true,
					"identity": [],
					"logs": [],
					"outbound_ip_address_list": [],
					"possible_outbound_ip_address_list": [],
					"site_config": [],
					"site_credential": [],
					"source_control": [],
					"storage_account": [],
				},
			},
		},
		{
			"address": "azurerm_app_service.valid",
			"mode": "managed",
			"type": "azurerm_app_service",
			"name": "valid",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"app_settings": {"SOME_KEY": "some-value"},
					"backup": [],
					"client_affinity_enabled": false,
					"client_cert_enabled": false,
					"connection_string": [{
						"name": "Database",
						"type": "SQLServer",
						"value": "Server=some-server.mydomain.com;Integrated Security=SSPI",
					}],
					"enabled": true,
					"https_only": true,
					"location": "eastus",
					"name": "example-app-service",
					"resource_group_name": "terraform-example-resources",
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"app_service_plan_id": true,
					"app_settings": {},
					"auth_settings": true,
					"backup": [],
					"connection_string": [{}],
					"custom_domain_verification_id": true,
					"default_site_hostname": true,
					"id": true,
					"identity": true,
					"key_vault_reference_identity_id": true,
					"logs": true,
					"outbound_ip_address_list": true,
					"outbound_ip_addresses": true,
					"possible_outbound_ip_address_list": true,
					"possible_outbound_ip_addresses": true,
					"site_config": true,
					"site_credential": true,
					"source_control": true,
					"storage_account": true,
				},
				"before_sensitive": false,
				"after_sensitive": {
					"app_settings": {},
					"auth_settings": [],
					"backup": [],
					"connection_string": true,
					"identity": [],
					"logs": [],
					"outbound_ip_address_list": [],
					"possible_outbound_ip_address_list": [],
					"site_config": [],
					"site_credential": [],
					"source_control": [],
					"storage_account": [],
				},
			},
		},
		{
			"address": "azurerm_app_service_plan.example",
			"mode": "managed",
			"type": "azurerm_app_service_plan",
			"name": "example",
			"provider_name": "registry.terraform.io/hashicorp/azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"app_service_environment_id": null,
					"is_xenon": null,
					"kind": "Windows",
					"location": "eastus",
					"name": "example-appserviceplan",
					"per_site_scaling": null,
					"reserved": null,
					"resource_group_name": "terraform-example-resources",
					"sku": [{
						"size": "S1",
						"tier": "Standard",
					}],
					"tags": null,
					"timeouts": null,
					"zone_redundant": null,
				},
				"after_unknown": {
					"id": true,
					"maximum_elastic_worker_count": true,
					"maximum_number_of_workers": true,
					"sku": [{"capacity": true}],
				},
				"before_sensitive": false,
				"after_sensitive": {"sku": [{}]},
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
				"address": "azurerm_app_service.invalid",
				"mode": "managed",
				"type": "azurerm_app_service",
				"name": "invalid",
				"provider_config_key": "azurerm",
				"expressions": {
					"app_service_plan_id": {"references": [
						"azurerm_app_service_plan.example.id",
						"azurerm_app_service_plan.example",
					]},
					"app_settings": {"constant_value": {"SOME_KEY": "some-value"}},
					"connection_string": [{
						"name": {"constant_value": "Database"},
						"type": {"constant_value": "SQLServer"},
						"value": {"constant_value": "Server=some-server.mydomain.com;Integrated Security=SSPI"},
					}],
					"https_only": {"constant_value": false},
					"location": {"references": [
						"azurerm_resource_group.example.location",
						"azurerm_resource_group.example",
					]},
					"name": {"constant_value": "example-app-service"},
					"resource_group_name": {"references": [
						"azurerm_resource_group.example.name",
						"azurerm_resource_group.example",
					]},
				},
				"schema_version": 0,
			},
			{
				"address": "azurerm_app_service.valid",
				"mode": "managed",
				"type": "azurerm_app_service",
				"name": "valid",
				"provider_config_key": "azurerm",
				"expressions": {
					"app_service_plan_id": {"references": [
						"azurerm_app_service_plan.example.id",
						"azurerm_app_service_plan.example",
					]},
					"app_settings": {"constant_value": {"SOME_KEY": "some-value"}},
					"connection_string": [{
						"name": {"constant_value": "Database"},
						"type": {"constant_value": "SQLServer"},
						"value": {"constant_value": "Server=some-server.mydomain.com;Integrated Security=SSPI"},
					}],
					"https_only": {"constant_value": true},
					"location": {"references": [
						"azurerm_resource_group.example.location",
						"azurerm_resource_group.example",
					]},
					"name": {"constant_value": "example-app-service"},
					"resource_group_name": {"references": [
						"azurerm_resource_group.example.name",
						"azurerm_resource_group.example",
					]},
				},
				"schema_version": 0,
			},
			{
				"address": "azurerm_app_service_plan.example",
				"mode": "managed",
				"type": "azurerm_app_service_plan",
				"name": "example",
				"provider_config_key": "azurerm",
				"expressions": {
					"location": {"references": [
						"azurerm_resource_group.example.location",
						"azurerm_resource_group.example",
					]},
					"name": {"constant_value": "example-appserviceplan"},
					"resource_group_name": {"references": [
						"azurerm_resource_group.example.name",
						"azurerm_resource_group.example",
					]},
					"sku": [{
						"size": {"constant_value": "S1"},
						"tier": {"constant_value": "Standard"},
					}],
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
					"location": {"constant_value": "eastus"},
					"name": {"constant_value": "terraform-example-resources"},
				},
				"schema_version": 0,
			},
		]},
	},
}