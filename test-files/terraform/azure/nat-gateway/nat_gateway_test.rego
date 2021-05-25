# Rego test for NAT Gateway Creation
# Validating rule nat_gateway: Deny all creation of NAT gateways.
package rules.nat_gateway

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_nat_gateway {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["azurerm_nat_gateway.invalid_nat_gateway"] == false
}

# Mock input is generated plan for nat_gateway.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "azurerm_nat_gateway.invalid_nat_gateway",
			"mode": "managed",
			"type": "azurerm_nat_gateway",
			"name": "invalid_nat_gateway",
			"provider_name": "azurerm",
			"schema_version": 0,
			"values": {
				"idle_timeout_in_minutes": 10,
				"location": "eastus2",
				"name": "nat-Gateway",
				"public_ip_prefix_ids": null,
				"resource_group_name": "nat-gateway-example-rg",
				"sku_name": "Standard",
				"tags": null,
				"timeouts": null,
				"zones": ["1"],
			},
		},
		{
			"address": "azurerm_resource_group.example",
			"mode": "managed",
			"type": "azurerm_resource_group",
			"name": "example",
			"provider_name": "azurerm",
			"schema_version": 0,
			"values": {
				"location": "eastus2",
				"name": "nat-gateway-example-rg",
				"tags": null,
				"timeouts": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "azurerm_nat_gateway.invalid_nat_gateway",
			"mode": "managed",
			"type": "azurerm_nat_gateway",
			"name": "invalid_nat_gateway",
			"provider_name": "azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"idle_timeout_in_minutes": 10,
					"location": "eastus2",
					"name": "nat-Gateway",
					"public_ip_prefix_ids": null,
					"resource_group_name": "nat-gateway-example-rg",
					"sku_name": "Standard",
					"tags": null,
					"timeouts": null,
					"zones": ["1"],
				},
				"after_unknown": {
					"id": true,
					"public_ip_address_ids": true,
					"resource_guid": true,
					"zones": [false],
				},
			},
		},
		{
			"address": "azurerm_resource_group.example",
			"mode": "managed",
			"type": "azurerm_resource_group",
			"name": "example",
			"provider_name": "azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"location": "eastus2",
					"name": "nat-gateway-example-rg",
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {"id": true},
			},
		},
	],
	"configuration": {
		"provider_config": {"azurerm": {
			"name": "azurerm",
			"version_constraint": "~>2.0",
			"expressions": {"features": [{}]},
		}},
		"root_module": {"resources": [
			{
				"address": "azurerm_nat_gateway.invalid_nat_gateway",
				"mode": "managed",
				"type": "azurerm_nat_gateway",
				"name": "invalid_nat_gateway",
				"provider_config_key": "azurerm",
				"expressions": {
					"idle_timeout_in_minutes": {"constant_value": 10},
					"location": {"references": ["azurerm_resource_group.example"]},
					"name": {"constant_value": "nat-Gateway"},
					"resource_group_name": {"references": ["azurerm_resource_group.example"]},
					"sku_name": {"constant_value": "Standard"},
					"zones": {"constant_value": ["1"]},
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
					"location": {"constant_value": "eastus2"},
					"name": {"constant_value": "nat-gateway-example-rg"},
				},
				"schema_version": 0,
			},
		]},
	},
}
