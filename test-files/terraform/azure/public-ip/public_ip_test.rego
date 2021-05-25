# Rego test for Public IP Creation
# Validating rule public_ip: Deny all creation of Public IPs.
package rules.public_ip

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_public_ip {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["azurerm_public_ip.invalid_ip"] == false
}

# Mock input is generated plan for public_ip.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "azurerm_public_ip.invalid_ip",
			"mode": "managed",
			"type": "azurerm_public_ip",
			"name": "invalid_ip",
			"provider_name": "azurerm",
			"schema_version": 0,
			"values": {
				"allocation_method": "Dynamic",
				"domain_name_label": null,
				"idle_timeout_in_minutes": 4,
				"ip_version": "IPv4",
				"location": "eastus",
				"name": "myPublicIP",
				"public_ip_prefix_id": null,
				"resource_group_name": "myResourceGroup",
				"reverse_fqdn": null,
				"sku": "Basic",
				"tags": {"environment": "Terraform Demo"},
				"timeouts": null,
				"zones": null,
			},
		},
		{
			"address": "azurerm_resource_group.myterraformgroup",
			"mode": "managed",
			"type": "azurerm_resource_group",
			"name": "myterraformgroup",
			"provider_name": "azurerm",
			"schema_version": 0,
			"values": {
				"location": "eastus",
				"name": "myResourceGroup",
				"tags": {"environment": "Terraform Demo"},
				"timeouts": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "azurerm_public_ip.invalid_ip",
			"mode": "managed",
			"type": "azurerm_public_ip",
			"name": "invalid_ip",
			"provider_name": "azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"allocation_method": "Dynamic",
					"domain_name_label": null,
					"idle_timeout_in_minutes": 4,
					"ip_version": "IPv4",
					"location": "eastus",
					"name": "myPublicIP",
					"public_ip_prefix_id": null,
					"resource_group_name": "myResourceGroup",
					"reverse_fqdn": null,
					"sku": "Basic",
					"tags": {"environment": "Terraform Demo"},
					"timeouts": null,
					"zones": null,
				},
				"after_unknown": {
					"fqdn": true,
					"id": true,
					"ip_address": true,
					"tags": {},
				},
			},
		},
		{
			"address": "azurerm_resource_group.myterraformgroup",
			"mode": "managed",
			"type": "azurerm_resource_group",
			"name": "myterraformgroup",
			"provider_name": "azurerm",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"location": "eastus",
					"name": "myResourceGroup",
					"tags": {"environment": "Terraform Demo"},
					"timeouts": null,
				},
				"after_unknown": {
					"id": true,
					"tags": {},
				},
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
				"address": "azurerm_public_ip.invalid_ip",
				"mode": "managed",
				"type": "azurerm_public_ip",
				"name": "invalid_ip",
				"provider_config_key": "azurerm",
				"expressions": {
					"allocation_method": {"constant_value": "Dynamic"},
					"location": {"constant_value": "eastus"},
					"name": {"constant_value": "myPublicIP"},
					"resource_group_name": {"references": ["azurerm_resource_group.myterraformgroup"]},
					"tags": {"constant_value": {"environment": "Terraform Demo"}},
				},
				"schema_version": 0,
			},
			{
				"address": "azurerm_resource_group.myterraformgroup",
				"mode": "managed",
				"type": "azurerm_resource_group",
				"name": "myterraformgroup",
				"provider_config_key": "azurerm",
				"expressions": {
					"location": {"constant_value": "eastus"},
					"name": {"constant_value": "myResourceGroup"},
					"tags": {"constant_value": {"environment": "Terraform Demo"}},
				},
				"schema_version": 0,
			},
		]},
	},
}
