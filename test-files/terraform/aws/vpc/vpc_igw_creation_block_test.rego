# Rego test for VPC Internet Gateway Creation Block
# Validating rule vpc_igw_creation_block: Deny all Internet Gateways.
package rules.vpc_igw_creation_block

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_vpc_igw_creation_block {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_internet_gateway.invalid"] == false
}

# Mock input is generated plan for vpc_igw_creation_block.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_internet_gateway.invalid",
		"mode": "managed",
		"type": "aws_internet_gateway",
		"name": "invalid",
		"provider_name": "aws",
		"schema_version": 0,
		"values": {
			"tags": {"Name": "main"},
			"vpc_id": "vpc-abcde123",
		},
	}]}},
	"resource_changes": [{
		"address": "aws_internet_gateway.invalid",
		"mode": "managed",
		"type": "aws_internet_gateway",
		"name": "invalid",
		"provider_name": "aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"tags": {"Name": "main"},
				"vpc_id": "vpc-abcde123",
			},
			"after_unknown": {
				"arn": true,
				"id": true,
				"owner_id": true,
				"tags": {},
			},
		},
	}],
	"configuration": {
		"provider_config": {"aws": {
			"name": "aws",
			"expressions": {
				"profile": {"constant_value": "saml"},
				"region": {"constant_value": "us-east-1"},
				"shared_credentials_file": {"constant_value": "~/.aws/creds"},
			},
		}},
		"root_module": {"resources": [{
			"address": "aws_internet_gateway.invalid",
			"mode": "managed",
			"type": "aws_internet_gateway",
			"name": "invalid",
			"provider_config_key": "aws",
			"expressions": {
				"tags": {"constant_value": {"Name": "main"}},
				"vpc_id": {"constant_value": "vpc-abcde123"},
			},
			"schema_version": 0,
		}]},
	},
}
