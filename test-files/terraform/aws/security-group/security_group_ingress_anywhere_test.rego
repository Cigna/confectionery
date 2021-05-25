# Rego test for Security Group Ingress Anywhere 
# Validating rule security_group_ingress_anywhere_ssh: Deny Security Groups that allow unrestricted access from the internet that is not port 80 or 443

package rules.security_group_ingress_anywhere

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

mock_resources = mock_input.resources

test_security_group_ingress_anywhere {
	resources = mock_input.resources

	count(deny) == 0 with input as resources["aws_security_group.valid_exact_80"]
	count(deny) == 1 with input as resources["aws_security_group.invalid_include_80"]
	count(deny) == 0 with input as resources["aws_security_group.valid_exact_443"]
	count(deny) == 1 with input as resources["aws_security_group.invalid_include_443"]
	count(deny) == 1 with input as resources["aws_security_group.invalid_allow_all"]
}

# Mock input is generated plan for security_group_ingress_anywhere.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_security_group.invalid_allow_all",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "invalid_allow_all",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"description": "Managed by Terraform",
				"ingress": [{
					"cidr_blocks": ["0.0.0.0/0"],
					"description": "",
					"from_port": 0,
					"ipv6_cidr_blocks": [],
					"prefix_list_ids": [],
					"protocol": "tcp",
					"security_groups": [],
					"self": false,
					"to_port": 65535,
				}],
				"name": "invalid_allow_all",
				"name_prefix": null,
				"revoke_rules_on_delete": false,
				"tags": null,
				"timeouts": null,
			},
		},
		{
			"address": "aws_security_group.invalid_include_443",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "invalid_include_443",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"description": "Managed by Terraform",
				"ingress": [{
					"cidr_blocks": ["0.0.0.0/0"],
					"description": "",
					"from_port": 442,
					"ipv6_cidr_blocks": [],
					"prefix_list_ids": [],
					"protocol": "tcp",
					"security_groups": [],
					"self": false,
					"to_port": 444,
				}],
				"name": "invalid_include_valid_443",
				"name_prefix": null,
				"revoke_rules_on_delete": false,
				"tags": null,
				"timeouts": null,
			},
		},
		{
			"address": "aws_security_group.invalid_include_80",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "invalid_include_80",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"description": "Managed by Terraform",
				"ingress": [{
					"cidr_blocks": ["0.0.0.0/0"],
					"description": "",
					"from_port": 79,
					"ipv6_cidr_blocks": [],
					"prefix_list_ids": [],
					"protocol": "tcp",
					"security_groups": [],
					"self": false,
					"to_port": 81,
				}],
				"name": "invalid_include_valid_80",
				"name_prefix": null,
				"revoke_rules_on_delete": false,
				"tags": null,
				"timeouts": null,
			},
		},
		{
			"address": "aws_security_group.valid_exact_443",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "valid_exact_443",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"description": "Managed by Terraform",
				"ingress": [{
					"cidr_blocks": ["0.0.0.0/0"],
					"description": "",
					"from_port": 443,
					"ipv6_cidr_blocks": [],
					"prefix_list_ids": [],
					"protocol": "tcp",
					"security_groups": [],
					"self": false,
					"to_port": 443,
				}],
				"name": "valid_exact_443",
				"name_prefix": null,
				"revoke_rules_on_delete": false,
				"tags": null,
				"timeouts": null,
			},
		},
		{
			"address": "aws_security_group.valid_exact_80",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "valid_exact_80",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"description": "Managed by Terraform",
				"ingress": [{
					"cidr_blocks": ["0.0.0.0/0"],
					"description": "",
					"from_port": 80,
					"ipv6_cidr_blocks": [],
					"prefix_list_ids": [],
					"protocol": "tcp",
					"security_groups": [],
					"self": false,
					"to_port": 80,
				}],
				"name": "valid_exact_80",
				"name_prefix": null,
				"revoke_rules_on_delete": false,
				"tags": null,
				"timeouts": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_security_group.invalid_allow_all",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "invalid_allow_all",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Managed by Terraform",
					"ingress": [{
						"cidr_blocks": ["0.0.0.0/0"],
						"description": "",
						"from_port": 0,
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"protocol": "tcp",
						"security_groups": [],
						"self": false,
						"to_port": 65535,
					}],
					"name": "invalid_allow_all",
					"name_prefix": null,
					"revoke_rules_on_delete": false,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"egress": true,
					"id": true,
					"ingress": [{
						"cidr_blocks": [false],
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"security_groups": [],
					}],
					"owner_id": true,
					"vpc_id": true,
				},
			},
		},
		{
			"address": "aws_security_group.invalid_include_443",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "invalid_include_443",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Managed by Terraform",
					"ingress": [{
						"cidr_blocks": ["0.0.0.0/0"],
						"description": "",
						"from_port": 442,
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"protocol": "tcp",
						"security_groups": [],
						"self": false,
						"to_port": 444,
					}],
					"name": "invalid_include_valid_443",
					"name_prefix": null,
					"revoke_rules_on_delete": false,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"egress": true,
					"id": true,
					"ingress": [{
						"cidr_blocks": [false],
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"security_groups": [],
					}],
					"owner_id": true,
					"vpc_id": true,
				},
			},
		},
		{
			"address": "aws_security_group.invalid_include_80",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "invalid_include_80",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Managed by Terraform",
					"ingress": [{
						"cidr_blocks": ["0.0.0.0/0"],
						"description": "",
						"from_port": 79,
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"protocol": "tcp",
						"security_groups": [],
						"self": false,
						"to_port": 81,
					}],
					"name": "invalid_include_valid_80",
					"name_prefix": null,
					"revoke_rules_on_delete": false,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"egress": true,
					"id": true,
					"ingress": [{
						"cidr_blocks": [false],
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"security_groups": [],
					}],
					"owner_id": true,
					"vpc_id": true,
				},
			},
		},
		{
			"address": "aws_security_group.valid_exact_443",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "valid_exact_443",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Managed by Terraform",
					"ingress": [{
						"cidr_blocks": ["0.0.0.0/0"],
						"description": "",
						"from_port": 443,
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"protocol": "tcp",
						"security_groups": [],
						"self": false,
						"to_port": 443,
					}],
					"name": "valid_exact_443",
					"name_prefix": null,
					"revoke_rules_on_delete": false,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"egress": true,
					"id": true,
					"ingress": [{
						"cidr_blocks": [false],
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"security_groups": [],
					}],
					"owner_id": true,
					"vpc_id": true,
				},
			},
		},
		{
			"address": "aws_security_group.valid_exact_80",
			"mode": "managed",
			"type": "aws_security_group",
			"name": "valid_exact_80",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Managed by Terraform",
					"ingress": [{
						"cidr_blocks": ["0.0.0.0/0"],
						"description": "",
						"from_port": 80,
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"protocol": "tcp",
						"security_groups": [],
						"self": false,
						"to_port": 80,
					}],
					"name": "valid_exact_80",
					"name_prefix": null,
					"revoke_rules_on_delete": false,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"egress": true,
					"id": true,
					"ingress": [{
						"cidr_blocks": [false],
						"ipv6_cidr_blocks": [],
						"prefix_list_ids": [],
						"security_groups": [],
					}],
					"owner_id": true,
					"vpc_id": true,
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
				"address": "aws_security_group.invalid_allow_all",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "invalid_allow_all",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "invalid_allow_all"}},
				"schema_version": 1,
			},
			{
				"address": "aws_security_group.invalid_include_443",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "invalid_include_443",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "invalid_include_valid_443"}},
				"schema_version": 1,
			},
			{
				"address": "aws_security_group.invalid_include_80",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "invalid_include_80",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "invalid_include_valid_80"}},
				"schema_version": 1,
			},
			{
				"address": "aws_security_group.valid_exact_443",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "valid_exact_443",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "valid_exact_443"}},
				"schema_version": 1,
			},
			{
				"address": "aws_security_group.valid_exact_80",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "valid_exact_80",
				"provider_config_key": "aws",
				"expressions": {"name": {"constant_value": "valid_exact_80"}},
				"schema_version": 1,
			},
		]},
	},
}