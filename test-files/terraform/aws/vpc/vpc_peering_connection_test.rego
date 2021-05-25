# Rego test for VPC Peering Connection
# Validating rule vpc_peering_connection: Deny all VPC Peering Connections.
package rules.vpc_peering_connection

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_vpc_peering_connection {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_vpc_peering_connection.invalid"] == false
}

# Mock input is generated plan for vpc_peering_connection.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_vpc.bar",
			"mode": "managed",
			"type": "aws_vpc",
			"name": "bar",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"assign_generated_ipv6_cidr_block": false,
				"cidr_block": "10.2.0.0/16",
				"enable_dns_support": true,
				"instance_tenancy": "default",
				"tags": null,
			},
		},
		{
			"address": "aws_vpc.foo",
			"mode": "managed",
			"type": "aws_vpc",
			"name": "foo",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"assign_generated_ipv6_cidr_block": false,
				"cidr_block": "10.1.0.0/16",
				"enable_dns_support": true,
				"instance_tenancy": "default",
				"tags": null,
			},
		},
		{
			"address": "aws_vpc_peering_connection.invalid",
			"mode": "managed",
			"type": "aws_vpc_peering_connection",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"auto_accept": true,
				"peer_owner_id": "peer_owner_id",
				"tags": {"Name": "VPC Peering between foo and bar"},
				"timeouts": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_vpc.bar",
			"mode": "managed",
			"type": "aws_vpc",
			"name": "bar",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"assign_generated_ipv6_cidr_block": false,
					"cidr_block": "10.2.0.0/16",
					"enable_dns_support": true,
					"instance_tenancy": "default",
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"default_network_acl_id": true,
					"default_route_table_id": true,
					"default_security_group_id": true,
					"dhcp_options_id": true,
					"enable_classiclink": true,
					"enable_classiclink_dns_support": true,
					"enable_dns_hostnames": true,
					"id": true,
					"ipv6_association_id": true,
					"ipv6_cidr_block": true,
					"main_route_table_id": true,
					"owner_id": true,
				},
			},
		},
		{
			"address": "aws_vpc.foo",
			"mode": "managed",
			"type": "aws_vpc",
			"name": "foo",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"assign_generated_ipv6_cidr_block": false,
					"cidr_block": "10.1.0.0/16",
					"enable_dns_support": true,
					"instance_tenancy": "default",
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"default_network_acl_id": true,
					"default_route_table_id": true,
					"default_security_group_id": true,
					"dhcp_options_id": true,
					"enable_classiclink": true,
					"enable_classiclink_dns_support": true,
					"enable_dns_hostnames": true,
					"id": true,
					"ipv6_association_id": true,
					"ipv6_cidr_block": true,
					"main_route_table_id": true,
					"owner_id": true,
				},
			},
		},
		{
			"address": "aws_vpc_peering_connection.invalid",
			"mode": "managed",
			"type": "aws_vpc_peering_connection",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"auto_accept": true,
					"peer_owner_id": "peer_owner_id",
					"tags": {"Name": "VPC Peering between foo and bar"},
					"timeouts": null,
				},
				"after_unknown": {
					"accept_status": true,
					"accepter": true,
					"id": true,
					"peer_region": true,
					"peer_vpc_id": true,
					"requester": true,
					"tags": {},
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
				"address": "aws_vpc.bar",
				"mode": "managed",
				"type": "aws_vpc",
				"name": "bar",
				"provider_config_key": "aws",
				"expressions": {"cidr_block": {"constant_value": "10.2.0.0/16"}},
				"schema_version": 1,
			},
			{
				"address": "aws_vpc.foo",
				"mode": "managed",
				"type": "aws_vpc",
				"name": "foo",
				"provider_config_key": "aws",
				"expressions": {"cidr_block": {"constant_value": "10.1.0.0/16"}},
				"schema_version": 1,
			},
			{
				"address": "aws_vpc_peering_connection.invalid",
				"mode": "managed",
				"type": "aws_vpc_peering_connection",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"auto_accept": {"constant_value": true},
					"peer_owner_id": {"constant_value": "peer_owner_id"},
					"peer_vpc_id": {"references": ["aws_vpc.bar"]},
					"tags": {"constant_value": {"Name": "VPC Peering between foo and bar"}},
					"vpc_id": {"references": ["aws_vpc.foo"]},
				},
				"schema_version": 0,
			},
		]},
	},
}
