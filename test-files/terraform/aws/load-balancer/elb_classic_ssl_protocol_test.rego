# Rego test for ELB Classic SSL Protocol configuration check
# Validating rule elb_classic_ssl_protocol: Deny ELB Classic resources that are not configurated with proper SSL configurations
package rules.elb_classic_ssl_protocol

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_elb_classic_ssl_protocol {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_load_balancer_policy.wu-tang-ssl_valid"] == true
	resources["aws_load_balancer_policy.wu-tang-ssl_invalid"] == false
}

# Mock input is generated plan for elb_classic_ssl_protocol.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_elb.wu-tang",
			"mode": "managed",
			"type": "aws_elb",
			"name": "wu-tang",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"access_logs": [],
				"availability_zones": ["us-east-1a"],
				"connection_draining": false,
				"connection_draining_timeout": 300,
				"cross_zone_load_balancing": true,
				"idle_timeout": 60,
				"listener": [{
					"instance_port": 443,
					"instance_protocol": "http",
					"lb_port": 443,
					"lb_protocol": "https",
					"ssl_certificate_id": "arn:aws:iam::000000000000:server-certificate/wu-tang.net",
				}],
				"name": "wu-tang",
				"name_prefix": null,
				"tags": {"Name": "wu-tang"},
			},
		},
		{
			"address": "aws_load_balancer_policy.wu-tang-ssl_invalid",
			"mode": "managed",
			"type": "aws_load_balancer_policy",
			"name": "wu-tang-ssl_invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"load_balancer_name": "wu-tang",
				"policy_attribute": [
					{
						"name": "ECDHE-ECDSA-AES128-GCM-SHA256",
						"value": "true",
					},
					{
						"name": "Protocol-TLSv1",
						"value": "true",
					},
				],
				"policy_name": "wu-tang-ssl",
				"policy_type_name": "SSLNegotiationPolicyType",
			},
		},
		{
			"address": "aws_load_balancer_policy.wu-tang-ssl_valid",
			"mode": "managed",
			"type": "aws_load_balancer_policy",
			"name": "wu-tang-ssl_valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"load_balancer_name": "wu-tang",
				"policy_attribute": [
					{
						"name": "ECDHE-ECDSA-AES128-GCM-SHA256",
						"value": "true",
					},
					{
						"name": "Protocol-TLSv1.2",
						"value": "true",
					},
				],
				"policy_name": "wu-tang-ssl",
				"policy_type_name": "SSLNegotiationPolicyType",
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_elb.wu-tang",
			"mode": "managed",
			"type": "aws_elb",
			"name": "wu-tang",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access_logs": [],
					"availability_zones": ["us-east-1a"],
					"connection_draining": false,
					"connection_draining_timeout": 300,
					"cross_zone_load_balancing": true,
					"idle_timeout": 60,
					"listener": [{
						"instance_port": 443,
						"instance_protocol": "http",
						"lb_port": 443,
						"lb_protocol": "https",
						"ssl_certificate_id": "arn:aws:iam::000000000000:server-certificate/wu-tang.net",
					}],
					"name": "wu-tang",
					"name_prefix": null,
					"tags": {"Name": "wu-tang"},
				},
				"after_unknown": {
					"access_logs": [],
					"arn": true,
					"availability_zones": [false],
					"dns_name": true,
					"health_check": true,
					"id": true,
					"instances": true,
					"internal": true,
					"listener": [{}],
					"security_groups": true,
					"source_security_group": true,
					"source_security_group_id": true,
					"subnets": true,
					"tags": {},
					"zone_id": true,
				},
			},
		},
		{
			"address": "aws_load_balancer_policy.wu-tang-ssl_invalid",
			"mode": "managed",
			"type": "aws_load_balancer_policy",
			"name": "wu-tang-ssl_invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"load_balancer_name": "wu-tang",
					"policy_attribute": [
						{
							"name": "ECDHE-ECDSA-AES128-GCM-SHA256",
							"value": "true",
						},
						{
							"name": "Protocol-TLSv1",
							"value": "true",
						},
					],
					"policy_name": "wu-tang-ssl",
					"policy_type_name": "SSLNegotiationPolicyType",
				},
				"after_unknown": {
					"id": true,
					"policy_attribute": [
						{},
						{},
					],
				},
			},
		},
		{
			"address": "aws_load_balancer_policy.wu-tang-ssl_valid",
			"mode": "managed",
			"type": "aws_load_balancer_policy",
			"name": "wu-tang-ssl_valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"load_balancer_name": "wu-tang",
					"policy_attribute": [
						{
							"name": "ECDHE-ECDSA-AES128-GCM-SHA256",
							"value": "true",
						},
						{
							"name": "Protocol-TLSv1.2",
							"value": "true",
						},
					],
					"policy_name": "wu-tang-ssl",
					"policy_type_name": "SSLNegotiationPolicyType",
				},
				"after_unknown": {
					"id": true,
					"policy_attribute": [
						{},
						{},
					],
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
				"address": "aws_elb.wu-tang",
				"mode": "managed",
				"type": "aws_elb",
				"name": "wu-tang",
				"provider_config_key": "aws",
				"expressions": {
					"availability_zones": {"constant_value": ["us-east-1a"]},
					"listener": [{
						"instance_port": {"constant_value": 443},
						"instance_protocol": {"constant_value": "http"},
						"lb_port": {"constant_value": 443},
						"lb_protocol": {"constant_value": "https"},
						"ssl_certificate_id": {"constant_value": "arn:aws:iam::000000000000:server-certificate/wu-tang.net"},
					}],
					"name": {"constant_value": "wu-tang"},
					"tags": {"constant_value": {"Name": "wu-tang"}},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_load_balancer_policy.wu-tang-ssl_invalid",
				"mode": "managed",
				"type": "aws_load_balancer_policy",
				"name": "wu-tang-ssl_invalid",
				"provider_config_key": "aws",
				"expressions": {
					"load_balancer_name": {"references": ["aws_elb.wu-tang"]},
					"policy_attribute": [
						{
							"name": {"constant_value": "ECDHE-ECDSA-AES128-GCM-SHA256"},
							"value": {"constant_value": "true"},
						},
						{
							"name": {"constant_value": "Protocol-TLSv1"},
							"value": {"constant_value": "true"},
						},
					],
					"policy_name": {"constant_value": "wu-tang-ssl"},
					"policy_type_name": {"constant_value": "SSLNegotiationPolicyType"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_load_balancer_policy.wu-tang-ssl_valid",
				"mode": "managed",
				"type": "aws_load_balancer_policy",
				"name": "wu-tang-ssl_valid",
				"provider_config_key": "aws",
				"expressions": {
					"load_balancer_name": {"references": ["aws_elb.wu-tang"]},
					"policy_attribute": [
						{
							"name": {"constant_value": "ECDHE-ECDSA-AES128-GCM-SHA256"},
							"value": {"constant_value": "true"},
						},
						{
							"name": {"constant_value": "Protocol-TLSv1.2"},
							"value": {"constant_value": "true"},
						},
					],
					"policy_name": {"constant_value": "wu-tang-ssl"},
					"policy_type_name": {"constant_value": "SSLNegotiationPolicyType"},
				},
				"schema_version": 0,
			},
		]},
	},
}
