# Rego test for ELB Classic TLS enablement
# Validating rule for ELB Classic TLS enablement: Deny ELB Classic resources that do not enable TLS
package rules.elb_classic_tls_enabled

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_elb_classic_tls_enabled {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_elb.valid"] == true
	resources["aws_elb.invalid"] == false
}

# Mock input is generated plan for elb_classic_tls_enabled.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_elb.invalid",
			"mode": "managed",
			"type": "aws_elb",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"access_logs": [{
					"bucket": "foo",
					"bucket_prefix": "bar",
					"enabled": true,
					"interval": 60,
				}],
				"availability_zones": [
					"us-west-2a",
					"us-west-2b",
					"us-west-2c",
				],
				"connection_draining": true,
				"connection_draining_timeout": 400,
				"cross_zone_load_balancing": true,
				"health_check": [{
					"healthy_threshold": 2,
					"interval": 30,
					"target": "HTTP:8000/",
					"timeout": 3,
					"unhealthy_threshold": 2,
				}],
				"idle_timeout": 400,
				"listener": [{
					"instance_port": 8000,
					"instance_protocol": "http",
					"lb_port": 80,
					"lb_protocol": "http",
					"ssl_certificate_id": "",
				}],
				"name": "foobar-terraform-elb",
				"name_prefix": null,
				"tags": {"Name": "foobar-terraform-elb"},
			},
		},
		{
			"address": "aws_elb.valid",
			"mode": "managed",
			"type": "aws_elb",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"access_logs": [{
					"bucket": "foo",
					"bucket_prefix": "bar",
					"enabled": true,
					"interval": 60,
				}],
				"availability_zones": [
					"us-west-2a",
					"us-west-2b",
					"us-west-2c",
				],
				"connection_draining": true,
				"connection_draining_timeout": 400,
				"cross_zone_load_balancing": true,
				"health_check": [{
					"healthy_threshold": 2,
					"interval": 30,
					"target": "HTTP:8000/",
					"timeout": 3,
					"unhealthy_threshold": 2,
				}],
				"idle_timeout": 400,
				"listener": [
					{
						"instance_port": 8000,
						"instance_protocol": "http",
						"lb_port": 443,
						"lb_protocol": "https",
						"ssl_certificate_id": "arn:aws:iam::123456789012:server-certificate/certName",
					},
					{
						"instance_port": 8000,
						"instance_protocol": "http",
						"lb_port": 80,
						"lb_protocol": "http",
						"ssl_certificate_id": "",
					},
				],
				"name": "foobar-terraform-elb",
				"name_prefix": null,
				"tags": {"Name": "foobar-terraform-elb"},
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_elb.invalid",
			"mode": "managed",
			"type": "aws_elb",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access_logs": [{
						"bucket": "foo",
						"bucket_prefix": "bar",
						"enabled": true,
						"interval": 60,
					}],
					"availability_zones": [
						"us-west-2a",
						"us-west-2b",
						"us-west-2c",
					],
					"connection_draining": true,
					"connection_draining_timeout": 400,
					"cross_zone_load_balancing": true,
					"health_check": [{
						"healthy_threshold": 2,
						"interval": 30,
						"target": "HTTP:8000/",
						"timeout": 3,
						"unhealthy_threshold": 2,
					}],
					"idle_timeout": 400,
					"listener": [{
						"instance_port": 8000,
						"instance_protocol": "http",
						"lb_port": 80,
						"lb_protocol": "http",
						"ssl_certificate_id": "",
					}],
					"name": "foobar-terraform-elb",
					"name_prefix": null,
					"tags": {"Name": "foobar-terraform-elb"},
				},
				"after_unknown": {
					"access_logs": [{}],
					"arn": true,
					"availability_zones": [
						false,
						false,
						false,
					],
					"dns_name": true,
					"health_check": [{}],
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
			"address": "aws_elb.valid",
			"mode": "managed",
			"type": "aws_elb",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access_logs": [{
						"bucket": "foo",
						"bucket_prefix": "bar",
						"enabled": true,
						"interval": 60,
					}],
					"availability_zones": [
						"us-west-2a",
						"us-west-2b",
						"us-west-2c",
					],
					"connection_draining": true,
					"connection_draining_timeout": 400,
					"cross_zone_load_balancing": true,
					"health_check": [{
						"healthy_threshold": 2,
						"interval": 30,
						"target": "HTTP:8000/",
						"timeout": 3,
						"unhealthy_threshold": 2,
					}],
					"idle_timeout": 400,
					"listener": [
						{
							"instance_port": 8000,
							"instance_protocol": "http",
							"lb_port": 443,
							"lb_protocol": "https",
							"ssl_certificate_id": "arn:aws:iam::123456789012:server-certificate/certName",
						},
						{
							"instance_port": 8000,
							"instance_protocol": "http",
							"lb_port": 80,
							"lb_protocol": "http",
							"ssl_certificate_id": "",
						},
					],
					"name": "foobar-terraform-elb",
					"name_prefix": null,
					"tags": {"Name": "foobar-terraform-elb"},
				},
				"after_unknown": {
					"access_logs": [{}],
					"arn": true,
					"availability_zones": [
						false,
						false,
						false,
					],
					"dns_name": true,
					"health_check": [{}],
					"id": true,
					"instances": true,
					"internal": true,
					"listener": [
						{},
						{},
					],
					"security_groups": true,
					"source_security_group": true,
					"source_security_group_id": true,
					"subnets": true,
					"tags": {},
					"zone_id": true,
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
				"address": "aws_elb.invalid",
				"mode": "managed",
				"type": "aws_elb",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"access_logs": [{
						"bucket": {"constant_value": "foo"},
						"bucket_prefix": {"constant_value": "bar"},
						"interval": {"constant_value": 60},
					}],
					"availability_zones": {"constant_value": [
						"us-west-2a",
						"us-west-2b",
						"us-west-2c",
					]},
					"connection_draining": {"constant_value": true},
					"connection_draining_timeout": {"constant_value": 400},
					"cross_zone_load_balancing": {"constant_value": true},
					"health_check": [{
						"healthy_threshold": {"constant_value": 2},
						"interval": {"constant_value": 30},
						"target": {"constant_value": "HTTP:8000/"},
						"timeout": {"constant_value": 3},
						"unhealthy_threshold": {"constant_value": 2},
					}],
					"idle_timeout": {"constant_value": 400},
					"listener": [{
						"instance_port": {"constant_value": 8000},
						"instance_protocol": {"constant_value": "http"},
						"lb_port": {"constant_value": 80},
						"lb_protocol": {"constant_value": "http"},
					}],
					"name": {"constant_value": "foobar-terraform-elb"},
					"tags": {"constant_value": {"Name": "foobar-terraform-elb"}},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_elb.valid",
				"mode": "managed",
				"type": "aws_elb",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"access_logs": [{
						"bucket": {"constant_value": "foo"},
						"bucket_prefix": {"constant_value": "bar"},
						"interval": {"constant_value": 60},
					}],
					"availability_zones": {"constant_value": [
						"us-west-2a",
						"us-west-2b",
						"us-west-2c",
					]},
					"connection_draining": {"constant_value": true},
					"connection_draining_timeout": {"constant_value": 400},
					"cross_zone_load_balancing": {"constant_value": true},
					"health_check": [{
						"healthy_threshold": {"constant_value": 2},
						"interval": {"constant_value": 30},
						"target": {"constant_value": "HTTP:8000/"},
						"timeout": {"constant_value": 3},
						"unhealthy_threshold": {"constant_value": 2},
					}],
					"idle_timeout": {"constant_value": 400},
					"listener": [
						{
							"instance_port": {"constant_value": 8000},
							"instance_protocol": {"constant_value": "http"},
							"lb_port": {"constant_value": 80},
							"lb_protocol": {"constant_value": "http"},
						},
						{
							"instance_port": {"constant_value": 8000},
							"instance_protocol": {"constant_value": "http"},
							"lb_port": {"constant_value": 443},
							"lb_protocol": {"constant_value": "https"},
							"ssl_certificate_id": {"constant_value": "arn:aws:iam::123456789012:server-certificate/certName"},
						},
					],
					"name": {"constant_value": "foobar-terraform-elb"},
					"tags": {"constant_value": {"Name": "foobar-terraform-elb"}},
				},
				"schema_version": 0,
			},
		]},
	},
}
