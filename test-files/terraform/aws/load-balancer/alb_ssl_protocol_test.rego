# Rego test for alb_ssl_configuration
# Validating rule for alb_ssl_configuration: Deny Application Load Balancers with improperly configured Listeners regarding encryption

package rules.alb_ssl_configuration

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_alb_ssl_configuration {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_lb_listener.valid_listener"] == true
	resources["aws_lb_listener.invalid_listener"] == false
	resources["aws_lb_listener.nlb_listener"] == true
}

# Mock input is generated plan for alb_ssl_configuration.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_lb.invalidtest",
			"mode": "managed",
			"type": "aws_lb",
			"name": "invalidtest",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"access_logs": [],
				"drop_invalid_header_fields": false,
				"enable_cross_zone_load_balancing": null,
				"enable_deletion_protection": true,
				"enable_http2": true,
				"idle_timeout": 60,
				"internal": false,
				"load_balancer_type": "application",
				"name": "test-lb-tf",
				"name_prefix": null,
				"tags": null,
				"timeouts": null,
			},
		},
		{
			"address": "aws_lb.nlb_valid",
			"mode": "managed",
			"type": "aws_lb",
			"name": "nlb_valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"access_logs": [],
				"drop_invalid_header_fields": null,
				"enable_cross_zone_load_balancing": false,
				"enable_deletion_protection": true,
				"enable_http2": null,
				"idle_timeout": null,
				"internal": false,
				"load_balancer_type": "network",
				"name": "test-lb-tf",
				"name_prefix": null,
				"tags": null,
				"timeouts": null,
			},
		},
		{
			"address": "aws_lb.validtest",
			"mode": "managed",
			"type": "aws_lb",
			"name": "validtest",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"access_logs": [],
				"drop_invalid_header_fields": false,
				"enable_cross_zone_load_balancing": null,
				"enable_deletion_protection": true,
				"enable_http2": true,
				"idle_timeout": 60,
				"internal": false,
				"load_balancer_type": "application",
				"name": "test-lb-tf",
				"name_prefix": null,
				"tags": null,
				"timeouts": null,
			},
		},
		{
			"address": "aws_lb_listener.invalid_listener",
			"mode": "managed",
			"type": "aws_lb_listener",
			"name": "invalid_listener",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"certificate_arn": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4",
				"default_action": [{
					"authenticate_cognito": [],
					"authenticate_oidc": [],
					"fixed_response": [],
					"forward": [],
					"redirect": [],
					"target_group_arn": null,
					"type": "forward",
				}],
				"port": 80,
				"protocol": "HTTP",
				"ssl_policy": "ELBSecurityPolicy-2016",
				"timeouts": null,
			},
		},
		{
			"address": "aws_lb_listener.nlb_listener",
			"mode": "managed",
			"type": "aws_lb_listener",
			"name": "nlb_listener",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"certificate_arn": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4",
				"default_action": [{
					"authenticate_cognito": [],
					"authenticate_oidc": [],
					"fixed_response": [],
					"forward": [],
					"redirect": [],
					"target_group_arn": null,
					"type": "forward",
				}],
				"port": 80,
				"protocol": "HTTP",
				"ssl_policy": "ELBSecurityPolicy-2016",
				"timeouts": null,
			},
		},
		{
			"address": "aws_lb_listener.valid_listener",
			"mode": "managed",
			"type": "aws_lb_listener",
			"name": "valid_listener",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"certificate_arn": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4",
				"default_action": [{
					"authenticate_cognito": [],
					"authenticate_oidc": [],
					"fixed_response": [],
					"forward": [],
					"redirect": [],
					"target_group_arn": null,
					"type": "forward",
				}],
				"port": 443,
				"protocol": "HTTPS",
				"ssl_policy": "ELBSecurityPolicy-2016-08",
				"timeouts": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_lb.invalidtest",
			"mode": "managed",
			"type": "aws_lb",
			"name": "invalidtest",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access_logs": [],
					"drop_invalid_header_fields": false,
					"enable_cross_zone_load_balancing": null,
					"enable_deletion_protection": true,
					"enable_http2": true,
					"idle_timeout": 60,
					"internal": false,
					"load_balancer_type": "application",
					"name": "test-lb-tf",
					"name_prefix": null,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"access_logs": [],
					"arn": true,
					"arn_suffix": true,
					"dns_name": true,
					"id": true,
					"ip_address_type": true,
					"security_groups": true,
					"subnet_mapping": true,
					"subnets": true,
					"vpc_id": true,
					"zone_id": true,
				},
			},
		},
		{
			"address": "aws_lb.nlb_valid",
			"mode": "managed",
			"type": "aws_lb",
			"name": "nlb_valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access_logs": [],
					"drop_invalid_header_fields": null,
					"enable_cross_zone_load_balancing": false,
					"enable_deletion_protection": true,
					"enable_http2": null,
					"idle_timeout": null,
					"internal": false,
					"load_balancer_type": "network",
					"name": "test-lb-tf",
					"name_prefix": null,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"access_logs": [],
					"arn": true,
					"arn_suffix": true,
					"dns_name": true,
					"id": true,
					"ip_address_type": true,
					"security_groups": true,
					"subnet_mapping": true,
					"subnets": true,
					"vpc_id": true,
					"zone_id": true,
				},
			},
		},
		{
			"address": "aws_lb.validtest",
			"mode": "managed",
			"type": "aws_lb",
			"name": "validtest",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"access_logs": [],
					"drop_invalid_header_fields": false,
					"enable_cross_zone_load_balancing": null,
					"enable_deletion_protection": true,
					"enable_http2": true,
					"idle_timeout": 60,
					"internal": false,
					"load_balancer_type": "application",
					"name": "test-lb-tf",
					"name_prefix": null,
					"tags": null,
					"timeouts": null,
				},
				"after_unknown": {
					"access_logs": [],
					"arn": true,
					"arn_suffix": true,
					"dns_name": true,
					"id": true,
					"ip_address_type": true,
					"security_groups": true,
					"subnet_mapping": true,
					"subnets": true,
					"vpc_id": true,
					"zone_id": true,
				},
			},
		},
		{
			"address": "aws_lb_listener.invalid_listener",
			"mode": "managed",
			"type": "aws_lb_listener",
			"name": "invalid_listener",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"certificate_arn": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4",
					"default_action": [{
						"authenticate_cognito": [],
						"authenticate_oidc": [],
						"fixed_response": [],
						"forward": [],
						"redirect": [],
						"target_group_arn": null,
						"type": "forward",
					}],
					"port": 80,
					"protocol": "HTTP",
					"ssl_policy": "ELBSecurityPolicy-2016",
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"default_action": [{
						"authenticate_cognito": [],
						"authenticate_oidc": [],
						"fixed_response": [],
						"forward": [],
						"order": true,
						"redirect": [],
					}],
					"id": true,
					"load_balancer_arn": true,
				},
			},
		},
		{
			"address": "aws_lb_listener.nlb_listener",
			"mode": "managed",
			"type": "aws_lb_listener",
			"name": "nlb_listener",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"certificate_arn": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4",
					"default_action": [{
						"authenticate_cognito": [],
						"authenticate_oidc": [],
						"fixed_response": [],
						"forward": [],
						"redirect": [],
						"target_group_arn": null,
						"type": "forward",
					}],
					"port": 80,
					"protocol": "HTTP",
					"ssl_policy": "ELBSecurityPolicy-2016",
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"default_action": [{
						"authenticate_cognito": [],
						"authenticate_oidc": [],
						"fixed_response": [],
						"forward": [],
						"order": true,
						"redirect": [],
					}],
					"id": true,
					"load_balancer_arn": true,
				},
			},
		},
		{
			"address": "aws_lb_listener.valid_listener",
			"mode": "managed",
			"type": "aws_lb_listener",
			"name": "valid_listener",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"certificate_arn": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4",
					"default_action": [{
						"authenticate_cognito": [],
						"authenticate_oidc": [],
						"fixed_response": [],
						"forward": [],
						"redirect": [],
						"target_group_arn": null,
						"type": "forward",
					}],
					"port": 443,
					"protocol": "HTTPS",
					"ssl_policy": "ELBSecurityPolicy-2016-08",
					"timeouts": null,
				},
				"after_unknown": {
					"arn": true,
					"default_action": [{
						"authenticate_cognito": [],
						"authenticate_oidc": [],
						"fixed_response": [],
						"forward": [],
						"order": true,
						"redirect": [],
					}],
					"id": true,
					"load_balancer_arn": true,
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
				"address": "aws_lb.invalidtest",
				"mode": "managed",
				"type": "aws_lb",
				"name": "invalidtest",
				"provider_config_key": "aws",
				"expressions": {
					"enable_deletion_protection": {"constant_value": true},
					"internal": {"constant_value": false},
					"load_balancer_type": {"constant_value": "application"},
					"name": {"constant_value": "test-lb-tf"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_lb.nlb_valid",
				"mode": "managed",
				"type": "aws_lb",
				"name": "nlb_valid",
				"provider_config_key": "aws",
				"expressions": {
					"enable_deletion_protection": {"constant_value": true},
					"internal": {"constant_value": false},
					"load_balancer_type": {"constant_value": "network"},
					"name": {"constant_value": "test-lb-tf"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_lb.validtest",
				"mode": "managed",
				"type": "aws_lb",
				"name": "validtest",
				"provider_config_key": "aws",
				"expressions": {
					"enable_deletion_protection": {"constant_value": true},
					"internal": {"constant_value": false},
					"load_balancer_type": {"constant_value": "application"},
					"name": {"constant_value": "test-lb-tf"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_lb_listener.invalid_listener",
				"mode": "managed",
				"type": "aws_lb_listener",
				"name": "invalid_listener",
				"provider_config_key": "aws",
				"expressions": {
					"certificate_arn": {"constant_value": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"},
					"default_action": [{"type": {"constant_value": "forward"}}],
					"load_balancer_arn": {"references": ["aws_lb.invalidtest"]},
					"port": {"constant_value": "80"},
					"protocol": {"constant_value": "HTTP"},
					"ssl_policy": {"constant_value": "ELBSecurityPolicy-2016"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_lb_listener.nlb_listener",
				"mode": "managed",
				"type": "aws_lb_listener",
				"name": "nlb_listener",
				"provider_config_key": "aws",
				"expressions": {
					"certificate_arn": {"constant_value": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"},
					"default_action": [{"type": {"constant_value": "forward"}}],
					"load_balancer_arn": {"references": ["aws_lb.nlb_valid"]},
					"port": {"constant_value": "80"},
					"protocol": {"constant_value": "HTTP"},
					"ssl_policy": {"constant_value": "ELBSecurityPolicy-2016"},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_lb_listener.valid_listener",
				"mode": "managed",
				"type": "aws_lb_listener",
				"name": "valid_listener",
				"provider_config_key": "aws",
				"expressions": {
					"certificate_arn": {"constant_value": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"},
					"default_action": [{"type": {"constant_value": "forward"}}],
					"load_balancer_arn": {"references": ["aws_lb.validtest"]},
					"port": {"constant_value": "443"},
					"protocol": {"constant_value": "HTTPS"},
					"ssl_policy": {"constant_value": "ELBSecurityPolicy-2016-08"},
				},
				"schema_version": 0,
			},
		]},
	},
}