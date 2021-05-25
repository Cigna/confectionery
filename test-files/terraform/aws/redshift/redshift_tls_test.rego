# Rego test for Redshift TLS
# Validating rule redshift_tls: Deny Redshift parameter groups that do not ensure tls connections.
package rules.redshift_tls

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_redshift_tls {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_redshift_parameter_group.valid"] == true
	resources["aws_redshift_parameter_group.invalid-missing"] == false
	resources["aws_redshift_parameter_group.invalid-false"] == false
}

# Mock input is generated plan for redshift_tls.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_redshift_parameter_group.invalid-false",
			"mode": "managed",
			"type": "aws_redshift_parameter_group",
			"name": "invalid-false",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "Managed by Terraform",
				"family": "redshift-1.0",
				"name": "parameter-group-test-terraform",
				"parameter": [
					{
						"name": "enable_user_activity_logging",
						"value": "true",
					},
					{
						"name": "query_group",
						"value": "example",
					},
				],
				"tags": null,
			},
		},
		{
			"address": "aws_redshift_parameter_group.invalid-missing",
			"mode": "managed",
			"type": "aws_redshift_parameter_group",
			"name": "invalid-missing",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "Managed by Terraform",
				"family": "redshift-1.0",
				"name": "parameter-group-test-terraform",
				"parameter": [
					{
						"name": "enable_user_activity_logging",
						"value": "true",
					},
					{
						"name": "query_group",
						"value": "example",
					},
				],
				"tags": null,
			},
		},
		{
			"address": "aws_redshift_parameter_group.valid",
			"mode": "managed",
			"type": "aws_redshift_parameter_group",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"description": "Managed by Terraform",
				"family": "redshift-1.0",
				"name": "parameter-group-test-terraform",
				"parameter": [
					{
						"name": "enable_user_activity_logging",
						"value": "true",
					},
					{
						"name": "query_group",
						"value": "example",
					},
					{
						"name": "require_ssl",
						"value": "true",
					},
				],
				"tags": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_redshift_parameter_group.invalid-false",
			"mode": "managed",
			"type": "aws_redshift_parameter_group",
			"name": "invalid-false",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Managed by Terraform",
					"family": "redshift-1.0",
					"name": "parameter-group-test-terraform",
					"parameter": [
						{
							"name": "enable_user_activity_logging",
							"value": "true",
						},
						{
							"name": "query_group",
							"value": "example",
						},
					],
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"parameter": [
						{},
						{},
					],
				},
			},
		},
		{
			"address": "aws_redshift_parameter_group.invalid-missing",
			"mode": "managed",
			"type": "aws_redshift_parameter_group",
			"name": "invalid-missing",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Managed by Terraform",
					"family": "redshift-1.0",
					"name": "parameter-group-test-terraform",
					"parameter": [
						{
							"name": "enable_user_activity_logging",
							"value": "true",
						},
						{
							"name": "query_group",
							"value": "example",
						},
					],
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"parameter": [
						{},
						{},
					],
				},
			},
		},
		{
			"address": "aws_redshift_parameter_group.valid",
			"mode": "managed",
			"type": "aws_redshift_parameter_group",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"description": "Managed by Terraform",
					"family": "redshift-1.0",
					"name": "parameter-group-test-terraform",
					"parameter": [
						{
							"name": "enable_user_activity_logging",
							"value": "true",
						},
						{
							"name": "query_group",
							"value": "example",
						},
						{
							"name": "require_ssl",
							"value": "true",
						},
					],
					"tags": null,
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"parameter": [
						{},
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
				"address": "aws_redshift_parameter_group.invalid-false",
				"mode": "managed",
				"type": "aws_redshift_parameter_group",
				"name": "invalid-false",
				"provider_config_key": "aws",
				"expressions": {
					"family": {"constant_value": "redshift-1.0"},
					"name": {"constant_value": "parameter-group-test-terraform"},
					"parameter": [
						{
							"name": {"constant_value": "query_group"},
							"value": {"constant_value": "example"},
						},
						{
							"name": {"constant_value": "enable_user_activity_logging"},
							"value": {"constant_value": "true"},
						},
					],
				},
				"schema_version": 0,
			},
			{
				"address": "aws_redshift_parameter_group.invalid-missing",
				"mode": "managed",
				"type": "aws_redshift_parameter_group",
				"name": "invalid-missing",
				"provider_config_key": "aws",
				"expressions": {
					"family": {"constant_value": "redshift-1.0"},
					"name": {"constant_value": "parameter-group-test-terraform"},
					"parameter": [
						{
							"name": {"constant_value": "query_group"},
							"value": {"constant_value": "example"},
						},
						{
							"name": {"constant_value": "enable_user_activity_logging"},
							"value": {"constant_value": "true"},
						},
					],
				},
				"schema_version": 0,
			},
			{
				"address": "aws_redshift_parameter_group.valid",
				"mode": "managed",
				"type": "aws_redshift_parameter_group",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"family": {"constant_value": "redshift-1.0"},
					"name": {"constant_value": "parameter-group-test-terraform"},
					"parameter": [
						{
							"name": {"constant_value": "require_ssl"},
							"value": {"constant_value": "true"},
						},
						{
							"name": {"constant_value": "query_group"},
							"value": {"constant_value": "example"},
						},
						{
							"name": {"constant_value": "enable_user_activity_logging"},
							"value": {"constant_value": "true"},
						},
					],
				},
				"schema_version": 0,
			},
		]},
	},
}
