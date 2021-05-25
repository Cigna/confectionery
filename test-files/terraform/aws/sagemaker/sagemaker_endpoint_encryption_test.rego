# Rego test for sagemaker endpoint encryption enforcement rule
package rules.sagemaker_endpoint_encryption

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_sagemaker_endpoint_encryption_enforcement {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_sagemaker_endpoint_configuration.valid"] == true
	resources["aws_sagemaker_endpoint_configuration.invalid"] == false
}

# mock input generated from sagemaker_endpoint_encryption_enforcement.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_sagemaker_endpoint_configuration.invalid",
			"mode": "managed",
			"type": "aws_sagemaker_endpoint_configuration",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"kms_key_arn": null,
				"name": "my-endpoint-config",
				"production_variants": [{
					"accelerator_type": null,
					"initial_instance_count": 1,
					"initial_variant_weight": 1,
					"instance_type": "ml.t2.medium",
					"model_name": "name",
					"variant_name": "variant-1",
				}],
				"tags": {"Name": "foo"},
			},
		},
		{
			"address": "aws_sagemaker_endpoint_configuration.valid",
			"mode": "managed",
			"type": "aws_sagemaker_endpoint_configuration",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"kms_key_arn": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4",
				"name": "my-endpoint-config",
				"production_variants": [{
					"accelerator_type": null,
					"initial_instance_count": 1,
					"initial_variant_weight": 1,
					"instance_type": "ml.t2.medium",
					"model_name": "name",
					"variant_name": "variant-1",
				}],
				"tags": {"Name": "foo"},
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_sagemaker_endpoint_configuration.invalid",
			"mode": "managed",
			"type": "aws_sagemaker_endpoint_configuration",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"kms_key_arn": null,
					"name": "my-endpoint-config",
					"production_variants": [{
						"accelerator_type": null,
						"initial_instance_count": 1,
						"initial_variant_weight": 1,
						"instance_type": "ml.t2.medium",
						"model_name": "name",
						"variant_name": "variant-1",
					}],
					"tags": {"Name": "foo"},
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"production_variants": [{}],
					"tags": {},
				},
			},
		},
		{
			"address": "aws_sagemaker_endpoint_configuration.valid",
			"mode": "managed",
			"type": "aws_sagemaker_endpoint_configuration",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"kms_key_arn": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4",
					"name": "my-endpoint-config",
					"production_variants": [{
						"accelerator_type": null,
						"initial_instance_count": 1,
						"initial_variant_weight": 1,
						"instance_type": "ml.t2.medium",
						"model_name": "name",
						"variant_name": "variant-1",
					}],
					"tags": {"Name": "foo"},
				},
				"after_unknown": {
					"arn": true,
					"id": true,
					"production_variants": [{}],
					"tags": {},
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
				"address": "aws_sagemaker_endpoint_configuration.invalid",
				"mode": "managed",
				"type": "aws_sagemaker_endpoint_configuration",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "my-endpoint-config"},
					"production_variants": [{
						"initial_instance_count": {"constant_value": 1},
						"instance_type": {"constant_value": "ml.t2.medium"},
						"model_name": {"constant_value": "name"},
						"variant_name": {"constant_value": "variant-1"},
					}],
					"tags": {"constant_value": {"Name": "foo"}},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_sagemaker_endpoint_configuration.valid",
				"mode": "managed",
				"type": "aws_sagemaker_endpoint_configuration",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"kms_key_arn": {"constant_value": "arn:aws:iam::187416307283:server-certificate/test_cert_rab3wuqwgja25ct3n4jdj2tzu4"},
					"name": {"constant_value": "my-endpoint-config"},
					"production_variants": [{
						"initial_instance_count": {"constant_value": 1},
						"instance_type": {"constant_value": "ml.t2.medium"},
						"model_name": {"constant_value": "name"},
						"variant_name": {"constant_value": "variant-1"},
					}],
					"tags": {"constant_value": {"Name": "foo"}},
				},
				"schema_version": 0,
			},
		]},
	},
}
