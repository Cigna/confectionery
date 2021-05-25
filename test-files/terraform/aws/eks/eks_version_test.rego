# Rego test for EKS Public Endpoint 
# Validating rule eks_version: Deny eks clusters with a version less than 1.15

package rules.eks_version_enforcement

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_eks_version_enforcement {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_eks_cluster.valid"] == true
	resources["aws_eks_cluster.invalid"] == false
}

# Mock input is generated plan for eks_version.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_eks_cluster.invalid",
			"mode": "managed",
			"type": "aws_eks_cluster",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"enabled_cluster_log_types": null,
				"encryption_config": [],
				"name": "example",
				"role_arn": "arn:aws:iam::123456789012:user/*",
				"tags": null,
				"timeouts": null,
				"version": "1.14",
				"vpc_config": [{
					"endpoint_private_access": false,
					"endpoint_public_access": true,
					"security_group_ids": null,
					"subnet_ids": [
						"subnet-abcde012",
						"subnet-bcde012a",
						"subnet-fghi345a",
					],
				}],
			},
		},
		{
			"address": "aws_eks_cluster.valid",
			"mode": "managed",
			"type": "aws_eks_cluster",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"enabled_cluster_log_types": null,
				"encryption_config": [],
				"name": "example",
				"role_arn": "arn:aws:iam::123456789012:user/*",
				"tags": null,
				"timeouts": null,
				"version": "1.15",
				"vpc_config": [{
					"endpoint_private_access": false,
					"endpoint_public_access": true,
					"security_group_ids": null,
					"subnet_ids": [
						"subnet-abcde012",
						"subnet-bcde012a",
						"subnet-fghi345a",
					],
				}],
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_eks_cluster.invalid",
			"mode": "managed",
			"type": "aws_eks_cluster",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"enabled_cluster_log_types": null,
					"encryption_config": [],
					"name": "example",
					"role_arn": "arn:aws:iam::123456789012:user/*",
					"tags": null,
					"timeouts": null,
					"version": "1.14",
					"vpc_config": [{
						"endpoint_private_access": false,
						"endpoint_public_access": true,
						"security_group_ids": null,
						"subnet_ids": [
							"subnet-abcde012",
							"subnet-bcde012a",
							"subnet-fghi345a",
						],
					}],
				},
				"after_unknown": {
					"arn": true,
					"certificate_authority": true,
					"created_at": true,
					"encryption_config": [],
					"endpoint": true,
					"id": true,
					"identity": true,
					"platform_version": true,
					"status": true,
					"vpc_config": [{
						"cluster_security_group_id": true,
						"public_access_cidrs": true,
						"subnet_ids": [
							false,
							false,
							false,
						],
						"vpc_id": true,
					}],
				},
			},
		},
		{
			"address": "aws_eks_cluster.valid",
			"mode": "managed",
			"type": "aws_eks_cluster",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"enabled_cluster_log_types": null,
					"encryption_config": [],
					"name": "example",
					"role_arn": "arn:aws:iam::123456789012:user/*",
					"tags": null,
					"timeouts": null,
					"version": "1.15",
					"vpc_config": [{
						"endpoint_private_access": false,
						"endpoint_public_access": true,
						"security_group_ids": null,
						"subnet_ids": [
							"subnet-abcde012",
							"subnet-bcde012a",
							"subnet-fghi345a",
						],
					}],
				},
				"after_unknown": {
					"arn": true,
					"certificate_authority": true,
					"created_at": true,
					"encryption_config": [],
					"endpoint": true,
					"id": true,
					"identity": true,
					"platform_version": true,
					"status": true,
					"vpc_config": [{
						"cluster_security_group_id": true,
						"public_access_cidrs": true,
						"subnet_ids": [
							false,
							false,
							false,
						],
						"vpc_id": true,
					}],
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
				"address": "aws_eks_cluster.invalid",
				"mode": "managed",
				"type": "aws_eks_cluster",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "example"},
					"role_arn": {"constant_value": "arn:aws:iam::123456789012:user/*"},
					"version": {"constant_value": "1.14"},
					"vpc_config": [{"subnet_ids": {"constant_value": [
						"subnet-abcde012",
						"subnet-bcde012a",
						"subnet-fghi345a",
					]}}],
				},
				"schema_version": 0,
			},
			{
				"address": "aws_eks_cluster.valid",
				"mode": "managed",
				"type": "aws_eks_cluster",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "example"},
					"role_arn": {"constant_value": "arn:aws:iam::123456789012:user/*"},
					"version": {"constant_value": "1.15"},
					"vpc_config": [{"subnet_ids": {"constant_value": [
						"subnet-abcde012",
						"subnet-bcde012a",
						"subnet-fghi345a",
					]}}],
				},
				"schema_version": 0,
			},
		]},
	},
}
