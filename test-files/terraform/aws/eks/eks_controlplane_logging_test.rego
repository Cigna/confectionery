# Rego test for EKS Control Plane Logging 
# Validating rule eks_controlplane_logging: Deny eks clusters that do not have eks control plane logging enabled
package rules.eks_controlplane_logging

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_eks_controlplane_logging {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_eks_cluster.invalid_eks_cluster"] == false
	resources["aws_eks_cluster.valid_eks_cluster"] == true
}

# Mock input is generated plan for eks_controlplane_logging.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.13.2",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_eks_cluster.invalid_eks_cluster",
			"mode": "managed",
			"type": "aws_eks_cluster",
			"name": "invalid_eks_cluster",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {
				"enabled_cluster_log_types": null,
				"encryption_config": [],
				"name": "invalid_eks_cluster",
				"role_arn": "arn:aws:iam::123456789000:user/*",
				"tags": null,
				"timeouts": null,
				"vpc_config": [{
					"endpoint_private_access": false,
					"endpoint_public_access": true,
					"security_group_ids": null,
					"subnet_ids": [
						"subnet-abcde123",
						"subnet-bcdef456",
						"subnet-fghi320b",
					],
				}],
			},
		},
		{
			"address": "aws_eks_cluster.valid_eks_cluster",
			"mode": "managed",
			"type": "aws_eks_cluster",
			"name": "valid_eks_cluster",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"schema_version": 0,
			"values": {
				"enabled_cluster_log_types": [
					"api",
					"audit",
					"authenticator",
					"controllerManager",
					"scheduler",
				],
				"encryption_config": [],
				"name": "valid_eks_cluster",
				"role_arn": "arn:aws:iam::123456789000:user/*",
				"tags": null,
				"timeouts": null,
				"vpc_config": [{
					"endpoint_private_access": false,
					"endpoint_public_access": true,
					"security_group_ids": null,
					"subnet_ids": [
						"subnet-abcde123",
						"subnet-bcdef456",
						"subnet-fghi320b",
					],
				}],
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_eks_cluster.invalid_eks_cluster",
			"mode": "managed",
			"type": "aws_eks_cluster",
			"name": "invalid_eks_cluster",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"enabled_cluster_log_types": null,
					"encryption_config": [],
					"name": "invalid_eks_cluster",
					"role_arn": "arn:aws:iam::123456789000:user/*",
					"tags": null,
					"timeouts": null,
					"vpc_config": [{
						"endpoint_private_access": false,
						"endpoint_public_access": true,
						"security_group_ids": null,
						"subnet_ids": [
							"subnet-abcde123",
							"subnet-bcdef456",
							"subnet-fghi320b",
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
					"version": true,
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
			"address": "aws_eks_cluster.valid_eks_cluster",
			"mode": "managed",
			"type": "aws_eks_cluster",
			"name": "valid_eks_cluster",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"enabled_cluster_log_types": [
						"api",
						"audit",
						"authenticator",
						"controllerManager",
						"scheduler",
					],
					"encryption_config": [],
					"name": "valid_eks_cluster",
					"role_arn": "arn:aws:iam::123456789000:user/*",
					"tags": null,
					"timeouts": null,
					"vpc_config": [{
						"endpoint_private_access": false,
						"endpoint_public_access": true,
						"security_group_ids": null,
						"subnet_ids": [
							"subnet-abcde123",
							"subnet-bcdef456",
							"subnet-fghi320b",
						],
					}],
				},
				"after_unknown": {
					"arn": true,
					"certificate_authority": true,
					"created_at": true,
					"enabled_cluster_log_types": [
						false,
						false,
						false,
						false,
						false,
					],
					"encryption_config": [],
					"endpoint": true,
					"id": true,
					"identity": true,
					"platform_version": true,
					"status": true,
					"version": true,
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
				"address": "aws_eks_cluster.invalid_eks_cluster",
				"mode": "managed",
				"type": "aws_eks_cluster",
				"name": "invalid_eks_cluster",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "invalid_eks_cluster"},
					"role_arn": {"constant_value": "arn:aws:iam::123456789000:user/*"},
					"vpc_config": [{"subnet_ids": {"constant_value": [
						"subnet-abcde123",
						"subnet-bcdef456",
						"subnet-fghi320b",
					]}}],
				},
				"schema_version": 0,
			},
			{
				"address": "aws_eks_cluster.valid_eks_cluster",
				"mode": "managed",
				"type": "aws_eks_cluster",
				"name": "valid_eks_cluster",
				"provider_config_key": "aws",
				"expressions": {
					"enabled_cluster_log_types": {"constant_value": [
						"api",
						"controllerManager",
						"scheduler",
						"audit",
						"authenticator",
					]},
					"name": {"constant_value": "valid_eks_cluster"},
					"role_arn": {"constant_value": "arn:aws:iam::123456789000:user/*"},
					"vpc_config": [{"subnet_ids": {"constant_value": [
						"subnet-abcde123",
						"subnet-bcdef456",
						"subnet-fghi320b",
					]}}],
				},
				"schema_version": 0,
			},
		]},
	},
}
