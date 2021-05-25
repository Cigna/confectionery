# Rego test for IAM User Creation
# Validating rule iam_user_creation: Deny all IAM Users.
package rules.iam_user_creation

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_iam_user_creation {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_iam_user.invalid"] == false
}

# Mock input is generated plan for iam_user_creation.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_iam_user.invalid",
		"mode": "managed",
		"type": "aws_iam_user",
		"name": "invalid",
		"provider_name": "aws",
		"schema_version": 0,
		"values": {
			"force_destroy": false,
			"name": "loadbalancer",
			"path": "/system/",
			"permissions_boundary": null,
			"tags": {"tag-key": "tag-value"},
		},
	}]}},
	"resource_changes": [{
		"address": "aws_iam_user.invalid",
		"mode": "managed",
		"type": "aws_iam_user",
		"name": "invalid",
		"provider_name": "aws",
		"change": {
			"actions": ["create"],
			"before": null,
			"after": {
				"force_destroy": false,
				"name": "loadbalancer",
				"path": "/system/",
				"permissions_boundary": null,
				"tags": {"tag-key": "tag-value"},
			},
			"after_unknown": {
				"arn": true,
				"id": true,
				"tags": {},
				"unique_id": true,
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
			"address": "aws_iam_user.invalid",
			"mode": "managed",
			"type": "aws_iam_user",
			"name": "invalid",
			"provider_config_key": "aws",
			"expressions": {
				"name": {"constant_value": "loadbalancer"},
				"path": {"constant_value": "/system/"},
				"tags": {"constant_value": {"tag-key": "tag-value"}},
			},
			"schema_version": 0,
		}]},
	},
}
