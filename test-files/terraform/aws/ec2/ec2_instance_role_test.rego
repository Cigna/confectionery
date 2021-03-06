# Rego test file for ec2 instance role rule
package rules.ec2_instance_role

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_ec2_iam_instance_profile {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_instance.valid"] == true
	resources["aws_instance.invalid"] == false
}

# mock input is generated from ec2_instance_role.tf
mock_plan_input = {
	"format_version": "0.1",
	"terraform_version": "0.12.28",
	"planned_values": {"root_module": {"resources": [
		{
			"address": "aws_iam_instance_profile.test_profile",
			"mode": "managed",
			"type": "aws_iam_instance_profile",
			"name": "test_profile",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"name": "test_profile",
				"name_prefix": null,
				"path": "/",
				"role": "test_role",
			},
		},
		{
			"address": "aws_iam_role.test_role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "test_role",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [{\n      \"Action\": [\n                \"iam:PassRole\",\n                \"iam:ListInstanceProfiles\",\n                \"ec2:*\"\n                ],\n      \"Resource\": \"*\",\n      \"Effect\": \"Allow\"\n    }\n  ]\n}\n",
				"description": null,
				"force_detach_policies": false,
				"max_session_duration": 3600,
				"name": "test_role",
				"name_prefix": null,
				"path": "/",
				"permissions_boundary": null,
				"tags": {"tag-key": "tag-value"},
			},
		},
		{
			"address": "aws_instance.invalid",
			"mode": "managed",
			"type": "aws_instance",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"ami": "ami-0758470213bdd23b1",
				"credit_specification": [],
				"disable_api_termination": null,
				"ebs_optimized": null,
				"get_password_data": false,
				"hibernation": null,
				"iam_instance_profile": null,
				"instance_initiated_shutdown_behavior": null,
				"instance_type": "t3.micro",
				"monitoring": null,
				"source_dest_check": true,
				"tags": {"Name": "HelloWorld"},
				"timeouts": null,
				"user_data": null,
				"user_data_base64": null,
			},
		},
		{
			"address": "aws_instance.valid",
			"mode": "managed",
			"type": "aws_instance",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 1,
			"values": {
				"ami": "ami-0758470213bdd23b1",
				"credit_specification": [],
				"disable_api_termination": null,
				"ebs_optimized": null,
				"get_password_data": false,
				"hibernation": null,
				"iam_instance_profile": "test_profile",
				"instance_initiated_shutdown_behavior": null,
				"instance_type": "t3.micro",
				"monitoring": null,
				"source_dest_check": true,
				"tags": {"Name": "HelloWorld"},
				"timeouts": null,
				"user_data": null,
				"user_data_base64": null,
			},
		},
	]}},
	"resource_changes": [
		{
			"address": "aws_iam_instance_profile.test_profile",
			"mode": "managed",
			"type": "aws_iam_instance_profile",
			"name": "test_profile",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"name": "test_profile",
					"name_prefix": null,
					"path": "/",
					"role": "test_role",
				},
				"after_unknown": {
					"arn": true,
					"create_date": true,
					"id": true,
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_iam_role.test_role",
			"mode": "managed",
			"type": "aws_iam_role",
			"name": "test_role",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"assume_role_policy": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [{\n      \"Action\": [\n                \"iam:PassRole\",\n                \"iam:ListInstanceProfiles\",\n                \"ec2:*\"\n                ],\n      \"Resource\": \"*\",\n      \"Effect\": \"Allow\"\n    }\n  ]\n}\n",
					"description": null,
					"force_detach_policies": false,
					"max_session_duration": 3600,
					"name": "test_role",
					"name_prefix": null,
					"path": "/",
					"permissions_boundary": null,
					"tags": {"tag-key": "tag-value"},
				},
				"after_unknown": {
					"arn": true,
					"create_date": true,
					"id": true,
					"tags": {},
					"unique_id": true,
				},
			},
		},
		{
			"address": "aws_instance.invalid",
			"mode": "managed",
			"type": "aws_instance",
			"name": "invalid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"ami": "ami-0758470213bdd23b1",
					"credit_specification": [],
					"disable_api_termination": null,
					"ebs_optimized": null,
					"get_password_data": false,
					"hibernation": null,
					"iam_instance_profile": null,
					"instance_initiated_shutdown_behavior": null,
					"instance_type": "t3.micro",
					"monitoring": null,
					"source_dest_check": true,
					"tags": {"Name": "HelloWorld"},
					"timeouts": null,
					"user_data": null,
					"user_data_base64": null,
				},
				"after_unknown": {
					"arn": true,
					"associate_public_ip_address": true,
					"availability_zone": true,
					"cpu_core_count": true,
					"cpu_threads_per_core": true,
					"credit_specification": [],
					"ebs_block_device": true,
					"ephemeral_block_device": true,
					"host_id": true,
					"id": true,
					"instance_state": true,
					"ipv6_address_count": true,
					"ipv6_addresses": true,
					"key_name": true,
					"metadata_options": true,
					"network_interface": true,
					"outpost_arn": true,
					"password_data": true,
					"placement_group": true,
					"primary_network_interface_id": true,
					"private_dns": true,
					"private_ip": true,
					"public_dns": true,
					"public_ip": true,
					"root_block_device": true,
					"secondary_private_ips": true,
					"security_groups": true,
					"subnet_id": true,
					"tags": {},
					"tenancy": true,
					"volume_tags": true,
					"vpc_security_group_ids": true,
				},
			},
		},
		{
			"address": "aws_instance.valid",
			"mode": "managed",
			"type": "aws_instance",
			"name": "valid",
			"provider_name": "aws",
			"change": {
				"actions": ["create"],
				"before": null,
				"after": {
					"ami": "ami-0758470213bdd23b1",
					"credit_specification": [],
					"disable_api_termination": null,
					"ebs_optimized": null,
					"get_password_data": false,
					"hibernation": null,
					"iam_instance_profile": "test_profile",
					"instance_initiated_shutdown_behavior": null,
					"instance_type": "t3.micro",
					"monitoring": null,
					"source_dest_check": true,
					"tags": {"Name": "HelloWorld"},
					"timeouts": null,
					"user_data": null,
					"user_data_base64": null,
				},
				"after_unknown": {
					"arn": true,
					"associate_public_ip_address": true,
					"availability_zone": true,
					"cpu_core_count": true,
					"cpu_threads_per_core": true,
					"credit_specification": [],
					"ebs_block_device": true,
					"ephemeral_block_device": true,
					"host_id": true,
					"id": true,
					"instance_state": true,
					"ipv6_address_count": true,
					"ipv6_addresses": true,
					"key_name": true,
					"metadata_options": true,
					"network_interface": true,
					"outpost_arn": true,
					"password_data": true,
					"placement_group": true,
					"primary_network_interface_id": true,
					"private_dns": true,
					"private_ip": true,
					"public_dns": true,
					"public_ip": true,
					"root_block_device": true,
					"secondary_private_ips": true,
					"security_groups": true,
					"subnet_id": true,
					"tags": {},
					"tenancy": true,
					"volume_tags": true,
					"vpc_security_group_ids": true,
				},
			},
		},
	],
	"prior_state": {
		"format_version": "0.1",
		"terraform_version": "0.12.28",
		"values": {"root_module": {"resources": [{
			"address": "data.aws_ami.ubuntu",
			"mode": "data",
			"type": "aws_ami",
			"name": "ubuntu",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"architecture": "x86_64",
				"arn": "arn:aws:ec2:us-east-1::image/ami-0758470213bdd23b1",
				"block_device_mappings": [
					{
						"device_name": "/dev/sda1",
						"ebs": {
							"delete_on_termination": "true",
							"encrypted": "false",
							"iops": "0",
							"snapshot_id": "snap-079902f15a82d5157",
							"volume_size": "8",
							"volume_type": "gp2",
						},
						"no_device": "",
						"virtual_name": "",
					},
					{
						"device_name": "/dev/sdb",
						"ebs": {},
						"no_device": "",
						"virtual_name": "ephemeral0",
					},
					{
						"device_name": "/dev/sdc",
						"ebs": {},
						"no_device": "",
						"virtual_name": "ephemeral1",
					},
				],
				"creation_date": "2020-07-30T15:39:28.000Z",
				"description": "Canonical, Ubuntu, 20.04 LTS, amd64 focal image build on 2020-07-29",
				"executable_users": null,
				"filter": [
					{
						"name": "name",
						"values": ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"],
					},
					{
						"name": "virtualization-type",
						"values": ["hvm"],
					},
				],
				"hypervisor": "xen",
				"id": "ami-0758470213bdd23b1",
				"image_id": "ami-0758470213bdd23b1",
				"image_location": "099720109477/ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20200729",
				"image_owner_alias": null,
				"image_type": "machine",
				"kernel_id": null,
				"most_recent": true,
				"name": "ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20200729",
				"name_regex": null,
				"owner_id": "099720109477",
				"owners": ["099720109477"],
				"platform": null,
				"product_codes": [],
				"public": true,
				"ramdisk_id": null,
				"root_device_name": "/dev/sda1",
				"root_device_type": "ebs",
				"root_snapshot_id": "snap-079902f15a82d5157",
				"sriov_net_support": "simple",
				"state": "available",
				"state_reason": {
					"code": "UNSET",
					"message": "UNSET",
				},
				"tags": {},
				"virtualization_type": "hvm",
			},
		}]}},
	},
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
				"address": "aws_iam_instance_profile.test_profile",
				"mode": "managed",
				"type": "aws_iam_instance_profile",
				"name": "test_profile",
				"provider_config_key": "aws",
				"expressions": {
					"name": {"constant_value": "test_profile"},
					"role": {"references": ["aws_iam_role.test_role"]},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_iam_role.test_role",
				"mode": "managed",
				"type": "aws_iam_role",
				"name": "test_role",
				"provider_config_key": "aws",
				"expressions": {
					"assume_role_policy": {"constant_value": "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [{\n      \"Action\": [\n                \"iam:PassRole\",\n                \"iam:ListInstanceProfiles\",\n                \"ec2:*\"\n                ],\n      \"Resource\": \"*\",\n      \"Effect\": \"Allow\"\n    }\n  ]\n}\n"},
					"name": {"constant_value": "test_role"},
					"tags": {"constant_value": {"tag-key": "tag-value"}},
				},
				"schema_version": 0,
			},
			{
				"address": "aws_instance.invalid",
				"mode": "managed",
				"type": "aws_instance",
				"name": "invalid",
				"provider_config_key": "aws",
				"expressions": {
					"ami": {"references": ["data.aws_ami.ubuntu"]},
					"instance_type": {"constant_value": "t3.micro"},
					"tags": {"constant_value": {"Name": "HelloWorld"}},
				},
				"schema_version": 1,
			},
			{
				"address": "aws_instance.valid",
				"mode": "managed",
				"type": "aws_instance",
				"name": "valid",
				"provider_config_key": "aws",
				"expressions": {
					"ami": {"references": ["data.aws_ami.ubuntu"]},
					"iam_instance_profile": {"references": ["aws_iam_instance_profile.test_profile"]},
					"instance_type": {"constant_value": "t3.micro"},
					"tags": {"constant_value": {"Name": "HelloWorld"}},
				},
				"schema_version": 1,
			},
			{
				"address": "data.aws_ami.ubuntu",
				"mode": "data",
				"type": "aws_ami",
				"name": "ubuntu",
				"provider_config_key": "aws",
				"expressions": {
					"filter": [
						{
							"name": {"constant_value": "name"},
							"values": {"constant_value": ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]},
						},
						{
							"name": {"constant_value": "virtualization-type"},
							"values": {"constant_value": ["hvm"]},
						},
					],
					"most_recent": {"constant_value": true},
					"owners": {"constant_value": ["099720109477"]},
				},
				"schema_version": 0,
			},
		]},
	},
}
