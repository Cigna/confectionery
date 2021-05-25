## Testing

## Terraform Plan Mock input(_test.rego file)
Within the /test-files/terraform directory you will find both a passing and failing resource for your rule in a _test.rego file. The filename should match the rule that it is testing.

A few examples snippets from Terraform plans:

Here we have an invalid KMS key that violates our enable key rotation policy, as you can see key rotation is false.
``` 
{
			"address": "aws_kms_key.invalid",
			"mode": "managed",
			"type": "aws_kms_key",
			"name": "invalid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"deletion_window_in_days": null,
				"description": "KMS key 2",
				"enable_key_rotation": false,
				"is_enabled": true,
				"tags": null,
			},
		},
```
Now this would be a passing resource labeled valid because key rotation is true.

```
{
			"address": "aws_kms_key.valid",
			"mode": "managed",
			"type": "aws_kms_key",
			"name": "valid",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"deletion_window_in_days": null,
				"description": "KMS key 1",
				"enable_key_rotation": true,
				"is_enabled": true,
				"tags": null,
			},
		},
```

## Rego file
The rego file should open with a structure similar to the one below

```
package rules.sqs_server_side_encryption

import data.fugue.resource_view.resource_view_input

mock_input = ret {
	ret = resource_view_input with input as mock_plan_input
}

test_sqs_server_side_encryption {
	pol := policy with input as mock_input
	resources := {p.id: p.valid | pol[p]}

	resources["aws_sqs_queue.valid"] == true
	resources["aws_sqs_queue.invalid"] == false
}
```

Note that the package name calls out what rule is being tested. The Regula library is also imported to allow for the test to generate the view. You should also rename the function to make clear what it is testing.

Using the above rego test:
* The first line points to a mock input variable which will be defined below. 
* The second line references the resources validated against the rule being tested. Therefore the package name from your rule being tested must match this value. This test is testing the ``rules.sqs_server_side_encryption`` package.
* The third line or validity check is referencing one of the terraform resources by address (combination of resource type/logical name).

mock_input should then be set to the terraform plan json from the source terraform file. The terraform file should follow the same naming convention as your rego file to help with matching.

```
mock_input = {
    "configuration": {
        "provider_config": {
            "aws": {
                "expressions": {
                    "profile": {
                        "constant_value": "saml"
                    },
                    "region": {
                        "constant_value": "us-east-1"
                    },
                    "shared_credentials_file": {
                        "constant_value": "~/.aws/creds"
                    }
                },
                "name": "aws"
            }
        },
        "root_module": {
            "resources": [
                {
                    "address": "aws_sqs_queue.test",
                    "expressions": {
                        "delay_seconds": {
                            "constant_value": 90
                        },
                        "max_message_size": {
                            "constant_value": 2048
                        },
                        "message_retention_seconds": {
                            "constant_value": 86400
                        },
                        "name": {
                            "constant_value": "terraform-example-queue"
                        },
                        "receive_wait_time_seconds": {
                            "constant_value": 10
                        },
                        "redrive_policy": {},
                        "tags": {
                            "constant_value": {
                                "Environment": "production"
                            }
                        }
                    },
```

This snippet shows the address mentioned above. By defining the mock_input we provide all the necessary information for the test to work.

To test additional resources you can add additional resource lines in the test. The resource address from terraform should be used as the identifier.
```
resources["aws_sqs_queue.valid"] == true
```

To run all tests you can run the following command from the root of the Conftest directory. Alternatively, subdirectories can be used to limit which tests are being run.

```
opa test rules/terraform test-files
```

Our CI also runs this command on each commit.
