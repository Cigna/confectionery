# Sagemaker endpoint encryption ensures encyption at rest for endpoints
package rules.sagemaker_endpoint_encryption

import data.fugue

resource_type = "MULTIPLE"

# Find all sagemaker endpoints
aws_sagemaker_endpoint = fugue.resources("aws_sagemaker_endpoint_configuration")

# an endpoint is encrypted if it uses a kms key
is_encrypted(resource) {
	resource.kms_key_arn != null
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = aws_sagemaker_endpoint[_]
	is_encrypted(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = aws_sagemaker_endpoint[_]
	not is_encrypted(resource)
	p = fugue.deny_resource_with_message(resource, "Sagemaker endpoints must be encrypted and kms_key_arn cannot be null.")
}
