# Sagemaker notebook encryption ensures notebooks are encrypted at rest
package rules.sagemaker_notebook_encryption

import data.fugue

resource_type = "MULTIPLE"

# Find all sagemaker notebooks
aws_sagemaker_notebook = fugue.resources("aws_sagemaker_notebook_instance")

#Notebook is encrypted is kms key id is defined
is_encrypted(resource) {
	resource.kms_key_id != null
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = aws_sagemaker_notebook[_]
	is_encrypted(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = aws_sagemaker_notebook[_]
	not is_encrypted(resource)
	p = fugue.deny_resource_with_message(resource, "Sagemaker notebooks must be encrypted with a kms_key.")
}
