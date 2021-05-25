package rules.sagemaker_notebook_internet_access

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
aws_sagemaker_notebook_instance = fugue.resources("aws_sagemaker_notebook_instance")

# Auxiliary function.
is_internet_access(resource) {
	resource.direct_internet_access == "Enabled"
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = aws_sagemaker_notebook_instance[_]
	not is_internet_access(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = aws_sagemaker_notebook_instance[_]
	is_internet_access(resource)
	p = fugue.deny_resource_with_message(resource, "All Sagemaker notebook instances must disable direct internet access.")
}
