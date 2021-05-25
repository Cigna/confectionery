package rules.redshift_tls

import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# Grab redshift parameter groups in terraform template
aws_redshift_parameter_group = fugue.resources("aws_redshift_parameter_group")

# Auxiliary function
is_valid_redshift(resource) {
	parameter = resource.parameter[_]
	parameter.name == "require_ssl"
	parameter.value == "true"
}

# Regula expects advanced rules to contain a `policy` rule that holds a set of _judgements_.
policy[p] {
	resource = aws_redshift_parameter_group[_]
	not is_valid_redshift(resource)
	p = fugue.deny_resource_with_message(resource, "All redshift clusters must have data encryption in-transit over ssl connections.")
}

policy[p] {
	resource = aws_redshift_parameter_group[_]
	is_valid_redshift(resource)
	p = fugue.allow_resource(resource)
}
