# Redshift audit logging file validation: Deny if redshift logging is not enabled
package rules.redshift_logging

import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# Grab redshift clusters in terraform template
redshift_cluster = fugue.resources("aws_redshift_cluster")

# Auxiliary function
# Redshift cluster is invalid if logging is not configured
is_invalid_redshift(resource) {
	resource.logging == []
}

# Regula expects advanced rules to contain a `policy` rule that holds a set of _judgements_.
# Deny resource if redshift cluster does not have logging enabled
policy[p] {
	resource = redshift_cluster[_]
	is_invalid_redshift(resource)
	p = fugue.deny_resource_with_message(resource, "All redshift clusters must have logs enabled.")
}

# Allow resource if redshift cluster has logging enabled
policy[p] {
	resource = redshift_cluster[_]
	not is_invalid_redshift(resource)
	p = fugue.allow_resource(resource)
}
