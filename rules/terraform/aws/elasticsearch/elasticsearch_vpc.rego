package rules.elasticsearch_VPC

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.

# Find all elasticsearch resources in template 
elastic_search_domain = fugue.resources("aws_elasticsearch_domain")

# Auxiliary function
# Is valid if vpc_options present 
is_invalid(resource) {
	resource.vpc_options == []
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
# Allow resource if elasticsearch with VPC
policy[p] {
	resource = elastic_search_domain[_]
	not is_invalid(resource)
	p = fugue.allow_resource(resource)
}

# Deny resource if elasticsearch not with VPC
policy[p] {
	resource = elastic_search_domain[_]
	is_invalid(resource)
	p = fugue.deny_resource_with_message(resource, "All elasticsearch resources must be deployed to a VPC.")
}
