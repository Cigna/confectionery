package rules.api_gw_custom_domain

import data.fugue

resource_type = "MULTIPLE"

rest_api = fugue.resources("aws_api_gateway_rest_api")

mapping = fugue.resources("aws_api_gateway_base_path_mapping")

# Auxiliary function checking if a mapping exists
is_valid(resource) {
	resource.id == mapping[_].api_id
}

# Second is_valid accounts for when the address is lost to an arn or other id
is_valid(resource) {
	resource._id == mapping[_].api_id
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

policy[p] {
	resource = rest_api[_]
	is_valid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = rest_api[_]
	not is_valid(resource)
	p = fugue.deny_resource_with_message(resource, "API Gateway Should be configured with a custom domain name for operational resilency and to allow for enabling of proper tls versions.")
}
