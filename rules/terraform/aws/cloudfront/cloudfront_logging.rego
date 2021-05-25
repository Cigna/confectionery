package rules.cloudfront_logging

import data.fugue

resource_type = "MULTIPLE"

# Grab every aws cloudfront in template
cloudfront_distribution = fugue.resources("aws_cloudfront_distribution")

# Cloudfront is disabled if no logging configurations
is_invalid_cloudfront(resource) {
	resource.logging_config == []
}

# Deny resource if cloudfront does not have logging enabled
policy[p] {
	resource = cloudfront_distribution[_]
	is_invalid_cloudfront(resource)
	p = fugue.deny_resource_with_message(resource, "All cloudfront distributions must have logs enabled.")
}

# Allow resource if cloudfront has logging enabled
policy[p] {
	resource = cloudfront_distribution[_]
	not is_invalid_cloudfront(resource)
	p = fugue.allow_resource(resource)
}
