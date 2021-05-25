# ALB Access Logging: Deny Application Load Balancers (ALBs) that are built without access logging enabled
package rules.alb_access_logging

import data.fugue

resource_type = "MULTIPLE"

# Grab every aws load balancer in template
application_load_balancer = fugue.resources("aws_lb")

# Application load balancer is disabled if no access logging configurations
is_invalid_load_balancer(resource) {
	resource.access_logs == []
	resource.load_balancer_type == "application"
}

# Deny resource if ALB does not have access logging enabled
policy[p] {
	resource = application_load_balancer[_]
	is_invalid_load_balancer(resource)
	p = fugue.deny_resource_with_message(resource, "All application load balancers must have access logs enabled.")
}

# Allow resource if ALB has access logging enabled
policy[p] {
	resource = application_load_balancer[_]
	not is_invalid_load_balancer(resource)
	p = fugue.allow_resource(resource)
}
