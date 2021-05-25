package rules.minimum_required_tags

import data.fugue

resource_type = "MULTIPLE"

taggable_resource_types = {
	"aws_cloudfront_distribution",
	"aws_cloudwatch_event_rule",
	"aws_cloudwatch_log_group",
	"aws_cloudwatch_metric_alarm",
	"aws_cognito_user_pool",
	"aws_config_config_rule",
	"aws_customer_gateway",
	"aws_eip",
	"aws_internet_gateway",
	"aws_kms_key",
	"aws_lambda_function",
	"aws_lb_target_group",
	"aws_network_acl",
	"aws_network_interface",
	"aws_redshift_parameter_group",
	"aws_redshift_subnet_group",
	"aws_route53_zone",
	"aws_route_table",
	"aws_security_group",
	"aws_sfn_state_machine",
	"aws_subnet",
	"aws_vpc",
	"aws_vpc_dhcp_options",
	"aws_vpn_connection",
	"aws_vpn_gateway",
	"aws_elb",
	"aws_lb",
}

taggable_resources[id] = resource {
	some resource_type
	taggable_resource_types[resource_type]
	resources = fugue.resources(resource_type)
	resource = resources[id]
}

is_properly_tagged(resource) {
	minimum_tags = {"CostCenter"}

	keys := {key | resource.tags[key]}
	leftover := minimum_tags - keys
	leftover == set()
}

policy[r] {
	resource = taggable_resources[_]
	not is_properly_tagged(resource)
	r = fugue.deny_resource_with_message(resource, "Missing minimum required tags for resources.")
}

policy[r] {
	resource = taggable_resources[_]
	is_properly_tagged(resource)
	r = fugue.allow_resource(resource)
}
