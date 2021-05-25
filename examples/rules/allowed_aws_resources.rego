package rules.allowed_aws_resources

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# Sample list of allowed terraform prefixes
allowlist = [
	"aws_ebs",
	"aws_ec2",
	"aws_ecr",
	"aws_ecs",
	"aws_eip",
	"aws_eks",
]

#check if resource is allowed
is_allowed_resource(resource) {
	startswith(resource._type, allowlist[_])
}

#allow resources that are in allowed resource type list
policy[p] {
	resource = input.resources[_]
	startswith(resource._type, "aws")
	is_allowed_resource(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = input.resources[_]
	startswith(resource._type, "aws")
	not is_allowed_resource(resource)
	p = fugue.deny_resource_with_message(resource, "This is not a resource from an allowed AWS service")
}
