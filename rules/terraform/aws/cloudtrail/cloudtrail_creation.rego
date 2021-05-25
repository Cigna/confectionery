package rules.cloudtrail_creation

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
aws_cloudtrail = fugue.resources("aws_cloudtrail")

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = aws_cloudtrail[_]
	not resource
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = aws_cloudtrail[_]
	resource
	p = fugue.deny_resource_with_message(resource, "Cloudtrails are not allowed to be created.")
}
