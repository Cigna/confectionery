package rules.iam_user_creation

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
aws_iam_user = fugue.resources("aws_iam_user")

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = aws_iam_user[_]
	not resource
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = aws_iam_user[_]
	resource
	p = fugue.deny_resource_with_message(resource, "IAM Users are not allowed to be created.")
}
