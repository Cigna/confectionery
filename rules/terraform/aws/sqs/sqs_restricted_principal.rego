package rules.sqs_restricted_principal

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

aws_sqs_queue_policy = fugue.resources("aws_sqs_queue_policy")

# Checking for Principal * or AWS:*
is_deny_star_principal(a) {
	a == "*"
}

is_deny_star_principal(a) {
	a.AWS == "*"
}

# Exception conditions if Principal * or AWS:* does exist

# Determine if a policy is a "public policy"
#
# - Effect: Allow
# - Principal: "*" or .AWS: "*"
# - Condition does not exist
is_not_wildcard_policy(resource) {
	startswith(resource.policy, "{")
	json.unmarshal(resource.policy, doc)
	statements = as_array(doc.Statement)
	statement = statements[_]

	statement.Effect == "Allow"

	principals = as_array(statement.Principal)
	principal = principals[_]

	not is_deny_star_principal(principal)
}

is_not_wildcard_policy(resource) {
	startswith(resource.policy, "{")
	json.unmarshal(resource.policy, doc)
	statements = as_array(doc.Statement)
	statement = statements[_]

	statement.Effect == "Allow"

	principals = as_array(statement.Principal)
	principal = principals[_]

	statement.Condition
}

# Judge policies and wildcard policies.
policy[p] {
	resource = aws_sqs_queue_policy[_]
	not is_not_wildcard_policy(resource)
	p = fugue.deny_resource_with_message(resource, "Deny SQS policies that have wildcard principals with no limiting conditions defined.")
}

policy[p] {
	resource = aws_sqs_queue_policy[_]
	is_not_wildcard_policy(resource)
	p = fugue.allow_resource(resource)
}

# Helper function to make anything an array that is not already
as_array(x) = [x] {
	not is_array(x)
}

else = x {
	true
}
