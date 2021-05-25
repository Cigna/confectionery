# IAM Policy Document Restricted Principal: Deny IAM Policy Documents that extend permissions to be made publicly accessible
# This rule denies IAM Policy Documents that extend permissions to be made publicly accessible by validating and ensuring the
# policy does not grant permissions when a principal attribute is set to a wildcard such as "*"
package rules.iam_policy_document_principal_star

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# Set Resource type to aws_iam_policy_document
policy_document = fugue.resources("aws_iam_policy_document")

# Checking for Principal *
is_deny_star_principal(a) {
	a == "*"
}

# Determine if a policy is a "public policy"
#
# - Effect: Allow
# - Principal: "*"
# - Condition does not exist
# IAM Policy documents shoud not grant permissions to everyone Principal:"*"
is_valid(resource) {
	statement = resource.statement[_]
	statement.effect == "Allow"

	identifiers = statement.principals[_].identifiers
	identifier = identifiers[_]

	not is_deny_star_principal(identifier)
}

# IAM Policy Documents shoud not grant permissions to everyone Principal:"*", but excepts conditions(which restricts access to everyone)
is_valid(resource) {
	statement = resource.statement[_]
	statement.effect == "Allow"

	identifiers = statement.principals[_].identifiers
	identifier = identifiers[_]

	statement.condition[_]
}

# IAM Policy Documents without a principal are being used as iam policies instead of resource policies and should therefore be ignored for this rule
is_valid(resource) {
	statement = resource.statement[_]
	statement.effect == "Allow"

	statement.principals == []
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

# Allows the resource if permissions are not made publicly accessible 
policy[p] {
	resource = policy_document[_]
	is_valid(resource)
	p = fugue.allow_resource(resource)
}

# Denies the resource and presents custom message if permissions are made publicly accessible
# provides custom message of the policy name(resource address) that failed 
policy[p] {
	resource = policy_document[_]
	not is_valid(resource)
	p = fugue.deny_resource_with_message(resource, "IAM Policy Documents should not grant permissions to everyone with no limiting conditions defined.")
}
