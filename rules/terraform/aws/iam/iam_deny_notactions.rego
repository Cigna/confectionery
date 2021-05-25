# IAM Deny NotActions: Deny policies that grant permissions using deny-list approach
# This rule denies any type of iam policy that grant permissions using deny-list approach 
# by validating and ensuring the policy does not contain NotAction Elements
package rules.iam_deny_notactions

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# Validate all iam policy types
iam_policy_types = {
	"aws_iam_policy",
	"aws_iam_group_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
}

#Finding the name of the resource type
#list of iam policies
policies[name] = resource {
	some resource_type
	iam_policy_types[resource_type]
	resources = fugue.resources(resource_type)
	resource = resources[name]
}

# Iam policies should deny NotActions , policies should only specify Actions 
is_invalid(resource) {
	startswith(resource.policy, "{")
	json.unmarshal(resource.policy, doc)
	statements = as_array(doc)
	statement := statements[_].Statement
	statement[_].NotAction
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# # of _judgements_.

# Allows the resource if the policy does not contain a NotAction element 
# Only Action elements are allowed
policy[p] {
	resource = policies[_]
	not is_invalid(resource)
	p = fugue.allow_resource(resource)
}

# Denies the resource and presents custom message if the policy contains a NotAction element
# provides custom message of the policy name(resource address) that failed 
policy[p] {
	resource = policies[_]
	is_invalid(resource)
	p = fugue.deny_resource_with_message(resource, "IAM policies should not contain NotAction Elements.")
}

# Utility: turns anything into an array, if it's not an array already.
as_array(x) = [x] {
	not is_array(x)
}

else {
	x = true
}
