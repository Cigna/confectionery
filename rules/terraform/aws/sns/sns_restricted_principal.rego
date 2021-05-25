# SNS Restricted Principal: Deny SNS topic policies that extend permissions to be made publicly accessible
# This rule denies SNS topic policies that extend permissions to be made publicly accessible by validating 
# and ensuring the policy does not grant permissions when a principal attribute is set to a wildcard such as " * "
package rules.sns_restricted_principal

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# Validate all aws_sns_topic_policies
sns_policy = {"aws_sns_topic_policy"}

sns_policies[name] = resource {
	some resource_type
	sns_policy[resource_type]
	resources = fugue.resources(resource_type)
	resource = resources[name]
}

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
# SNS topic policies shoud not grant permissions to everyone Principal:"*" or .AWS: "*"
is_valid(resource) {
	startswith(resource.policy, "{")
	json.unmarshal(resource.policy, doc)
	statements = as_array(doc)
	statement = statements[_].Statement

	statement[_].Effect == "Allow"

	principals = as_array(statement[_].Principal)
	principal = principals[_]

	not is_deny_star_principal(principal)
}

# SNS topic policies shoud not grant permissions to everyone Principal:"*" or .AWS: "*" , but excepts conditions(which restricts access to everyone)
is_valid(resource) {
	startswith(resource.policy, "{")
	json.unmarshal(resource.policy, doc)
	statements = as_array(doc)
	statement = statements[_].Statement

	statement[_].Effect == "Allow"

	principals = as_array(statement[_].Principal)
	principal = principals[_]

	conditions = as_array(statement[_].Condition)
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

# Allows the resource if permissions are not made publicly accessible 
policy[p] {
	resource = sns_policies[_]
	is_valid(resource)
	p = fugue.allow_resource(resource)
}

# Denies the resource and presents custom message if permissions are made publicly accessible
# provides custom message of the policy name(resource address) that failed 
policy[p] {
	resource = sns_policies[_]
	not is_valid(resource)
	p = fugue.deny_resource_with_message(resource, "SNS policies should not grant permissions to everyone with no limiting conditions defined.")
}

# Utility: turns anything into an array, if it's not an array already.
as_array(x) = [x] {
	not is_array(x)
}

else {
	x = true
}
