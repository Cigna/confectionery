# IAM Service Star Policy: Deny Iam policies that use the wildcard "*" attribute  with service actions 
# This rule denies any type of Iam policy that uses the wildcard attribute with service actions by validating 
# and ensuring the wildcard is not used and actions are listed.

package rules.iam_service_star

import data.fugue

resource_type = "MULTIPLE"

iam_policy_types = {
	"aws_iam_policy",
	"aws_iam_group_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
}

#Validate all iam policy types
policies[name] = p {
	some resource_type
	iam_policy_types[resource_type]
	resources = fugue.resources(resource_type)
	p = resources[name]
}

# All wildcard policies.
wildcard_policies[name] = p {
	p = policies[name]
	is_wildcard_policy(p)
}

is_deny_star_action(a) {
	re_match(`[a-zA-Z0-9\-]+:\*$`, a)
}

# Determine if a policy is a "wildcard policy"
#
# - Effect: Allow
# - Resource: "<service>:*"
# - Action: "*"
is_wildcard_policy(p) {
	startswith(p.policy, "{")
	json.unmarshal(p.policy, doc)
	statements = as_array(doc.Statement)
	statement = statements[_]

	statement.Effect == "Allow"

	resources = as_array(statement.Resource)
	resource = resources[_]
	resource == "*"

	actions = as_array(statement.Action)
	action = actions[_]
	is_deny_star_action(action)
}

# Judge policies and wildcard policies.
# Denies the resource if it is a wildcard policy and actions are not listed 
policy[p] {
	single_policy = wildcard_policies[name]
	p = fugue.deny_resource_with_message(single_policy, "List actions required rather than using <service>:*.")
}

# Allows the resource if it is not a wildcard policy and actions are listed
policy[p] {
	single_policy = policies[name]
	not wildcard_policies[name]
	p = fugue.allow_resource(single_policy)
}

# Utility: turns anything into an array, if it's not an array already.
as_array(x) = [x] {
	not is_array(x)
}

else = x {
	true
}
