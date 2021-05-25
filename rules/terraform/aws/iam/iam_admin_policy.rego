# IAM Admin Policy: Deny full administrative permissions
# This rule denies any type of iam policy that grants full administrative permissions 
# by validating and ensuring the policy is not a wildcard policy 
package rules.iam_admin_policy

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

# Determine if a policy is a "wildcard policy".  A wildcard policy is defined as
# a policy having a statement that has all of:
#
# - Effect: Allow
# - Resource: "*"
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
	action == "*"
}

# Judge policies and wildcard policies.
# Denies the resource if it is a wildcard policy/grants full administrative permissions
policy[p] {
	single_policy = wildcard_policies[name]
	p = fugue.deny_resource_with_message(single_policy, "Full administrative permissions should not be granted.")
}

# Allows the resource if it is not a wildcard policy/does not grant full administrative permissions
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
