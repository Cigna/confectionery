# IAM Resource Star Policy: Deny policies that permits powerful actions and uses a wildcard attribute for resource
# This rule denies any type of iam policy that permits powerful actions and uses a wildcard attribute for resource 
# by validating and ensuring powerful actions are scoped to a specific resource

package rules.iam_star_resource

import data.fugue

resource_type = "MULTIPLE"

iam_policy_types = {
	"aws_iam_policy",
	"aws_iam_group_policy",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
}

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

# The following actions should be scoped to a specific resource 
is_deny_star_action(a) {
	deny_actions := {"iam:PassRole", "sts:AssumeRole", "s3:PutObject", "s3:GetObject", "s3:Get*", "s3:Put*", "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:CreateRole", "iam:AttachRolePolicy", "dynamodb:GetItem", "dynamodb:Query"}
	a == deny_actions[_]
}

# Determine if a policy is a "wildcard policy".  A wildcard policy is defined as
# a policy having a statement that has a concerning deny star action and a wild card in resource:
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
	is_deny_star_action(action)
}

# Judge policies and wildcard policies.
# Denies the iam policy if any of the deny_actions above are used along with using a wildcard "*" attribute for resource
policy[p] {
	single_policy = wildcard_policies[name]
	p = fugue.deny_resource_with_message(single_policy, "This policy specifies an action that should be scoped to specific resources instead of a star.")
}

# Allows the iam policy if any of the deny_actions above are scoped to a specific resource 
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
