# IAM Permissive Policy Attachments: Deny IAM managed policies that are overly permissive 
# This rule denies any type of IAM policy attachments that overly permissive by validating and ensuring AWS managed policies that are too permissive are not used

package rules.iam_permissive_attached_policy

import data.fugue

resource_type = "MULTIPLE"

# Some AWS managed policies are too permissive and should not be used. You should create new more granular policies
# The following managed policies are not allowed
#	"AdministratorAccess"
#	"AmazonS3FullAccess"
#	"AmazonElasticMapReduceFullAccess"
#	"IAMFullAccess"
#	"PowerUserAccess"
#	"service-role/AmazonEC2RoleforSSM"
#	"service-role/AmazonElasticMapReduceforEC2Role"
#	"arn:aws:iam::aws:policy/AWSLambdaFullAccess"

# Validate any of the following iam policy types
iam_policy_types = {
	"aws_iam_user_policy_attachment",
	"aws_iam_policy_attachment",
	"aws_iam_group_policy_attachment",
	"aws_iam_role_policy_attachment",
}

iam_policies[id] = resource {
	some resource_type
	iam_policy_types[resource_type]
	resources = fugue.resources(resource_type)
	resource = resources[id]
}

# The following overly permissive policies should not be used 
is_invalid(resource) {
	deny_policies := {
		"arn:aws:iam::aws:policy/AdministratorAccess",
		"arn:aws:iam::aws:policy/IAMFullAccess",
		"arn:aws:iam::aws:policy/AmazonS3FullAccess",
		"arn:aws:iam::aws:policy/AmazonElasticMapReduceFullAccess",
		"arn:aws:iam::aws:policy/PowerUserAccess",
		"arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM",
		"arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role",
		"arn:aws:iam::aws:policy/AWSLambdaFullAccess",
	}

	resource.policy_arn == deny_policies[_]
}

# Denies the resource if any of the deny_policies are used
policy[r] {
	resource = iam_policies[_]
	is_invalid(resource)
	r = fugue.deny_resource_with_message(resource, "Overly Permissive managed policy used, please use/create a policy that follows least privilege.")
}

# Allows the resource if none of the deny_policies are used
policy[r] {
	resource = iam_policies[_]
	not is_invalid(resource)
	r = fugue.allow_resource(resource)
}
