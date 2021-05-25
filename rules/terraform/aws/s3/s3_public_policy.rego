package rules.s3_public_policy

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

s3_bucket = fugue.resources("aws_s3_bucket_policy")

# Checking for Principal * or AWS:*
is_deny_star_principal(a) {
	a == "*"
}

is_deny_star_principal(a) {
	a.AWS == "*"
}

# Exception conditions if Principal * or AWS:* does exist
check_conditions(condition) {
	condition.StringEquals["aws:SourceVpc"]
}

check_conditions(condition) {
	condition.StringEquals["aws:PrincipalOrgID"]
}

# Determine if a policy is a "public policy"
#
# - Effect: Allow
# - Principal: "*" or .AWS: "*"
# - Condition does not contain StringEquals.aws:sourceVpc or StringEquals.aws:PrincipalOrgID
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

	check_conditions(statement.Condition)
}

is_not_wildcard_policy(resource) {
	startswith(resource.policy, "{")
	json.unmarshal(resource.policy, doc)
	statements = as_array(doc.Statement)
	statement = statements[_]

	statement.Effect == "Deny"
}

# Judge policies and wildcard policies.
policy[p] {
	resource = s3_bucket[_]
	not is_not_wildcard_policy(resource)
	p = fugue.deny_resource_with_message(resource, "Having Effect:Allow and Principal:* with no condition on a Bucket Policy can unintentionally leave an S3 bucket open to the public. Either set a sourceVPC or PrincipalOrgID condition or set Principal more restrictive than *.")
}

policy[p] {
	resource = s3_bucket[_]
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
