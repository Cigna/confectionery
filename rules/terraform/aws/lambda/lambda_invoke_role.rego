package rules.lambda_invoke_role

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the Lambda functions
# again.
aws_lambda_function = fugue.resources("aws_lambda_function")

aws_iam_role = fugue.resources("aws_iam_role")

is_invalid(resource) {
	iam_role = aws_iam_role[_]
	resource.role == iam_role.id
	is_invoke_policy(iam_role)
}

is_invoke_policy(role) {
	startswith(role.assume_role_policy, "{")
	json.unmarshal(role.assume_role_policy, doc)
	statements = as_array(doc.Statement)
	statement = statements[_]

	statement.Effect == "Allow"

	principals = as_array(statement.Principal)
	principal = principals[_]
	principal.Service == "lambda.amazonaws.com"

	actions = as_array(statement.Action)
	action = actions[_]
	action == "lambda:InvokeLambda"
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = aws_lambda_function[_]
	not is_invalid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = aws_lambda_function[_]
	is_invalid(resource)
	p = fugue.deny_resource_with_message(resource, "Lambda functions should not have an iam role that can invoke lambdas.")
}

as_array(x) = [x] {
	not is_array(x)
} else = x {
	true
}
