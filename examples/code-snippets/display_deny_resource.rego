# The following code snippet helps developers debug confectionary rules by displaying the json representation
# for each terraform resource. To see the end result, place the following snippet 
# in the deny section of the policy function.

# Code Snippet
msg = sprintf("Resource Info: %s",[resource]) 
p = fugue.deny_resource_with_message(resource, msg)


# Example

policy[p] {
	resource = iam_policies[_]
	is_invalid(resource)
	msg = sprintf("Resource Info: %s",[resource]) 
	p = fugue.deny_resource_with_message(resource, msg)
	# p = fugue.deny_resource_with_message(resource, "Overly Permissive managed policy used, please use/create a policy that follows least privilege")
}