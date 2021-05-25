package rules.eks_version_enforcement

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
eks_cluster = fugue.resources("aws_eks_cluster")

#Auxiliary function.
is_allowed_version(resource) {
	minimum_accepted_version := [1, 15, 0]

	# Parse version into each value to be converted to number
	version := resource.version
	version_value := split(version, ".")

	#Compare terraform version to minimum_accepted_version to ensure its equal to or greater than
	#Major >= 1
	to_number(version_value[0]) >= minimum_accepted_version[0]

	#Minor >= 15
	to_number(version_value[1]) >= minimum_accepted_version[1]
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = eks_cluster[_]
	is_allowed_version(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = eks_cluster[_]
	not is_allowed_version(resource)
	p = fugue.deny_resource_with_message(resource, "EKS must be version 1.15 or higher.")
}
