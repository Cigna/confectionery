package rules.eks_public_endpoint

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
eks_cluster = fugue.resources("aws_eks_cluster")

#Auxiliary function.
is_private_eks(resource) {
	vpc_config = resource.vpc_config[_]
	vpc_config.endpoint_private_access == true
	vpc_config.endpoint_public_access == false
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = eks_cluster[_]
	is_private_eks(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = eks_cluster[_]
	not is_private_eks(resource)
	p = fugue.deny_resource_with_message(resource, "EKS must have private endpoints.")
}
