# EKS Control Plane Logging: Deny eks clusters that do not have eks control plane logging enabled
# This rule denies eks clusters that does not have eks control plane logging enabled 
# by validating and ensuring that cluster log types are enabled

package rules.eks_controlplane_logging

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  

#Validate all eks clusters
eks_cluster_logging = fugue.resources("aws_eks_cluster")

# Auxiliary function
# resource is invalid if enabled_cluster_log_types is null/empty
is_invalid(resource) {
	resource.enabled_cluster_log_types == null
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

# Eks Clusters is allowed if control plane logging is enabled
policy[p] {
	resource = eks_cluster_logging[_]
	not is_invalid(resource)
	p = fugue.allow_resource(resource)
}

# Eks Clusters are denied if control plane logging is not enabled
policy[p] {
	resource = eks_cluster_logging[_]
	is_invalid(resource)
	p = fugue.deny_resource_with_message(resource, "EKS control plane logging must be enabled.")
}
