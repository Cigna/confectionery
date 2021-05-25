# Elasticache encryption file validation: Deny if elasticache replication groups do not have encryption at-rest and in-transit.
package rules.elasticache_encryption

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.

# Gather all elasticache replications groups in terraform template
elasticache_replication_group = fugue.resources("aws_elasticache_replication_group")

# Auxiliary function.
# Checks that the replication group has at_rest and in_transit encryption enabled
is_valid(resource) {
	resource.at_rest_encryption_enabled == true
	resource.transit_encryption_enabled == true
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

# Allows the resource if is_valid method returns true
policy[p] {
	resource = elasticache_replication_group[_]
	is_valid(resource)
	p = fugue.allow_resource(resource)
}

# Denies the resource and presents custom message if is_valid method returns false
policy[p] {
	resource = elasticache_replication_group[_]
	not is_valid(resource)
	p = fugue.deny_resource_with_message(resource, "Elasticache Replication groups must have encryption at rest and in transit.")
}
