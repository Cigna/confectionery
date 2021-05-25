package rules.rds_encryption

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.

rds_resource_types = {
	"aws_rds_cluster",
	"aws_db_instance",
}

rds_resources[id] = resource {
	some resource_type
	rds_resource_types[resource_type]
	resources = fugue.resources(resource_type)
	resource = resources[id]
}

# Auxiliary function.
is_encrypted(resource) {
	resource.storage_encrypted == true
	resource.kms_key_id
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = rds_resources[_]
	is_encrypted(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = rds_resources[_]
	not is_encrypted(resource)
	p = fugue.deny_resource_with_message(resource, "RDS DB Instances and Clusters should be encrypted with a KMS Customer Managed key.")
}
