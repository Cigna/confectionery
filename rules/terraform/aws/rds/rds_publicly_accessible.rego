package rules.rds_publicly_accessible

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

rds_resource_types = {
	"aws_rds_cluster_instance",
	"aws_db_instance",
}

rds_resources[id] = resource {
	some resource_type
	rds_resource_types[resource_type]
	resources = fugue.resources(resource_type)
	resource = resources[id]
}

# Auxillary Function
# Deny Resource if 'publicly_accessible' is set to true
is_public(resource) {
	resource.publicly_accessible == true
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = rds_resources[_]
	not is_public(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = rds_resources[_]
	is_public(resource)
	p = fugue.deny_resource_with_message(resource, "RDS Instances should not be public.")
}
