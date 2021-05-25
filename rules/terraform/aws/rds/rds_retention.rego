package rules.rds_retention

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

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

#rds_instance = fugue.resources("aws_db_instance")

# Auxiliary function.
is_retained(resource) {
	resource.backup_retention_period >= 7
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = rds_resources[_]
	is_retained(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = rds_resources[_]
	not is_retained(resource)
	p = fugue.deny_resource_with_message(resource, "RDS DB Instances and Clusters backup retention period should be set to at least 7 days.")
}
