package rules.rds_multi_az

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

rds_instance = fugue.resources("aws_db_instance")

is_multi_az(resource) {
	resource.multi_az
	resource.multi_az == true
}

is_multi_az(resource) {
	startswith(resource.engine, "aurora")
}

is_multi_az(resource) {
	startswith(resource.engine, "sqlserver")
}

is_multi_az(resource) {
	startswith(resource.engine, "docdb")
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = rds_instance[_]
	is_multi_az(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = rds_instance[_]
	not is_multi_az(resource)
	p = fugue.deny_resource_with_message(resource, "All RDS database instances should have MultiAZ enabled except AuroraDB, SQLServer, and DocumentDB.")
}
