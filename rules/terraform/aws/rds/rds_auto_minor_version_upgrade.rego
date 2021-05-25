package rules.rds_auto_minor_version_upgrade

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
db_instance = fugue.resources("aws_db_instance")

# Auxiliary function.
is_enabled(resource) {
	resource.auto_minor_version_upgrade == true
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = db_instance[_]
	is_enabled(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = db_instance[_]
	not is_enabled(resource)
	p = fugue.deny_resource_with_message(resource, "auto_minor_version_upgrade should be set to true.")
}
