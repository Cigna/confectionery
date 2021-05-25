package rules.redshift_publicly_accessible

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

redshift_cluster = fugue.resources("aws_redshift_cluster")

# Auxillary Function
# Deny Resource if 'publicly_accessible' is set to true
is_public(resource) {
	resource.publicly_accessible == true
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = redshift_cluster[_]
	not is_public(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = redshift_cluster[_]
	is_public(resource)
	p = fugue.deny_resource_with_message(resource, "Redshift Clusters should not be public.")
}
