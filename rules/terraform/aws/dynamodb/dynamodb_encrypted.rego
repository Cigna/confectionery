# Dynamodb Encryption: Deny dynamodb tables that are encrypted using AWS Owned CMK 
# This rule denies dynamodb tables that are encrypted using AWS Owned CMK by validating and ensuring that dynamodb is encrypted using AWS Managed CMK

package rules.dynamodb_encrypted

import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# Validate all dynamodb tables
db_tables = fugue.resources("aws_dynamodb_table")

# Auxiliary function
# Denies the dynamodb table if server side encryption is not enabled and set to true
is_valid(resource) {
	sse = resource.server_side_encryption[_]
	sse.enabled == true
}

# Regula expects advanced rules to contain a `policy` rule that holds a set of _judgements_.
# Denies resource if dynamodb table is not encrypted using AWS Managed CMK
policy[p] {
	resource = db_tables[_]
	not is_valid(resource)
	p = fugue.deny_resource_with_message(resource, "Dynamodb tables must be encrypted using AWS Managed CMK.")
}

# Allows resource if dynamodb table is encrypted using AWS Managed CMK
policy[p] {
	resource = db_tables[_]
	is_valid(resource)
	p = fugue.allow_resource(resource)
}
