# SNS Encryption: Deny SNS topics that are not server-side encrypted
# This rule denies SNS topics that are not encrypted by validating server side encryption is enabled
package rules.sns_encryption

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.
# This will validate all aws_sns_topic resources
aws_sns_topic = fugue.resources("aws_sns_topic")

# Auxiliary function.
# sns encryption is enabled if KmsMasterKeyId exists
is_not_null(resource) {
	not resource.kms_master_key_id == null
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
# Resource is Valid if KmsMasterKeyId is not null
policy[p] {
	resource = aws_sns_topic[_]
	is_not_null(resource)
	p = fugue.allow_resource(resource)
}

# Resource is Invalid if KmsMasterKeyId is null
policy[p] {
	resource = aws_sns_topic[_]
	not is_not_null(resource)
	p = fugue.deny_resource_with_message(resource, "SNS topic encryption should be enabled.")
}
