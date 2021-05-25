package rules.sqs_server_side_encryption

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
aws_sqs_queue = fugue.resources("aws_sqs_queue")

# Auxiliary function.
#sqs queue encryption is enabled if KmsMasterKeyId exists
is_not_null(resource) {
	not resource.kms_master_key_id == null
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = aws_sqs_queue[_]
	is_not_null(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = aws_sqs_queue[_]
	not is_not_null(resource)
	p = fugue.deny_resource_with_message(resource, "Deny SQS queues that do not have server side encryption.")
}
