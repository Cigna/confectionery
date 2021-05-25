# S3 Bucket Encryption: Deny S3 Buckets with ACL set to public.
# ACL permissions permit anyone, malicious or not, to add, update, or remove the contents of your S3 bucket. 
# This rule denies S3 buckets with an ACL value that begin with "public-" or "authenticated-".
package rules.s3_public_access_acl

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
s3_bucket = fugue.resources("aws_s3_bucket")

# Auxiliary function.
# Deny resource is ACL value begins with "public-"
is_public(resource) {
	contains(resource.acl, "public-")
}

# Deny resource is ACL value begins with "authenticated-"
is_public(resource) {
	contains(resource.acl, "authenticated-")
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	resource = s3_bucket[_]
	not is_public(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = s3_bucket[_]
	is_public(resource)
	p = fugue.deny_resource_with_message(resource, "S3 bucket ACLs should not be public.")
}
