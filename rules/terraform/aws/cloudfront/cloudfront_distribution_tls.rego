# Cloudfront distributions must utilize TLSv1.2_* or higher
# TLS1.1 and lower are considered deprecated and should not be used. TLSv1.2 or TLSv1.3 are secure.

package rules.cloudfront_distribution_tls

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
cloudfront_distribution_resource = fugue.resources("aws_cloudfront_distribution")

correct_ciphers = {"TLSv1.2", "TLSv1.3"}

#Auxiliary function.
#Ensure TLS1.2_* or higher is being utilized
is_TLS_correct_version(resource) {
	contains(resource.viewer_certificate[_].minimum_protocol_version, correct_ciphers[_])
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

#Allow resource if TLS1.2_* or higher is being used
policy[p] {
	resource = cloudfront_distribution_resource[_]
	is_TLS_correct_version(resource)
	p = fugue.allow_resource(resource)
}

#Deny resource if TLS is not enabled
policy[p] {
	resource = cloudfront_distribution_resource[_]
	not is_TLS_correct_version(resource)
	p = fugue.deny_resource_with_message(resource, "TLSv1.2_* or high must be utilized on cloudfront distributions.")
}
