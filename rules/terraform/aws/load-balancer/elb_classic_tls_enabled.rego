# Elastic Load Balancers Classic must have TLS (Encryption) enabled
# Enabling HTTPs with a valid SSL certificate arn will enable TLS on classic load balancers
# Transport Layer Security can be enabled on an ELB Classic resource by enabling HTTPs with a valid SSL certificate arn
package rules.elb_classic_tls_enabled

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
elb_resource = fugue.resources("aws_elb")

#Auxiliary function.
#Ensure TLS is enabled
is_TLS_enabled(resource) {
	some val

	#Creating an index to loop through the listener values
	listener_values := resource.listener[val]

	#ensures https is set
	listener_values.lb_protocol == "https"

	#ensures ssl_certificate_id key exists (its optional)
	listener_values.ssl_certificate_id

	#ssl_certificate_id contains "arn" when valid	
	contains(listener_values.ssl_certificate_id, "arn")
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

#Allow resource if TLS is enabled
policy[p] {
	resource = elb_resource[_]
	is_TLS_enabled(resource)
	p = fugue.allow_resource(resource)
}

#Deny resource if TLS is not enabled
policy[p] {
	resource = elb_resource[_]
	not is_TLS_enabled(resource)
	p = fugue.deny_resource_with_message(resource, "TLS must be enabled.")
}
