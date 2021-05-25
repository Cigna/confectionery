# Elastic Load Balancer Classic SSL protocol configuration must not contain one of the following SSL protocols to be compliant
# These versions of TLS are not reccomended by AWS and are considered deprecated
package rules.elb_classic_ssl_protocol

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.
elb_resource = fugue.resources("aws_load_balancer_policy")

#SSL Protocols that are not allowed
dissallowed_ssl_protocols = {"Protocol-TLSv1", "Protocol-SSLv3", "Protocol-SSLv2", "Protocol-SSLv1"}

#Auxiliary function.
#Limit users to TLS1.1 or higher
is_TLS_incorrect_version(resource) {
	some attr
	policy_attributes := resource.policy_attribute[attr]
	policy_attributes.name == dissallowed_ssl_protocols[_]
	policy_attributes.value == "true"
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
# Allow resource if it is not utilizing an incorrect TLS version
policy[p] {
	resource = elb_resource[_]
	not is_TLS_incorrect_version(resource)
	p = fugue.allow_resource(resource)
}

# Deny if resource is utilizing an incorrect TLS version
policy[p] {
	resource = elb_resource[_]
	is_TLS_incorrect_version(resource)
	p = fugue.deny_resource_with_message(resource, "An improper SSL protocol is being deployed.")
}
