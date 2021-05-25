#ALB SSL Protocol: Deny Application Load Balancers that have an attached Listener that is not using encryption or proper encryption configurations
#ALB Listeners must have: HTTPs enabled, a valid certificate arn, and is using an AWS recommended SSL policy.
package rules.alb_ssl_configuration

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# `fugue.resources` is a function that allows querying for resources of a
# specific type.  In our case, we are just going to ask for the EBS volumes
# again.

elb_listener_resource = fugue.resources("aws_lb_listener")

elb_load_balancer_resource = fugue.resources("aws_lb")

#SSL Protocols that are allowed. Only protool not inlcuded in the list is: ELBSecurityPolicy-TLS-1-0-2015-04 per AWS recommendation
allowed_security_policies = {
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
	"ELBSecurityPolicy-TLS-1-2-2017-01",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
	"ELBSecurityPolicy-FS-2018-06",
	"ELBSecurityPolicy-FS-1-1-2019-08",
	"ELBSecurityPolicy-FS-1-2-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2019-08",
	"ELBSecurityPolicy-2015-05",
}

#Auxiliary functions.
#Limit users to the recommended AWS SSL policies for ALBs only, not NLBs
#NLB Check

is_ssl_properly_configured(elb_listener_resource) {
	#anywhere loadbalancer arn = address of resource
	elb_listener_resource.load_balancer_arn == elb_load_balancer_resource[x].arn
	elb_load_balancer_resource[x].load_balancer_type == "application"

	# HTTPS must be enabled, HTTP is not allowed
	elb_listener_resource.protocol == "HTTPS"

	# the certificate arn must not be 'null'
	not is_null(elb_listener_resource.certificate_arn)

	# lastly, ensure correct security policies are chosen
	elb_listener_resource.ssl_policy == allowed_security_policies[_]
}

#ALB configuration check
is_ssl_properly_configured(elb_listener_resource) {
	#anywhere loadbalancer arn = address of resource
	elb_listener_resource.load_balancer_arn == elb_load_balancer_resource[x].id
	elb_load_balancer_resource[x].load_balancer_type == "application"

	# HTTPS must be enabled, HTTP is not allowed
	elb_listener_resource.protocol == "HTTPS"

	#a certificate arn must be included
	not is_null(elb_listener_resource.certificate_arn)

	# lastly, ensure correct security policies are chosen
	elb_listener_resource.ssl_policy == allowed_security_policies[_]
}

is_ssl_properly_configured(elb_listener_resource) {
	#anywhere loadbalancer arn = address of resource
	elb_listener_resource.load_balancer_arn == elb_load_balancer_resource[x].arn
	elb_load_balancer_resource[x].load_balancer_type == "network"
}

is_ssl_properly_configured(elb_listener_resource) {
	#anywhere loadbalancer arn = address of resource
	elb_listener_resource.load_balancer_arn == elb_load_balancer_resource[x].id
	elb_load_balancer_resource[x].load_balancer_type == "network"
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.
policy[p] {
	listener_resource = elb_listener_resource[_]

	is_ssl_properly_configured(listener_resource)
	p = fugue.allow_resource(listener_resource)
}

policy[p] {
	listener_resource = elb_listener_resource[_]

	not is_ssl_properly_configured(listener_resource)
	p = fugue.deny_resource_with_message(listener_resource, "An improper SSL configuration is being deployed.")
}
