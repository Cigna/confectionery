# ACM validation: Deny any ACM Certificate that is not certified by DNS, validation by email is not allowed.
package rules.acm_dns_validation

# Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

#Find all acm_certificate resources
acm_certificate = fugue.resources("aws_acm_certificate")

# Auxiliary function
#ACM Certificates should not be validated with Email 
is_invalid(resource) {
	resource.validation_method == "EMAIL"
}

# Regula expects advanced rules to contain a `policy` rule that holds a set of _judgements_.
# Allow resource if ACM Certificate is validated with DNS 
policy[p] {
	resource = acm_certificate[_]
	not is_invalid(resource)
	p = fugue.allow_resource(resource)
}

#Deny resource if ACM Certificate is not validated with DNS
policy[p] {
	resource = acm_certificate[_]
	is_invalid(resource)
	p = fugue.deny_resource_with_message(resource, "ACM Certificates should be validated with DNS, not email.")
}
