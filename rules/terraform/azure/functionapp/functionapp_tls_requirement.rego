# Functionapp TLS Requirement: Deny functionapp resources that do not leverage at least TLS version 1.2
# This rule denies functionapp resources from being created that do not utilize the required minimum TLS version 1.2
package rules.functionapp_tls_requirement

import data.fugue

resource_type = "MULTIPLE"

functionapp = fugue.resources("azurerm_function_app")

# Ensures a given functionapp uses at least TLS 1.2
uses_required_tls_version(resource) {
	to_number(resource.site_config[_].min_tls_version) >= to_number("1.2")
}

policy[p] {
	resource = functionapp[_]
	uses_required_tls_version(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = functionapp[_]
	not uses_required_tls_version(resource)
	p = fugue.deny_resource_with_message(resource, "Functionapp resources must utilize TLS version 1.2 or greater.")
}
