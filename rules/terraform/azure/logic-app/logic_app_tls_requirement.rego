# Logic App TlS Requirement: Deny Standard Logic App resources that do not utilize TLS version 1.2 or higher
# This rule denies Standard Logic App resources from being created that do not utilize TLS version 1.2 or higher
package rules.logic_app_tls_requirement

import data.fugue

resource_type = "MULTIPLE"

logic_apps = fugue.resources("azurerm_logic_app_standard")

# Ensures a given web app requires TLS 1.2 or higher
uses_required_tls_version(resource) {
	to_number(resource.site_config[_].min_tls_version) >= to_number("1.2")
}

policy[p] {
	resource = logic_apps[_]
	uses_required_tls_version(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = logic_apps[_]
	not uses_required_tls_version(resource)
	p = fugue.deny_resource_with_message(resource, "Standard Logic App resources must utilize TLS version 1.2 or higher.")
}
