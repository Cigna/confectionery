# Web App TLS Requirement: Deny Web App resources that do not leverage at least TLS version 1.2
# This rule denies Web App resources from being created that do not utilize the required minimum TLS version 1.2
package rules.web_app_tls_requirement

import data.fugue

resource_type = "MULTIPLE"

web_apps = fugue.resources("azurerm_app_service")

# Ensures a given web app uses at least TLS 1.2
uses_required_tls_version(resource) {
	to_number(resource.site_config[_].min_tls_version) >= to_number("1.2")
}

policy[p] {
	resource = web_apps[_]
	uses_required_tls_version(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = web_apps[_]
	not uses_required_tls_version(resource)
	p = fugue.deny_resource_with_message(resource, "Web App resources must utilize TLS version 1.2 or greater.")
}
