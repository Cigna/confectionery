# Logic App HTTPS Requirement: Deny Standard Logic App resources that do not require HTTPS endpoint connections
# This rule denies Standard Logic App resources from being created that do not require HTTPS protocol for app endpoint access
package rules.logic_app_https_requirement

import data.fugue

resource_type = "MULTIPLE"

logic_apps = fugue.resources("azurerm_logic_app_standard")

# Ensures a given web app requires HTTPS
requires_https(resource) {
	resource.https_only == true
}

policy[p] {
	resource = logic_apps[_]
	requires_https(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = logic_apps[_]
	not requires_https(resource)
	p = fugue.deny_resource_with_message(resource, "Standard Logic App resources must require HTTPS endpoint connections.")
}
