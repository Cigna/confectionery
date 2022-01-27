# Web App HTTPS Requirement: Deny Web App resources that do not require HTTPS endpoint connections
# This rule denies Web App resources from being created that do not require HTTPS protocol for app endpoint access
package rules.web_app_https_requirement

import data.fugue

resource_type = "MULTIPLE"

web_apps = fugue.resources("azurerm_app_service")

# Ensures a given web app requires HTTPS
requires_https(resource) {
	resource.https_only == true
}

policy[p] {
	resource = web_apps[_]
	requires_https(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = web_apps[_]
	not requires_https(resource)
	p = fugue.deny_resource_with_message(resource, "Web App resources must require HTTPS endpoint connections.")
}
