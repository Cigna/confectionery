# Functionapp HTTPS Requirement: Deny functionapp resources that do not require HTTPS
# This rule denies functionapp resources from being created that do not require client connections to function endpoints to leverage HTTPS
# https://docs.microsoft.com/en-us/azure/azure-functions/security-concepts
package rules.functionapp_https_requirement

import data.fugue

resource_type = "MULTIPLE"

functionapp = fugue.resources("azurerm_function_app")

# Ensures a given functionapp requires HTTPS connections
requires_https(resource) {
	resource.https_only = true
}

policy[p] {
	resource = functionapp[_]
	requires_https(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = functionapp[_]
	not requires_https(resource)
	p = fugue.deny_resource_with_message(resource, "Functionapp resources must require HTTPS function endpoint connections.")
}
