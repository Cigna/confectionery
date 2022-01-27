# Log Analytics Disable Internet Queries: Deny log analytics workspace resources that do not disable internet queries
# This rule denies Log Analytics Workspace resources from being created that do not disable internet queries
package rules.log_analytics_disable_internet_queries

import data.fugue

resource_type = "MULTIPLE"

workspaces = fugue.resources("azurerm_log_analytics_workspace")

# Ensures a given log anayltics workspace disabled internet queries
disables_internet_queries(resource) {
	resource.internet_query_enabled == false
}

policy[p] {
	resource = workspaces[_]
	disables_internet_queries(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = workspaces[_]
	not disables_internet_queries(resource)
	p = fugue.deny_resource_with_message(resource, "Log Analytics Workspaces must disable Internet queries by setting internet_query_enabled to false.")
}
