# Cosmos DB Restrict Public Access: Deny CosmosDB resources that do not disable public network access
# This rule denies CosmosDB resources from being created that do not set the public_network_access_enabled attribute to false
package rules.cosmos_db_restrict_public_access

import data.fugue

resource_type = "MULTIPLE"

cosmosdbs = fugue.resources("azurerm_cosmosdb_account")

# Ensures a given Cosmos DB disables public network access
disables_public_network_access(resource) {
	resource.public_network_access_enabled == false
}

policy[p] {
	resource = cosmosdbs[_]
	disables_public_network_access(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = cosmosdbs[_]
	not disables_public_network_access(resource)
	p = fugue.deny_resource_with_message(resource, "CosmosDB resources must set public_network_access_enabled to false.")
}
