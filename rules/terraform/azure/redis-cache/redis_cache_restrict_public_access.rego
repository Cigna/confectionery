# Redis Cache Restrict Public Access: Deny Redis Cache resources that do not restrict public network access
# This rule denies Redis Cache resources from being created that do not configure public network access enabled to false
package rules.redis_cache_restrict_public_access

import data.fugue

resource_type = "MULTIPLE"

redis_caches = fugue.resources("azurerm_redis_cache")

# Ensures a given redis cache does not allow public network access
disables_public_network_access(resource) {
	resource.public_network_access_enabled == false
}

policy[p] {
	resource = redis_caches[_]
	disables_public_network_access(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = redis_caches[_]
	not disables_public_network_access(resource)
	p = fugue.deny_resource_with_message(resource, "Redis Cache resources must restrict public network access by setting public_network_access_enabled to false.")
}
