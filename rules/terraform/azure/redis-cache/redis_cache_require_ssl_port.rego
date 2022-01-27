# Redis Cache Require SSL Port: Deny Redis Cache resources that allow connections on non-SSL/TLS port 6379
# This rule denies Redis Cache resources from being created that allow connections on non-SSL/TLS port 6379
package rules.redis_cache_require_ssl_port

import data.fugue

resource_type = "MULTIPLE"

redis_caches = fugue.resources("azurerm_redis_cache")

# Ensures a given redis cache does not allow connections on non-SSL/TLS port 6379
disables_non_ssl_connections(resource) {
	resource.enable_non_ssl_port == false
}

policy[p] {
	resource = redis_caches[_]
	disables_non_ssl_connections(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = redis_caches[_]
	not disables_non_ssl_connections(resource)
	p = fugue.deny_resource_with_message(resource, "Redis Cache resources must disable non-SSL/TLS port 6379 access by setting enable_non_ssl_port to false.")
}
