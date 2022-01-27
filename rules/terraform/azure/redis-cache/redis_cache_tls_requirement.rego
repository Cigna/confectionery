# Redis Cache TlS Requirement: Deny Redis Cache resources that do not utilize TLS version 1.2 or higher
# This rule denies Redis Cache resources from being created that do not utilize TLS version 1.2 or higher
package rules.redis_cache_tls_requirement

import data.fugue

resource_type = "MULTIPLE"

redis_caches = fugue.resources("azurerm_redis_cache")

# Ensures a given web app requires TLS 1.2 or higher
uses_required_tls_version(resource) {
	to_number(resource.minimum_tls_version) >= to_number("1.2")
}

policy[p] {
	resource = redis_caches[_]
	uses_required_tls_version(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = redis_caches[_]
	not uses_required_tls_version(resource)
	p = fugue.deny_resource_with_message(resource, "Redis Cache resources must utilize TLS version 1.2 or higher.")
}
