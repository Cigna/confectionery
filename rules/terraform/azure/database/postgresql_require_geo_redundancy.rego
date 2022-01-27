# PostgreSQL Require Geo Redundancy: Deny PostgreSQL server resources that do not utilize geo-redundancy
# This rule denies PostgreSQL server resources from being created that do not utilize geo-redundancy
package rules.postgresql_require_geo_redundancy

import data.fugue

resource_type = "MULTIPLE"

postgres_dbs = fugue.resources("azurerm_postgresql_server")

# Ensures a given Maria DB server is geo-redundant
is_geo_redundant(resource) {
	resource.geo_redundant_backup_enabled == true
}

# Basic tier doesn't offer geo-redundancy, these lower tiers are valid
is_geo_redundant(resource) {
	# See SKU naming convention: https://docs.microsoft.com/en-us/rest/api/mariadb/servers/create#sku
	startswith(resource.sku_name, "B")
}

policy[p] {
	resource = postgres_dbs[_]
	is_geo_redundant(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = postgres_dbs[_]
	not is_geo_redundant(resource)
	p = fugue.deny_resource_with_message(resource, "PostgeSQL server resources must utilize geo-redundancy if run on a SKU that supports it.")
}
