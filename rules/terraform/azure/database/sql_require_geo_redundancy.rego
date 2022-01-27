# SQL Require Geo Redundancy: Deny SQL server resources that do not utilize geo-redundancy with failover groups
# This rule denies SQL server resources from being created that do not utilize geo-redundancy with a failover group and SQL servers at different locations
package rules.sql_require_geo_redundancy

import data.fugue

resource_type = "MULTIPLE"

sql_dbs = fugue.resources("azurerm_sql_server")

sql_failover_groups = fugue.resources("azurerm_sql_failover_group")

# Checks if there exists a SQL Server failover group that uses this SQL server as the PRIMARY server
has_geo_redundant_failover_group(resource) {
	some i
	sql_failover_groups[i].server_name == resource.name
	failover_server := sql_dbs[sql_failover_groups[i].partner_servers[_].id[_]]
	failover_server.location != resource.location
}

# Checks if there exists a SQL Server failover group that uses this SQL server as the SECONDARY server
has_geo_redundant_failover_group(resource) {
	sql_failover_groups[_].partner_servers[_].id[_] == resource.id
}

policy[p] {
	resource = sql_dbs[_]
	has_geo_redundant_failover_group(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = sql_dbs[_]
	not has_geo_redundant_failover_group(resource)
	p = fugue.deny_resource_with_message(resource, "SQL server resources must utilize geo-redundancy with a failover group where the failover SQL server is in a different location.")
}
