# Databricks Require CMK: Deny Databrick workspace resources that do not require CMK 
# This rule denies databricks workspace resources from being created that do not require CMK to encrypt the databricks data plane for premium SKU workspaces
package rules.databricks_require_cmk

import data.fugue

resource_type = "MULTIPLE"

databricks_workspaces = fugue.resources("azurerm_databricks_workspace")

# Ensures a given databricks workspace enables CMK encryption on the databricks hosted data plane
requires_cmk(resource) {
	resource.customer_managed_key_enabled == true
}

# OR is a databricks workspace is not on a "premium" plan, then the customer_managed_key_enabled is not available.  These workspaces should pass
requires_cmk(resource) {
	resource.sku != "premium"
}

policy[p] {
	resource = databricks_workspaces[_]
	requires_cmk(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = databricks_workspaces[_]
	not requires_cmk(resource)
	p = fugue.deny_resource_with_message(resource, "Databricks workspace resources must require CMK encryption with the customer_managed_key_enabled attribute enabled for all 'premium' SKU names.")
}
