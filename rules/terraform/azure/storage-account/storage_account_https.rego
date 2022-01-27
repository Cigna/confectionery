package rules.storage_account_https

import data.fugue

resource_type = "MULTIPLE"

azurerm_storage_account = fugue.resources("azurerm_storage_account")

# Auxiliary function checking if enable_https_traffic_only is true

valid(resource) {
	resource.enable_https_traffic_only == true
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

policy[p] {
	resource = azurerm_storage_account[_]
	valid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = azurerm_storage_account[_]
	not valid(resource)
	p = fugue.deny_resource_with_message(resource, "Storage accounts must enable https traffic only.")
}
