package rules.storage_account_tls

import data.fugue

resource_type = "MULTIPLE"

azurerm_storage_account = fugue.resources("azurerm_storage_account")

# Auxiliary function checking if min_tls_version is 1.2

valid(resource) {
	resource.min_tls_version == "TLS1_2"
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
	p = fugue.deny_resource_with_message(resource, "Minimum supported TLS version for Storage Accounts is 1.2")
}
