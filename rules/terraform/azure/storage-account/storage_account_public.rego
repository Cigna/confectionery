package rules.storage_account_public

import data.fugue

resource_type = "MULTIPLE"

azurerm_storage_account = fugue.resources("azurerm_storage_account")

# Auxiliary function checking if allow_blob_public_access is true

not_valid(resource) {
	resource.allow_blob_public_access == true
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

policy[p] {
	resource = azurerm_storage_account[_]
	not not_valid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = azurerm_storage_account[_]
	not_valid(resource)
	p = fugue.deny_resource_with_message(resource, "Storage Accounts should not be publicly accessible.")
}
