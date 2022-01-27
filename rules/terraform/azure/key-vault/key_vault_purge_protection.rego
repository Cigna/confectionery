package rules.key_vault_purge_protection

import data.fugue

resource_type = "MULTIPLE"

azurerm_key_vault = fugue.resources("azurerm_key_vault")

# Auxiliary function checking if purge_protection_enabled is true

valid(resource) {
	resource.purge_protection_enabled == true
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

policy[p] {
	resource = azurerm_key_vault[_]
	valid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = azurerm_key_vault[_]
	not valid(resource)
	p = fugue.deny_resource_with_message(resource, "Key Vaults should have purge protection enabled.")
}
