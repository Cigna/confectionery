package rules.cognitive_services_cmk

import data.fugue

resource_type = "MULTIPLE"

azurerm_cognitive_account = fugue.resources("azurerm_cognitive_account")

azurerm_cognitive_account_customer_managed_key = fugue.resources("azurerm_cognitive_account_customer_managed_key")

# Auxiliary function checking if cognitive services has an associated cmk

valid(resource) {
	azurerm_cognitive_account_customer_managed_key[_].cognitive_account_id == resource.id
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

policy[p] {
	resource = azurerm_cognitive_account[_]
	valid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = azurerm_cognitive_account[_]
	not valid(resource)
	p = fugue.deny_resource_with_message(resource, "Azure Cognitive Services should be encrypted with customer-managed-key.")
}
