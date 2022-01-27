package rules.cognitive_services_public

import data.fugue

resource_type = "MULTIPLE"

azurerm_cognitive_account = fugue.resources("azurerm_cognitive_account")

# Auxiliary function checking if cognitive services has public_network_access_enabled is false

valid(resource) {
	resource.public_network_access_enabled == false
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
	p = fugue.deny_resource_with_message(resource, "Azure Cognitive Services should disable public network access.")
}
