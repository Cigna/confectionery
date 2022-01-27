package rules.cognitive_services_restrict_network_access

import data.fugue

resource_type = "MULTIPLE"

azurerm_cognitive_account = fugue.resources("azurerm_cognitive_account")

valid(resource) {
	resource.network_acls[_].default_action == "Deny"
}

policy[p] {
	resource = azurerm_cognitive_account[_]
	valid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = azurerm_cognitive_account[_]
	not valid(resource)
	p = fugue.deny_resource_with_message(resource, "Cognitive Services should have public network access denied and utilize firewall rules.  See https://docs.microsoft.com/en-us/azure/cognitive-services/cognitive-services-virtual-networks?tabs=portal#change-the-default-network-access-rule")
}
