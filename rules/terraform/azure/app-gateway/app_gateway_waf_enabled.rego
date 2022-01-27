package rules.application_gateway_waf_enabled

import data.fugue

resource_type = "MULTIPLE"

azurerm_application_gateway = fugue.resources("azurerm_application_gateway")

# Auxiliary function checking if web application firewall policy is enabled on application gateway

valid(resource) {
	resource.firewall_policy_id != null
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

policy[p] {
	resource = azurerm_application_gateway[_]
	valid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = azurerm_application_gateway[_]
	not valid(resource)
	p = fugue.deny_resource_with_message(resource, "Application gateway should have an attached web application firewall policy.")
}
