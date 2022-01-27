package rules.front_door_waf_enabled

import data.fugue

resource_type = "MULTIPLE"

azurerm_frontdoor = fugue.resources("azurerm_frontdoor")

# Auxiliary function checking if web application firewall policy is enabled on frontdoor

valid(resource) {
	resource.frontend_endpoint[_].web_application_firewall_policy_link_id != null
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

policy[p] {
	resource = azurerm_frontdoor[_]
	valid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = azurerm_frontdoor[_]
	not valid(resource)
	p = fugue.deny_resource_with_message(resource, "Azure Front Door should have an attached web application firewall policy.")
}
