package rules.front_door_https

import data.fugue

resource_type = "MULTIPLE"

azurerm_frontdoor = fugue.resources("azurerm_frontdoor")

# Auxiliary function checking if frontdoor accepts HTTPS only or redirect HTTP to HTTPS

valid(resource) {
	some i
	rule := resource.routing_rule[i]
	count(rule.accepted_protocols) == 1 # checks if there is only one accepted protocol
	rule.accepted_protocols[_] == "Https" # Https only
	rule.forwarding_configuration[_].forwarding_protocol == "HttpsOnly" # forwarding configuration to HttpsOnly
}

valid(resource) {
	some j
	rule := resource.routing_rule[j]
	rule.accepted_protocols[_] == "Http" # checks if http is atleast in accepted protocols
	rule.redirect_configuration[_].redirect_protocol == "HttpsOnly" # redirects http to HttpsOnly
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
	p = fugue.deny_resource_with_message(resource, "Azure Front Door should only allow HTTPS or redirect HTTP to HTTPS.")
}
