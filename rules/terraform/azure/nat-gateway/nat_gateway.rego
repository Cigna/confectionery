package rules.nat_gateway

import data.fugue

resource_type = "MULTIPLE"

azurerm_nat_gateway = fugue.resources("azurerm_nat_gateway")

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

policy[p] {
	resource = azurerm_nat_gateway[_]
	not resource
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = azurerm_nat_gateway[_]
	resource
	p = fugue.deny_resource_with_message(resource, "Deny all creation of NAT gateways.")
}
