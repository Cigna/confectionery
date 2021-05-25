package rules.public_ip

import data.fugue

resource_type = "MULTIPLE"

azurerm_public_ip = fugue.resources("azurerm_public_ip")

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

policy[p] {
	resource = azurerm_public_ip[_]
	not resource
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = azurerm_public_ip[_]
	resource
	p = fugue.deny_resource_with_message(resource, "Deny all creation of public IP addresses.")
}
