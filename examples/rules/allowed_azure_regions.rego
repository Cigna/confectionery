package rules.allowed_azure_regions

import data.fugue

resource_type = "MULTIPLE"

# list of azure regions allowed
# azure terraform provider normalizes locations to be lowercase and no spaces after plan
allowlist = [
	"eastus",
	"eastus2",
]

# resource types that do not have location fields
exclude_resource_types = ["azurerm_resource_group"]

# check if resource is located in allowed regions
is_allowed_region(resource) {
	allowlist[_] == resource.location
}

# allow resources that are in allowed locations & not in excluded resource types
policy[p] {
	resource = input.resources[_]
	resource._type != exclude_resource_types[_]
	startswith(resource._type, "azurerm")
	is_allowed_region(resource)
	p = fugue.allow_resource(resource)
}

# 
policy[p] {
	resource = input.resources[_]
	resource._type != exclude_resource_types[_]
	startswith(resource._type, "azurerm")
	not is_allowed_region(resource)
	msg = sprintf("'%s' is not a valid azure location.", [resource.location])
	p = fugue.deny_resource_with_message(resource, msg)
}
