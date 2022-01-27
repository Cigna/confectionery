# Key Vault Restrict Network Access: Deny Key vault resources that allow public IP access
# This rule denies Key Vault resources from being created that do not deny all public IPs by default in their configured network ACL
package rules.key_vault_restrict_network_access

import data.fugue

resource_type = "MULTIPLE"

azurerm_key_vault = fugue.resources("azurerm_key_vault")

key_vault_network_firewall_on(resource) {
	# Note that attribute when set to "Deny" activates the key vault firewall so all public access is denied
	# https://docs.microsoft.com/en-us/azure/key-vault/general/network-security
	resource.network_acls[_].default_action == "Deny"
}

policy[p] {
	resource = azurerm_key_vault[_]
	key_vault_network_firewall_on(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = azurerm_key_vault[_]
	not key_vault_network_firewall_on(resource)
	p = fugue.deny_resource_with_message(resource, "Key Vaults should have public network access denied and utilize firewall rules.  See https://docs.microsoft.com/en-us/azure/key-vault/general/network-security")
}
