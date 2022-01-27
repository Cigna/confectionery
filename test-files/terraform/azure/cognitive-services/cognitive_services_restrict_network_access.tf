# Terraform template for Cognitive Services Restrict Network Access
# Generated plan output used for rego test cognitive_services_restrict_network_access.rego
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

# VALID: network acls default action is deny
resource "azurerm_cognitive_account" "valid" {
  name                = "example-account-valid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  kind                = "Face"
  custom_subdomain_name = "example-account-valid"

  sku_name = "S0"

  tags = {
    Acceptance = "Test"
  }
  network_acls {
    default_action = "Deny"
    ip_rules = ["10.0.0.0/16"] # A private IP CIDR range authorized to use this cognitive services account
  }
}

# INVALID: network acls default action is allow
resource "azurerm_cognitive_account" "invalid" {
  name                = "example-account-invalid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  kind                = "Face"
  custom_subdomain_name = "example-account-invalid"

  sku_name = "S0"

  tags = {
    Acceptance = "Test"
  }
  network_acls {
    default_action = "Allow" # This means that there is no firewall on the cognitive services account and all IPs can access
  }
}
