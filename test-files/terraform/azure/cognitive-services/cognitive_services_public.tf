# Terraform template for Cognitive Services Public
# Generated plan output used for rego test cognitive_services_public.rego
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

# VALID: public_network_access_enabled is set to false
resource "azurerm_cognitive_account" "valid" {
  name                = "example-account-valid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  kind                = "Face"
  public_network_access_enabled  = false

  sku_name = "S0"

  tags = {
    Acceptance = "Test"
  }
}

# INVALID: local_auth_enabled is set to true
resource "azurerm_cognitive_account" "invalid" {
  name                = "example-account-invalid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  kind                = "Face"

  sku_name = "S0"

  tags = {
    Acceptance = "Test"
  }
}