# Terraform template for Key Vault Purge Protection
# Generated plan output used for rego test key_vault_purge_protection_test.rego
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "East Us"
}

#VALID: purge_protection_enabled set to true
resource "azurerm_key_vault" "valid" {
  name                       = "examplekeyvault"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  tenant_id                  = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
  soft_delete_retention_days = 7
  purge_protection_enabled   = true
  sku_name                   = "standard"
}

#INVALID: purge_protection_enabled must be true
resource "azurerm_key_vault" "invalid_purge_protection" {
  name                       = "examplekeyvault"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  tenant_id                  = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  sku_name                   = "standard"
}
