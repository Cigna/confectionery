# Terraform template for Key Vault RBAC Authorization
# Generated plan output used for rego test key_vault_rbac_authorization_test.rego
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "East Us"
}

#VALID: enable_rbac_authorization set to true
resource "azurerm_key_vault" "valid" {
  name                       = "examplekeyvault"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  tenant_id                  = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
  soft_delete_retention_days = 7
  enable_rbac_authorization  = true
  sku_name                   = "standard"
}

#INVALID: enable_rbac_authorization must be true
resource "azurerm_key_vault" "invalid_rbac_authorization" {
  name                       = "examplekeyvault"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  tenant_id                  = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
  soft_delete_retention_days = 7
  enable_rbac_authorization  = false
  sku_name                   = "standard"
}
