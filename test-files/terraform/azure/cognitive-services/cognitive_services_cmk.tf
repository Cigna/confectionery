# Terraform template for Cognitive Services Public
# Generated plan output used for rego test cognitive_services_public.rego
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

# VALID: has an associated azurerm_cognitive_account_customer_managed_key
resource "azurerm_cognitive_account" "valid" {
  name                  = "example-account-valid"
  location              = azurerm_resource_group.example.location
  resource_group_name   = azurerm_resource_group.example.name
  kind                  = "Face"
  sku_name              = "E0"
  custom_subdomain_name = "example-account"
  identity {
    type         = "SystemAssigned, UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.example.id]
  }
}

resource "azurerm_cognitive_account_customer_managed_key" "example" {
  cognitive_account_id = azurerm_cognitive_account.valid.id
  key_vault_key_id     = azurerm_key_vault_key.example.id
  identity_client_id   = azurerm_user_assigned_identity.example.client_id
}

# INVALID: no associated azurerm_cognitive_account_customer_managed_key
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


resource "azurerm_key_vault" "example" {
  name                     = "example-vault"
  location                 = azurerm_resource_group.example.location
  resource_group_name      = azurerm_resource_group.example.name
  tenant_id                = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
  sku_name                 = "standard"
  soft_delete_enabled      = true
  purge_protection_enabled = true

  access_policy {
    tenant_id = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
    object_id = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
    key_permissions = [
      "Get", "Create", "List", "Restore", "Recover", "UnwrapKey", "WrapKey", "Purge", "Encrypt", "Decrypt", "Sign", "Verify"
    ]
    secret_permissions = [
      "Get",
    ]
  }
}

resource "azurerm_key_vault_key" "example" {
  name         = "example-key"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]
}

resource "azurerm_user_assigned_identity" "example" {
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  name                = "example-identity"
}