# Terraform template for Databricks Require CMK
# Generated plan output used for rego test databricks_require_cmk.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "eastus"
}

# VALID : Databricks workspace has customer_managed_key_enabled set to true and the SKU is premium, which is required to use CMKs to encrypt the databrick data plane
resource "azurerm_databricks_workspace" "valid" {
  name                = "databricks-test-1"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  # NOTE you can only enable customer_managed_key_enabled when the SKU is premium (not allowed with standard or trial)
  sku                 = "premium"
  customer_managed_key_enabled = true # <-- This also requires a azurerm
  tags = {
    Environment = "Production"
  }
}

### === EXTRA CMK RELATED RESOURCES ===

resource "azurerm_databricks_workspace_customer_managed_key" "example" {
  depends_on = [azurerm_key_vault_access_policy.databricks]

  workspace_id     = azurerm_databricks_workspace.valid.id
  key_vault_key_id = azurerm_key_vault_key.example.id
}

resource "azurerm_key_vault" "example" {
  name                = "examplekeyvault"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "premium" 

  purge_protection_enabled = true
}

resource "azurerm_key_vault_key" "example" {
  depends_on = [azurerm_key_vault_access_policy.terraform]

  name         = "example-certificate"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}

resource "azurerm_key_vault_access_policy" "terraform" {
  key_vault_id = azurerm_key_vault.example.id
  tenant_id    = azurerm_key_vault.example.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  key_permissions = [
    "get",
    "list",
    "create",
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
    "delete",
    "restore",
    "recover",
    "update",
    "purge",
  ]
}

resource "azurerm_key_vault_access_policy" "databricks" {
  depends_on = [azurerm_databricks_workspace.valid]

  key_vault_id = azurerm_key_vault.example.id
  tenant_id    = azurerm_databricks_workspace.valid.storage_account_identity.0.tenant_id
  object_id    = azurerm_databricks_workspace.valid.storage_account_identity.0.principal_id

  key_permissions = [
    "get",
    "unwrapKey",
    "wrapKey",
  ]
}

# ==================================

# VALID : Databricks workspace has customer_managed_key_enabled set to false, but the SKU is NOT premium, which is required to use CMKs to encrypt the databrick data plane
resource "azurerm_databricks_workspace" "valid_feature_not_available_with_sku" {
  name                = "databricks-test-2"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  # NOTE you can only enable customer_managed_key_enabled when the SKU is premium (not allowed with standard or trial)
  sku                 = "standard"
  customer_managed_key_enabled = false 
  tags = {
    Environment = "Production"
  }
}

# INVALID : Databricks workspace has customer_managed_key_enabled set to false and the SKU is premium (so it can uses a CMK)
resource "azurerm_databricks_workspace" "invalid" {
  name                = "databricks-test-3"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  # NOTE you can only enable customer_managed_key_enabled when the SKU is premium (not allowed with standard or trial)
  sku                 = "premium"
  customer_managed_key_enabled = false 
  tags = {
    Environment = "Production"
  }
}