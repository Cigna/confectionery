# Terraform template for Logic App TLS 1.2 Requirement
# Generated plan output used for rego test logic_app_tls_requirement.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

resource "azurerm_storage_account" "example" {
  name                     = "functionsapptestsa"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_app_service_plan" "example" {
  name                = "azure-functions-test-service-plan"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  kind                = "Linux"
  reserved            = true

  sku {
    tier = "ElasticPremium"
    size = "EP1"
  }
}

# VALID: Standard logic app hosted on standard/single tenant host requires TLS version 1.2 or greater
resource "azurerm_logic_app_standard" "valid" {
  name                       = "test-azure-functions-valid"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  site_config {
      min_tls_version = "1.2"
  }
}

# INVALID: Standard logic app hosted on standard/single tenant host does not require TLS version 1.2 or greater.  In this case, it uses TLS 1.0
resource "azurerm_logic_app_standard" "invalid" {
  name                       = "test-azure-functions-invalid"
  location                   = azurerm_resource_group.example.location
  resource_group_name        = azurerm_resource_group.example.name
  app_service_plan_id        = azurerm_app_service_plan.example.id
  storage_account_name       = azurerm_storage_account.example.name
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  site_config {
      min_tls_version = "1.0"
  }
}