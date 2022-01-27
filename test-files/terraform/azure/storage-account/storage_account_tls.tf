# Terraform template for Storage Account TLS 1.2
# Generated plan output used for rego test storage_account_tls_test.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "eastus"
}

#INVALID: min_tls_version is set to 1.0
resource "azurerm_storage_account" "invalid_tls" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  allow_blob_public_access = false
  min_tls_version          = "TLS1_0"

  tags = {
    environment = "staging"
  }
}

#VALID: min_tls_version is set to 1.2
resource "azurerm_storage_account" "valid" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_2"


  tags = {
    environment = "staging"
  }
}
