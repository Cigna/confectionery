# Terraform template for Storage Account HTTPs traffic only
# Generated plan output used for rego test storage_account_https_test.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "eastus"
}

#INVALID: enable_https_traffic_only is set to false
resource "azurerm_storage_account" "invalid_https" {
  name                      = "storageaccountname"
  resource_group_name       = azurerm_resource_group.example.name
  location                  = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  allow_blob_public_access  = false
  min_tls_version           = "TLS1_2"
  enable_https_traffic_only = false

  tags = {
    environment = "staging"
  }
}

#VALID: storage accounts default enable_https_traffic_only to true
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
