# Terraform template for Public Storage Account Creation
# Generated plan output used for rego test storage_account_public_test.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "eastus"
}

#INVALID: Setting a Storage Account Attribute allow_blob_public_access to TRUE making the Storage Account accessible to the public.
resource "azurerm_storage_account" "invalid" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  allow_blob_public_access = true

  tags = {
    environment = "staging"
  }
}

#VALID: Creating a Storage Account NOT publicly accessible. (Default behavior sets to false)
resource "azurerm_storage_account" "valid" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"


  tags = {
    environment = "staging"
  }
}
