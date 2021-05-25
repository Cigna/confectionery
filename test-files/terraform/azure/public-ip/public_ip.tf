# Terraform template for Public IP Creation
# Generated plan output used for rego test public_ip_test.rego
provider "azurerm" {
    version = "~>2.0"
    features {}
}

# Create a resource group if it doesn't exist
resource "azurerm_resource_group" "myterraformgroup" {
    name     = "myResourceGroup"
    location = "eastus"

    tags = {
        environment = "Terraform Demo"
    }
}

# INVALID : cannot create public ips
resource "azurerm_public_ip" "invalid_ip" {
    name                         = "myPublicIP"
    location                     = "eastus"
    resource_group_name          = azurerm_resource_group.myterraformgroup.name
    allocation_method            = "Dynamic"

    tags = {
        environment = "Terraform Demo"
    }
}