# Terraform template for NAT Gateway Creation
# Generated plan output used for rego test nat_gateway_test.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}


resource "azurerm_resource_group" "example" {
  name     = "nat-gateway-example-rg"
  location = "eastus2"
}

# INVALID: cannot create NAT gateways
resource "azurerm_nat_gateway" "invalid_nat_gateway" {
  name                    = "nat-Gateway"
  location                = azurerm_resource_group.example.location
  resource_group_name     = azurerm_resource_group.example.name
  sku_name                = "Standard"
  idle_timeout_in_minutes = 10
  zones                   = ["1"]
}