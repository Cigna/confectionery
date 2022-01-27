# Terraform template for Redis Cache Require SSL Port
# Generated plan output used for rego test redis_cache_require_ssl_port.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

# VALID : Redis cache resource disables traffic over non-tls/ssl port
resource "azurerm_redis_cache" "valid" {
  name                = "example-cache-valid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
}

# INVALID : Redis cache resource enables traffic over non-tls/ssl port
resource "azurerm_redis_cache" "invalid" {
  name                = "example-cache-invalid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = true
}