# Terraform template for Redis Cache Restrict Public Access
# Generated plan output used for rego test redis_cache_restrict_public_access.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

# VALID : Redis cache resource disables public network access
resource "azurerm_redis_cache" "valid" {
  name                = "example-cache-valid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
  public_network_access_enabled = false
}

# INVALID : Redis cache does NOT disable public network access
resource "azurerm_redis_cache" "invalid" {
  name                = "example-cache-invalid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
  public_network_access_enabled = true
}