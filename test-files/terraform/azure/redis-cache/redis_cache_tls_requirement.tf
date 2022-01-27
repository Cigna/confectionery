# Terraform template for Redis Cache TLS Requirement
# Generated plan output used for rego test redis_cache_tls_requirement.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

# VALID : Redis cache resource uses the required minimum TLS version of 1.2 or greater
resource "azurerm_redis_cache" "valid" {
  name                = "example-cache-valid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"
}

# INVALID : Redis cache resource uses the TLS version of 1.0
resource "azurerm_redis_cache" "invalid" {
  name                = "example-cache-invalid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
  minimum_tls_version = "1.0"
}