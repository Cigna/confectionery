# Terraform template for MySQL Require Geo Redundancy
# Generated plan output used for rego test mysql_require_geo_redundancy.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

# VALID : MySQL Server resource utilizes geo redundancy by setting geo_redundant_backup_enabled to true
resource "azurerm_mysql_server" "valid" {
  name                = "example-mysqlserver-1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mysqladminun"
  administrator_login_password = "H@Sh1CoR3!"

  # Geo-redundancy is only avaialable for General purpose / memory optimized database SKUs (start with GP or M)
  # Geo-redundancy is disable for basic SKUs
  sku_name   = "GP_Gen5_2"
  storage_mb = 5120
  version    = "5.7"

  auto_grow_enabled                 = true
  backup_retention_days             = 7
  geo_redundant_backup_enabled      = true # <--
  infrastructure_encryption_enabled = false
  public_network_access_enabled     = false
  ssl_enforcement_enabled           = true
  ssl_minimal_tls_version_enforced  = "TLS1_2"
}

# INVALID : MySQL server resource does not utilize geo redundancy by setting geo_redundant_backup_enabled to false
resource "azurerm_mysql_server" "invalid" {
  name                = "example-mysqlserver-2"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mysqladminun"
  administrator_login_password = "H@Sh1CoR3!"

  # Geo-redundancy is only avaialable for General purpose / memory optimized database SKUs (start with GP or M)
  # Geo-redundancy is disable for basic SKUs
  sku_name   = "GP_Gen5_2"
  storage_mb = 5120
  version    = "5.7"

  auto_grow_enabled                 = true
  backup_retention_days             = 7
  geo_redundant_backup_enabled      = false # <--
  infrastructure_encryption_enabled = false
  public_network_access_enabled     = false
  ssl_enforcement_enabled           = true
  ssl_minimal_tls_version_enforced  = "TLS1_2"
}

# VALID : MySQL server resource is a basic tier SKU so the geo redundancy feature is not available for use
resource "azurerm_mysql_server" "valid_basic_sku_not_compatible" {
  name                = "example-mysqlserver-3"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mysqladminun"
  administrator_login_password = "H@Sh1CoR3!"

  # Geo-redundancy is only avaialable for General purpose / memory optimized database SKUs (start with GP or M)
  # Geo-redundancy is disable for basic SKUs
  sku_name   = "B_Gen5_1"
  storage_mb = 5120
  version    = "5.7"

  auto_grow_enabled                 = true
  backup_retention_days             = 7
  geo_redundant_backup_enabled      = false # <--
  infrastructure_encryption_enabled = false
  public_network_access_enabled     = false
  ssl_enforcement_enabled           = true
  ssl_minimal_tls_version_enforced  = "TLS1_2"
}