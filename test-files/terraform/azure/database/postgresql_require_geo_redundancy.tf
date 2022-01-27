# Terraform template for PostgreSQL Require Geo Redundancy
# Generated plan output used for rego test postgresql_require_geo_redundancy.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

# VALID : PostgreSQL Server resource utilizes geo redundancy by setting geo_redundant_backup_enabled to true
resource "azurerm_postgresql_server" "valid" {
  name                = "example-psqlserver-1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladmin"
  administrator_login_password = "H@Sh1CoR3!"

  # Geo-redundancy is only avaialable for General purpose / memory optimized database SKUs (start with GP or M)
  # Geo-redundancy is disabled for basic SKUs
  sku_name   = "GP_Gen5_2"
  version    = "9.6"
  storage_mb = 640000

  backup_retention_days        = 7
  geo_redundant_backup_enabled = true # <--
  auto_grow_enabled            = true

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}

# INVALID : PostgreSQL server resource does not utilize geo redundancy by setting geo_redundant_backup_enabled to false
resource "azurerm_postgresql_server" "invalid" {
  name                = "example-psqlserver-2"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladmin"
  administrator_login_password = "H@Sh1CoR3!"

  # Geo-redundancy is only avaialable for General purpose / memory optimized database SKUs (start with GP or M)
  # Geo-redundancy is disabled for basic SKUs
  sku_name   = "GP_Gen5_2"
  version    = "9.6"
  storage_mb = 640000

  backup_retention_days        = 7
  geo_redundant_backup_enabled = false # <--
  auto_grow_enabled            = true

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}

# VALID : PostgreSQL server resource is a basic tier SKU so the geo redundancy feature is not available for use
resource "azurerm_postgresql_server" "valid_basic_sku_not_compatible" {
  name                = "example-psqlserver-3"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "psqladmin"
  administrator_login_password = "H@Sh1CoR3!"

  # Geo-redundancy is only avaialable for General purpose / memory optimized database SKUs (start with GP or M)
  # Geo-redundancy is disabled for basic SKUs
  sku_name   = "B_Gen5_1"
  version    = "9.6"
  storage_mb = 640000

  backup_retention_days        = 7
  geo_redundant_backup_enabled = false # <--
  auto_grow_enabled            = true

  public_network_access_enabled    = false
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}