# Terraform template for MariaDB Require Geo Redundancy
# Generated plan output used for rego test maria_db_require_geo_redundancy.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

# VALID : MariaDB resource utilizes geo redundancy by setting geo_redundant_backup_enabled to true
resource "azurerm_mariadb_server" "valid" {
  name                = "example-mariadb-server-1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = "H@Sh1CoR3!"

  # Geo-redundancy is only avaialable for General purpose / memory optimized database SKUs (start with GP or M)
  # Geo-redundancy is disable for basic SKUs
  sku_name   = "GP_Gen5_2"
  storage_mb = 5120
  version    = "10.2"

  auto_grow_enabled             = true
  backup_retention_days         = 7
  geo_redundant_backup_enabled  = true
  public_network_access_enabled = false
  ssl_enforcement_enabled       = true
}

# INVALID : MariaDB resource does not utilize geo redundancy by setting geo_redundant_backup_enabled to false
resource "azurerm_mariadb_server" "invalid" {
  name                = "example-mariadb-server-2"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = "H@Sh1CoR3!"

  # Geo-redundancy is only avaialable for General purpose / memory optimized database SKUs (start with GP or M)
  # Geo-redundancy is disable for basic SKUs
  sku_name   = "GP_Gen5_2"
  storage_mb = 5120
  version    = "10.2"

  auto_grow_enabled             = true
  backup_retention_days         = 7
  geo_redundant_backup_enabled  = false # <--
  public_network_access_enabled = false
  ssl_enforcement_enabled       = true
}

# VALID : MariaDB resource is a basic tier SKU so the geo redundancy feature is not available for use
resource "azurerm_mariadb_server" "valid_basic_sku_not_compatible" {
  name                = "example-mariadb-server-3"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  administrator_login          = "mariadbadmin"
  administrator_login_password = "H@Sh1CoR3!"

  # Geo-redundancy is only avaialable for General purpose / memory optimized database SKUs (start with GP or M)
  # Geo-redundancy is disable for basic SKUs
  sku_name   = "B_Gen5_1"
  storage_mb = 5120
  version    = "10.2"

  auto_grow_enabled             = true
  backup_retention_days         = 7
  geo_redundant_backup_enabled  = false
  public_network_access_enabled = false
  ssl_enforcement_enabled       = true
}