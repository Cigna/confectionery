# Terraform template for SQL Require Geo Redundancy
# Generated plan output used for rego test sql_require_geo_redundancy.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

# VALID 1: These primary/failover SQL servers are configured correctly for failover and are at different locations
resource "azurerm_sql_server" "primary" {
  name                         = "sql-primary"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "pa$$w0rd"
}

# VALID 1: These primary/failover SQL servers are configured correctly for failover and are at different locations
resource "azurerm_sql_server" "secondary" {
  name                         = "sql-secondary"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = "northeurope" # NOTE that this location does NOT equal the primary server location (eastus)
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "pa$$w0rd"
}

resource "azurerm_sql_failover_group" "example" {
  name                = "example-failover-group"
  resource_group_name = azurerm_sql_server.primary.resource_group_name
  server_name         = azurerm_sql_server.primary.name
  databases           = [azurerm_sql_database.db1.id]
  partner_servers {
    id = azurerm_sql_server.secondary.id
  }

  read_write_endpoint_failover_policy {
    mode          = "Automatic"
    grace_minutes = 60
  }
}

resource "azurerm_sql_database" "db1" {
  name                = "db1"
  resource_group_name = azurerm_sql_server.primary.resource_group_name
  location            = azurerm_sql_server.primary.location
  server_name         = azurerm_sql_server.primary.name
}

# INVALID : This SQL Server resource is not attached to a failover group in another Azure location
resource "azurerm_sql_server" "invalid" {
  name                         = "sql-primary-invalid"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "pa$$w0rd"
}

# INVALID 2: These primary/failover SQL servers are configured correctly but are at the same locations
resource "azurerm_sql_server" "primary_invalid_same_location" {
  name                         = "sql-primary-2"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "pa$$w0rd"
}

# INVALID 2: These primary/failover SQL servers are configured correctly but are at the same locations
resource "azurerm_sql_server" "secondary_invalid_same_location" {
  name                         = "sql-secondary-2"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location # NOTE that this location EQUALS the primary server location (eastus)
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "pa$$w0rd"
}

resource "azurerm_sql_failover_group" "example_invalid" {
  name                = "example-failover-group"
  resource_group_name = azurerm_sql_server.primary_invalid_same_location.resource_group_name
  server_name         = azurerm_sql_server.primary_invalid_same_location.name
  databases           = [azurerm_sql_database.db2.id]
  partner_servers {
    id = azurerm_sql_server.secondary_invalid_same_location.id
  }

  read_write_endpoint_failover_policy {
    mode          = "Automatic"
    grace_minutes = 60
  }
}

resource "azurerm_sql_database" "db2" {
  name                = "db2"
  resource_group_name = azurerm_sql_server.primary_invalid_same_location.resource_group_name
  location            = azurerm_sql_server.primary_invalid_same_location.location
  server_name         = azurerm_sql_server.primary_invalid_same_location.name
}