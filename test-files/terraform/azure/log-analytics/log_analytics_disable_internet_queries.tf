# Terraform template for Log Analytics Disable Internet Queries
# Generated plan output used for rego test log_analytics_disable_internet_queries.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

# VALID : the Log Analytics workspace does NOT allow Internet queries with internet_query_enabled set to false
resource "azurerm_log_analytics_workspace" "valid" {
  name                = "acctest-01-valid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  internet_query_enabled = false
}

# INVALID : the Log Analytics workspace allows Internet queries with internet_query_enabled set to true
resource "azurerm_log_analytics_workspace" "invalid" {
  name                = "acctest-01-invalid"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  internet_query_enabled = true
}