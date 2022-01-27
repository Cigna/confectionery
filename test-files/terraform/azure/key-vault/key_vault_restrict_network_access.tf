provider "azurerm" {
    version = "~>2.0"
    features {
        key_vault {
            purge_soft_delete_on_destroy = true
        }
    }
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

#VALID: Key Vault has public network access denied by default and utilize a firewall rule
resource "azurerm_key_vault" "valid" {
    name                       = "examplekeyvault-valid"
    location                   = azurerm_resource_group.example.location
    resource_group_name        = azurerm_resource_group.example.name
    tenant_id                  = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
    soft_delete_retention_days = 7
    purge_protection_enabled   = true
    sku_name                   = "standard"

    # Note that access policy is only half of the security.  You must also utilize network SG rules for specific IP ranges that need access.
    access_policy {
        tenant_id = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
        object_id = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"

        key_permissions = [
            "Get",
        ]

        secret_permissions = [
            "Get",
        ]

        storage_permissions = [
            "Get",
        ]
    }

    network_acls {
        bypass = "None"
        default_action = "Deny"
        ip_rules = ["10.0.0.0/16"] # A private IP CIDR range authorized to use this key vault
    }
}

#INVALID: Key Vault has public network access allowed by default
resource "azurerm_key_vault" "invalid" {
    name                       = "examplekeyvault-invalid"
    location                   = azurerm_resource_group.example.location
    resource_group_name        = azurerm_resource_group.example.name
    tenant_id                  = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
    soft_delete_retention_days = 7
    purge_protection_enabled   = true
    sku_name                   = "standard"

    # Note that access policy is only half of the security.  You must also utilize network SG rules for specific IP ranges that need access.
    access_policy {
        tenant_id = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"
        object_id = "791b26cb-3fdf-47c3-b85d-bd9f037e3e7f"

        key_permissions = [
            "Get",
        ]

        secret_permissions = [
            "Get",
        ]

        storage_permissions = [
            "Get",
        ]
    }

    network_acls {
        bypass = "None"
        default_action = "Allow" # This means that there is no firewall on the key vault and all IPs can access
    }
}

