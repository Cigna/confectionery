# Terraform template for Virtual Machine Auto Update
# Generated plan output used for rego test virtual_machine_auto_update.rego
provider "azurerm" {
  version = "~>2.0"
  features {}
}

resource "azurerm_resource_group" "example" {
  name     = "terraform-example-resources"
  location = "eastus"
}

resource "azurerm_virtual_network" "example" {
  name                = "example-network"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

resource "azurerm_subnet" "example" {
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.example.name
  virtual_network_name = azurerm_virtual_network.example.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_interface" "example" {
  name                = "example-nic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.example.id
    private_ip_address_allocation = "Dynamic"
  }
}

# ========== WINDOWS ============

resource "azurerm_windows_virtual_machine" "bad_vm_update_config" {
  name                = "example-machine"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_D4_v4" 
  admin_username      = "adminuser"
  admin_password      = "P@$$w0rd1234!"
  enable_automatic_updates = false # This should always be true
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]
  tags = {
      Exception = "DenyGoldenImage"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter"
    version   = "latest"
  }
}

# This one leverages auto update as the image is not supported
resource "azurerm_windows_virtual_machine" "valid_vm_update_config_1" {
  name                = "example-machine"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_D4_v4" 
  admin_username      = "adminuser"
  admin_password      = "P@$$w0rd1234!"
  enable_automatic_updates = true # True as expected
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]
  tags = {
      Exception = "DenyGoldenImage"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter"
    version   = "latest"
  }
}

# This one leverages 'AutomaticByPlatform' updates as the image is supported
resource "azurerm_windows_virtual_machine" "valid_vm_update_config_2" {
  name                = "example-machine"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_D4_v4" 
  admin_username      = "adminuser"
  admin_password      = "P@$$w0rd1234!"
  enable_automatic_updates = false # We aren't leveraging this feature because we can use the preferred 'AutomaticByPlatform' patch orchestration
  patch_mode = "AutomaticByPlatform"
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]
  tags = {
      Exception = "DenyGoldenImage"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2016-Datacenter"
    version   = "latest"
  }
}

# ========== LINUX ============
# NOTE that Linux does not have a built-in auto update feature, it only has one for select Linux images

resource "azurerm_linux_virtual_machine" "valid_vm_update_config" {
  name                = "example-machine"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_D4_v4" 
  admin_username      = "adminuser"
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]

  tags = {
      Exception = "DenyGoldenImage"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  # One of the supported Linux images for automatic updates
  # https://docs.microsoft.com/en-us/azure/virtual-machines/automatic-vm-guest-patching#supported-os-images
  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
  patch_mode = "AutomaticByPlatform"
}

resource "azurerm_linux_virtual_machine" "bad_vm_update_config" {
  name                = "example-machine"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_D4_v4" 
  admin_username      = "adminuser"
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]
  tags = {
      Exception = "DenyGoldenImage"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "16.04-LTS" # This is an unsupported Linux image for auto updates
    version   = "latest"
  }
  # If you don't have a support image, then you must use the "ImageDefault" patch mode setting
  # This effectively disables auto updating, just uses the version listed in the Linux image
  # https://docs.microsoft.com/en-us/azure/virtual-machines/automatic-vm-guest-patching#patch-orchestration-modes
  patch_mode = "ImageDefault"
}
