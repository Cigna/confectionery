# Virtual Machine Auto Update: Deny VM resources that do not leverage automatic updates
# This rule denies VM resources from being created that do not utilize the required patching strategy for a given Windows or Linux VM
package rules.virtual_machine_auto_update

import data.fugue

resource_type = "MULTIPLE"

windows_vm = fugue.resources("azurerm_windows_virtual_machine")

linux_vm = fugue.resources("azurerm_linux_virtual_machine")

# If the Windows VM can use the 'AutomaticByPlatform' patch mode, it must
uses_auto_update_windows(resource) {
	resource.patch_mode == "AutomaticByPlatform"
}

# If the Windows VM can't use the 'AutomaticByPlatform' patch mode, it must at least use 'enable_automatic_updates' 
uses_auto_update_windows(resource) {
	resource.enable_automatic_updates
}

uses_auto_update_linux(resource) {
	resource.patch_mode == "AutomaticByPlatform"
}

# WINDOWS VM auto update policies
policy[p] {
	windows = windows_vm[_]
	uses_auto_update_windows(windows)
	p = fugue.allow_resource(windows)
}

policy[p] {
	windows = windows_vm[_]
	not uses_auto_update_windows(windows)
	msg = sprintf("Windows virtual machines must utilize the 'AutomaticByPlatform' patch mode.  Check to see if your image '%s' is on of the supported Windows images: https://docs.microsoft.com/en-us/azure/virtual-machines/automatic-vm-guest-patching#supported-os-images.  If not you must leverage the 'enable_automatic_updates' feature in your Windows VM.", [windows.source_image_reference])
	p = fugue.deny_resource_with_message(windows, msg)
}

# LINUX VM auto update policies
policy[p] {
	linux = linux_vm[_]
	uses_auto_update_linux(linux)
	p = fugue.allow_resource(linux)
}

policy[p] {
	linux = linux_vm[_]
	not uses_auto_update_linux(linux)
	msg = sprintf("Linux virtual machines must utilize the 'AutomaticByPlatform' patch mode.  Check to see if your image '%s' is on of the supported auto update Linux images: https://docs.microsoft.com/en-us/azure/virtual-machines/automatic-vm-guest-patching#supported-os-images", [linux.source_image_reference])
	p = fugue.deny_resource_with_message(linux, msg)
}
