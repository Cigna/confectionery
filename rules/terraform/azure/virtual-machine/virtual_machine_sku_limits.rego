# Virtual Machine SKU Limits: Deny VM resources that use a restricted SKU (instance size)
# This rule denies VM resources from being created that utilize a restricted SKU (size) for a given Windows or Linux VM
package rules.virtual_machine_sku_limits

import data.fugue

resource_type = "MULTIPLE"

windows_vm = fugue.resources("azurerm_windows_virtual_machine")

linux_vm = fugue.resources("azurerm_linux_virtual_machine")

# allowed list of VM sizes
valid_vm_sizes = [
	"Standard_A1_v2",
	"Standard_B1s",
	"Standard_D2_v3",
	"Standard_D3_v2",
	"Standard_D4s_v4",
	"Standard_DC1s_v2",
	"Standard_DS4_v2",
	"Standard_E4-2as_v4",
	"Standard_F1",
	"Standard_F8s_v2",
	"Standard_A1",
	"Standard_B2ms",
	"Standard_D2_v4",
	"Standard_D4_v2",
	"Standard_D8_v3",
	"Standard_DC2s_v2",
	"Standard_E2_v3",
	"Standard_E4-2ds_v4",
	"Standard_F16s_v2",
	"Standard_F8s",
	"Standard_A2_v2",
	"Standard_B2s",
	"Standard_D2",
	"Standard_D4_v3",
	"Standard_D8_v4",
	"Standard_DS1_v2",
	"Standard_E2_v4",
	"Standard_E4-2s_v4",
	"Standard_F1s",
	"Standard_NV4as_v4",
	"Standard_A2m_v2",
	"Standard_B4hms",
	"Standard_D2a_v4",
	"Standard_D4_v4",
	"Standard_D8a_v4",
	"Standard_DS11_v2",
	"Standard_E2a_v4",
	"Standard_E4a_v4",
	"Standard_F2",
	"Standard_NV8as_v4",
	"Standard_A4_v2",
	"Standard_B4ms",
	"Standard_D2as_v4",
	"Standard_D4a_v4",
	"Standard_D8as_v4",
	"Standard_DS11-1_v2",
	"Standard_E2as_v4",
	"Standard_E4d_v4",
	"Standard_F2s_v2",
	"Standard_A4m_v2",
	"Standard_B8ms",
	"Standard_D2d_v4",
	"Standard_D4hs_v3",
	"Standard_D8d_v4",
	"Standard_DS12_v2",
	"Standard_E2d_v4",
	"Standard_E8_v3",
	"Standard_F2s",
	"Standard_A8_v2",
	"Standard_D1_v2",
	"Standard_D2ds_v4",
	"Standard_D4as_v4",
	"Standard_D8ds_v4",
	"Standard_DS12-1_v2",
	"Standard_E2ds_v4",
	"Standard_E8_v4",
	"Standard_F4",
	"Standard_B12ms",
	"Standard_D11_v2",
	"Standard_D2hs_v3",
	"Standard_D4d_v4",
	"Standard_D8hs_v3",
	"Standard_DS12-2_v2",
	"Standard_E2s_v4",
	"Standard_E8-2as_v4",
	"Standard_F4s_v2",
	"Standard_B1ls",
	"Standard_D12_v2",
	"Standard_D2s_v3",
	"Standard_D4ds_v4",
	"Standard_D8s_v3",
	"Standard_DS2_v2",
	"Standard_E4_v3",
	"Standard_E8a_v4",
	"Standard_F4s",
	"Standard_B1ms",
	"Standard_D2_v2",
	"Standard_D2s_v4",
	"Standard_D4s_v3",
	"Standard_D8s_v4",
	"Standard_DS3_v2",
	"Standard_E4_v4",
	"Standard_E8s_v3",
	"Standard_F8",
]

# Auxiliary function checking if a restricted VM SKU (size) is used
uses_valid_sku(resource) {
	# Get array of all valid sizes that match the curr resource size
	uses_valid_size := [valid_size | valid_size = valid_vm_sizes[_]; resource.size == valid_size]

	# If this is not 0 then the sku size is valid
	count(uses_valid_size) != 0
}

# WINDOWS VM SKU policies
policy[p] {
	windows = windows_vm[_]
	uses_valid_sku(windows)
	p = fugue.allow_resource(windows)
}

policy[p] {
	windows = windows_vm[_]
	not uses_valid_sku(windows)
	p = fugue.deny_resource_with_message(windows, "Windows virtual machines must utilize one of the listed approved SKUs (sizes) for cost savings. ")
}

# LINUX VM SKU policies
policy[p] {
	linux = linux_vm[_]
	uses_valid_sku(linux)
	p = fugue.allow_resource(linux)
}

policy[p] {
	linux = linux_vm[_]
	not uses_valid_sku(linux)
	p = fugue.deny_resource_with_message(linux, "Linux virtual machines must utilize one of the listed approved SKUs (sizes) for cost savings. ")
}
