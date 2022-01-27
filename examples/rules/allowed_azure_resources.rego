package rules.allowed_azure_resources

# azurerm Advanced rules typically use functions from the `fugue` library.
import data.fugue

# We mark an advanced rule by setting `resource_type` to `MULTIPLE`.
resource_type = "MULTIPLE"

# Sample list of allowed terraform prefixes
allowlist = [
	"azurerm_active_directory_domain_service",
	"azurerm_advanced_threat_protection",
	"azurerm_advisor_recommendations",
	"azurerm_analysis_services_server",
	"azurerm_api_management",
	"azurerm_app_",
	"azurerm_application",
	"azurerm_attestation",
	"azurerm_authorization",
]

#check if resource is allowed
is_allowed_resource(resource) {
	startswith(resource._type, allowlist[_])
}

#allow resources that are in allowed resource type list
policy[p] {
	resource = input.resources[_]
	startswith(resource._type, "azurerm")
	is_allowed_resource(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = input.resources[_]
	startswith(resource._type, "azurerm")
	not is_allowed_resource(resource)
	p = fugue.deny_resource_with_message(resource, "This is not a resource from an allowed Azurerm service.")
}
