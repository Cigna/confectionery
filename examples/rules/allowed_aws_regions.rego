package rules.allowed_aws_regions

import data.fugue

resource_type = "MULTIPLE"

allowlist = [
	"us-east-1",
	"us-east-2",
]

# Obtain the region set in the provider (if possible) and check that it equals
# one of the allowed regions

# Parse the plan metadata to get the region
provider_region = ret {
	provider := fugue.plan.configuration.provider_config.aws
	ret := provider.expressions.region.constant_value
}

is_allowed_region(reg) {
	reg == allowlist[_]
}

policy[p] {
	not is_allowed_region(provider_region)
	p = fugue.missing_resource_with_message("provider", "Not an allowed region")
}
