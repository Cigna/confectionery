package rules.security_group_ingress_port_range

import data.fugue

resource_type = "MULTIPLE"

# Grab security groups from terraform template
security_group = fugue.resources("aws_security_group")

# Security groups are valid if port range is limited
is_valid_security_group(resource) {
	ingress = resource.ingress[_]

	# Check ingress protocol is not for all
	not all_ports(ingress)
}

# Security groups are also valid if ingress is not defined
is_valid_security_group(resource) {
	not resource.ingress
}

# Security groups are also valid if ingress is empty
is_valid_security_group(resource) {
	resource.ingress == []
}

all_ports(ingress) {
	ingress.protocol == "-1"
	ingress.to_port == 0
	ingress.from_port == 0
	ingress.self == false
}

all_ports(ingress) {
	ingress.protocol == "-1"
	ingress.to_port == 0
	ingress.from_port == 0
	ingress.self == true
	count(ingress.cidr_blocks) != 0
}

all_ports(ingress) {
	ingress.protocol == "-1"
	ingress.to_port == 0
	ingress.from_port == 0
	ingress.self == true
	count(ingress.ipv6_cidr_blocks) != 0
}

all_ports(ingress) {
	ingress.protocol == "-1"
	ingress.to_port == 0
	ingress.from_port == 0
	ingress.self == true
	count(ingress.prefix_list_ids) != 0
}

all_ports(ingress) {
	ingress.protocol == "-1"
	ingress.to_port == 0
	ingress.from_port == 0
	ingress.self == true
	count(ingress.security_groups) != 0
}

# Deny resource if security group does not limit port range
policy[p] {
	resource = security_group[_]
	not is_valid_security_group(resource)
	p = fugue.deny_resource_with_message(resource, "All security groups must have a limited port range for ingress traffic.")
}

# Allow resource if security group does limit port range
policy[p] {
	resource = security_group[_]
	is_valid_security_group(resource)
	p = fugue.allow_resource(resource)
}
