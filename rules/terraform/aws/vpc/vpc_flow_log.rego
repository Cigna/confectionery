package rules.vpc_flow_log

import data.fugue

resource_type = "MULTIPLE"

controls = {
	"CIS_2-9",
	"NIST-800-53_AC-4",
	"NIST-800-53_SC-7a",
	"NIST-800-53_SI-4a.2",
	"REGULA_R00003",
}

# VPC flow logging should be enabled when VPCs are created. AWS VPC Flow Logs provide visibility into network traffic that 
# traverses the AWS VPC. Users can use the flow logs to detect anomalous traffic or insight during security workflows.

# every flow log in the template
flow_logs = fugue.resources("aws_flow_log")

# every VPC in the template
vpcs = fugue.resources("aws_vpc")

# VPC is valid if there is an associated flow log
is_valid_vpc(vpc) {
	# Compare arn with vpc_id (Added for golden vpc)
	arn_array := split(vpc.arn, "/")
	vpc_id := arn_array[count(arn_array) - 1]
	vpc_id == flow_logs[_].vpc_id
}

is_valid_vpc(vpc) {
	# Compare vpc id with flow_logs associated vpc id
	vpc.id == flow_logs[_].vpc_id
}

policy[p] {
	resource = vpcs[_]
	not is_valid_vpc(resource)
	p = fugue.deny_resource_with_message(resource, "All vpcs must have flow logs enabled.")
}

policy[p] {
	resource = vpcs[_]
	is_valid_vpc(resource)
	p = fugue.allow_resource(resource)
}
