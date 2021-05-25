# EC2 Instance Role: All instances should have an IAM role via an instance profile.
# This allows cloudwatch logging and ssm to work which are foundational requirements.
package rules.ec2_instance_role

import data.fugue

resource_type = "MULTIPLE"

# Grab every aws ec2 instance in template
ec2_instance = fugue.resources("aws_instance")

# EC2 is invalid if an iam_instance_profile is null
is_invalid_ec2(resource) {
	resource.iam_instance_profile == null
}

# Deny resource if ec2 instance does not have an iam instance profile
policy[p] {
	resource = ec2_instance[_]
	is_invalid_ec2(resource)
	p = fugue.deny_resource_with_message(resource, "All EC2 instances must have an iam instance profile.")
}

# Allow resource if ec2 instance does have an iam instance profile
policy[p] {
	resource = ec2_instance[_]
	not is_invalid_ec2(resource)
	p = fugue.allow_resource(resource)
}
