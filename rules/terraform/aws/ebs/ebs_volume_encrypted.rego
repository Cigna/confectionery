#EBS Volume Encrypted: EBS Volumes must be encrypted
#This rule denies EBS Volumes that are not utilizing encryption
package rules.ebs_volume_encrypted

resource_type = "aws_ebs_volume"

controls = {"NIST-800-53_SC-13"}

# Deny EBS Volume resources that do not have encryption enabled
deny[msg] {
	input.encrypted == false
	msg = "EBS volumes must be encrypted at rest."
}
