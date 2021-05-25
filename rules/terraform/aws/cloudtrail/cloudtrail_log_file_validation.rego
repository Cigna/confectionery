# Cloudtrail log file validation: Deny if enable_log_file_validation attribute == false, if attribute == true allow 
package rules.cloudtrail_log_file_validation

# Simple rule finding aws_cloudtrail resource
resource_type = "aws_cloudtrail"

controls = {
	"CIS_2-2",
	"NIST-800-53_AC-2g",
	"NIST-800-53_AC-6 (9)",
	"REGULA_R00006",
}

deny[msg] {
	input.enable_log_file_validation == false
	msg = "Cloudtrails must have log file validation enabled."
}
