# S3 Bucket Encryption: Deny S3 Buckets that are not encrypted and/or do not have a valid sse algorithm.
# Objects stored within S3 buckets are not encrypted at-rest by default. This rule denies S3 buckets that are not encrypted by validating server side encryption is enabled with valid algorithms (aws:kms or AES256).
package rules.s3_encryption

resource_type = "aws_s3_bucket"

controls = {"NIST-800-53_SC-13"}

# Explicitly allow AES256 or aws:kms server side SSE algorithms.
valid_sse_algorithms = {
	"AES256",
	"aws:kms",
}

# Collect all sse algorithms configured under `server_side_encryption_configuration`.
used_sse_algorithms[algorithm] {
	algorithm = input.server_side_encryption_configuration[_].rule[_][_][_].sse_algorithm
}

deny[msg] {
	# Deny resource if sse algorithm is not configured for s3
	count(used_sse_algorithms) <= 0
	msg = "S3 server-side encryption is required for all s3 buckets."
}

deny[msg] {
	# Deny resource if any of the used sse algorithms are not set to AES256 or aws:kms
	count(used_sse_algorithms - valid_sse_algorithms) > 0
	msg = "S3 server-side encryption is required for all s3 buckets."
}
