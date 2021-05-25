# Kinesis stream encrypted ensures a stream is encrypted at rest with a CMK
package rules.kinesis_stream_encrypted

# Simple rule finding kinesis streams
resource_type = "aws_kinesis_stream"

deny[msg] {
	input.encryption_type == "NONE"
	msg = "Kinesis streams must have encryption at-rest (CMK)."
}

deny[msg] {
	input.encryption_type == "KMS"
	input.kms_key_id == "alias/aws/kinesis"
	msg = "Kinesis streams must have encryption at-rest (CMK)."
}

deny[msg] {
	input.encryption_type == "KMS"
	input.kms_key_id == null
	msg = "Kinesis streams must have encryption at-rest (CMK)."
}
