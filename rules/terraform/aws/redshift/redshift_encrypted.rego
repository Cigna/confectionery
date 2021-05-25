# Redshift cluster encrypted ensures a cluster is encrypted at rest
package rules.redshift_cluster_encrypted

# Simple rule finding redshift clusters
resource_type = "aws_redshift_cluster"

deny[msg] {
	input.encrypted == false
	msg = "Redshift clusters must have encryption at-rest."
}
