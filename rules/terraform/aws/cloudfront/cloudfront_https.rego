package rules.cloudfront_distribution_https

resource_type = "aws_cloudfront_distribution"

# Explicitly allow only https or redirection to https.
valid_protocols = {
	"redirect-to-https",
	"https-only",
}

used_traffic_protocols[protocol] {
	protocol = input.default_cache_behavior[_].viewer_protocol_policy
}

deny[msg] {
	# Difference of used_traffic_protocols and valid_protocols must be empty.
	count(used_traffic_protocols - valid_protocols) > 0
	msg = "Cloudfront distributions must either redirect to or only allow https traffic."
}
