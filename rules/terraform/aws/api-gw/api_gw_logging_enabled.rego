package rules.api_gw_logging_enabled

import data.fugue

resource_type = "MULTIPLE"

api_stage = fugue.resources("aws_api_gateway_stage")

# required_format := "{ \"requestId\":\"$context.requestId\", \"ip\": \"$context.identity.sourceIp\", \"caller\":\"$context.identity.caller\", \"user\":\"$context.identity.user\",\"requestTime\":\"$context.requestTime\", \"httpMethod\":\"$context.httpMethod\",\"resourcePath\":\"$context.resourcePath\", \"status\":\"$context.status\",\"protocol\":\"$context.protocol\", \"responseLength\":\"$context.responseLength\" }"

# Code commented out will check for the correct logging format as well as if the log group naming convention is followed. Written as a Prisma rule for now while it is more widely socialized

# Auxiliary function checking if access_log_settings is not blank

is_valid(resource) {
	not resource.access_log_settings == []
	#resource.access_log_settings[_].format == required_format
	#endswith(resource.access_log_settings[_].destination_arn, "-apigwlogs")
}

# Regula expects advanced rules to contain a `policy` rule that holds a set
# of _judgements_.

policy[p] {
	resource = api_stage[_]
	is_valid(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource = api_stage[_]
	not is_valid(resource)
	p = fugue.deny_resource_with_message(resource, "API Gateway Access Logging should be enabled with the proper format configured.")
}
