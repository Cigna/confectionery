package utilities

# Method to check whether a version is greater than or equal to a minimum accepted version
# @params : used version array[] , accepted version array[]
# @return : boolean
check_version(used, accepted) {
	# Checks for exact version : 1.6.0
	to_number(used[0]) == accepted[0]
	to_number(used[1]) == accepted[1]
	to_number(used[2]) == accepted[2]
}

check_version(used, accepted) {
	# Checks the major version is greater
	to_number(used[0]) > accepted[0]
}

check_version(used, accepted) {
	# Checks the minor version is greater if major is equal to accepted
	to_number(used[0]) == accepted[0]
	to_number(used[1]) > accepted[1]
}

check_version(used, accepted) {
	# Checks the patch version is greater if major and minor are equal to accepted
	to_number(used[0]) == accepted[0]
	to_number(used[1]) == accepted[1]
	to_number(used[2]) > accepted[2]
}
