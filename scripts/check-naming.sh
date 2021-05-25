#!/bin/bash
set -o nounset -o errexit -o pipefail

# Quick test that checks file naming.

for rule_file in rules/terraform/*/*/*.rego; do
  1>&2 echo "Checking $rule_file..."

  # Capture full directory name
  full_dir="$(dirname "$rule_file")"

  # Ensure a matching path test file exists for each rule rego exclude the top level rules/ directory
  test_file="test-files/${full_dir#rules/}/$(basename "$rule_file" .rego)_test.rego"
  if [[ ! -f "$test_file" ]]; then
    1>&2 echo "Missing $test_file"
    exit 1
  fi

  # Ensure a matching path sample terraform file exists for each rule rego exclude the top level rules/ directory
  terraf_file="test-files/${full_dir#rules/}/$(basename "$rule_file" .rego).tf"
  if [[ ! -f "$terraf_file" ]]; then
    1>&2 echo "Missing $terraf_file"
    exit 1
  fi
done

1>&2 echo "All rego files have corresponding test and terraform files!"
