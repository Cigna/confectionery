#!/bin/bash
set -o nounset -o errexit -o pipefail

# Quick test that checks file naming.

for rule_file in rules/terraform/*/*/*.rego; do
  1>&2 echo "Checking $rule_file..."

  test_file="test-files/$(dirname "$rule_file")/$(basename "$rule_file" .rego)_test.rego"
  if [[ ! -f "$test_file" ]]; then
    1>&2 echo "Missing $test_file"
    exit 1
  fi

  terraf_file="test-files/$(dirname "$rule_file")/$(basename "$rule_file" .rego).tf"
  if [[ ! -f "$terraf_file" ]]; then
    1>&2 echo "Missing $terraf_file"
    exit 1
  fi
done

1>&2 echo "All rego files have corresponding test and terraform files!"
