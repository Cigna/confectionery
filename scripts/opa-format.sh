#!/bin/bash
set -o nounset -o errexit -o pipefail

GREEN='\033[0;32m'
ORANGE='\033[0;33m'
NC='\033[0m'

# Quick test that checks opa format.
if [[ $(opa fmt -l rules/terraform/ test-files) ]]; then
    opa fmt -l rules/terraform/ test-files
    1>&2 echo -e "${ORANGE}> Run \`opa fmt -w rules/terraform/ test-files/\` to format rego files.${NC}"
    exit 1
else
    1>&2 echo -e "${GREEN}> All rego files in the repository are formatted.${NC}"
fi

