#!/bin/sh

# SYSCOIN: Exact compact CRS independently checked by the V32/V8 key-generation workflow.
set -eu

pins='/usr/src/zksync/docker/prover-build-pins.json'
readonly_url="$(jq -er '.crs.url' "${pins}")"
readonly_size="$(jq -er '.crs.size' "${pins}")"
readonly_sha256="$(jq -er '.crs.sha256' "${pins}")"
output_path="${1:?trusted-setup output path is required}"

curl --proto '=https' --tlsv1.2 --fail --location --retry 5 \
    --output "${output_path}.part" "${readonly_url}"
test "$(stat -c '%s' "${output_path}.part")" = "${readonly_size}"
echo "${readonly_sha256}  ${output_path}.part" | sha256sum --check --strict
mv "${output_path}.part" "${output_path}"
