#!/bin/sh

# SYSCOIN: CPU and GPU wrappers deserialize different CRS formats. Verify the selected role's
# exact bytes before publishing a file; a valid compact GPU CRS is not a valid CPU CRS.
set -eu

usage() {
    echo "usage: $0 {cpu-snark|gpu-snark} OUTPUT (FRI needs no CRS)" >&2
    exit 2
}

case "$#" in
    1)
        case "$1" in cpu-snark|gpu-snark|fri) usage ;; esac
        # Preserve existing explicit compact downloads, but never silently select them for CPU.
        role='gpu-snark'
        output_path="$1"
        echo 'Legacy one-path invocation selects the compact GPU CRS; CPU requires cpu-snark OUTPUT.' >&2
        ;;
    2) role="$1"; output_path="$2" ;;
    *) usage ;;
esac
case "${role}" in
    cpu-snark|gpu-snark) ;;
    *) usage ;;
esac
test -n "${output_path}" || usage

# Docker keeps its fixed default; local operators/tests can explicitly select the reviewed pins.
pins="${PROVER_BUILD_PINS:-/usr/src/zksync/docker/prover-build-pins.json}"
selected_crs="$(jq -ce --arg role "${role}" '
    if .schema != "syscoin-prover-image-build-pins-v1" then error("invalid build pins schema") else . end
    | if $role == "cpu-snark" then .cpu_snark_crs else .crs end
    | if (.url | type) != "string" or (.url | startswith("https://") | not)
        or (.size | type) != "number" or .size <= 0 or .size != (.size | floor)
        or (.sha256 | type) != "string" or (.sha256 | test("^[0-9a-f]{64}$") | not)
        or .sha256 == ("0" * 64)
      then error("invalid CRS pins for selected role") else . end
    | if $role == "cpu-snark" and
        ((.g1_count | type) != "number" or .g1_count < 33554432 or .g1_count != (.g1_count | floor))
      then error("Security100 CPU CRS requires at least 2^25 G1 points") else . end
' "${pins}")"
readonly_url="$(printf '%s' "${selected_crs}" | jq -er '.url')"
readonly_size="$(printf '%s' "${selected_crs}" | jq -er '.size')"
readonly_sha256="$(printf '%s' "${selected_crs}" | jq -er '.sha256')"

part_path="$(mktemp "${output_path}.part.XXXXXX")"
trap 'rm -f -- "${part_path}"' 0
trap 'exit 1' HUP INT TERM
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --retry 5 \
    --output "${part_path}" "${readonly_url}"
test "$(wc -c < "${part_path}" | tr -d '[:space:]')" = "${readonly_size}"
# Hash stdin so both GNU and BSD sha256sum work, without parsing a caller-supplied filename.
actual_sha256="$(sha256sum < "${part_path}" | awk '{print $1}')"
if [ "${actual_sha256}" != "${readonly_sha256}" ]; then
    echo "CRS SHA-256 mismatch for ${role}" >&2
    exit 1
fi
# The pinned Security100 wrapper uses a 2^25 domain; the older 2^24 CPU example is too small.
# CPU Crs::read starts with a big-endian u64 count, unlike the compact GPU serialization.
if [ "${role}" = 'cpu-snark' ]; then
    readonly_g1_count="$(printf '%s' "${selected_crs}" | jq -er '.g1_count')"
    actual_g1_count="$(od -An -N8 -tu1 "${part_path}" | awk '
        { for (i = 1; i <= NF; i++) { count = count * 256 + $i; bytes++ } }
        END { if (bytes != 8) exit 1; printf "%.0f", count }
    ')"
    if [ "${actual_g1_count}" != "${readonly_g1_count}" ] || [ "${actual_g1_count}" -lt 33554432 ]; then
        echo 'CPU CRS G1 count does not satisfy the pinned Security100 capacity' >&2
        exit 1
    fi
fi
# CRS parameters are public; preserve readability for non-root workers in the runtime image.
chmod 0644 "${part_path}"
mv -- "${part_path}" "${output_path}"
