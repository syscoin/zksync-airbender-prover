# Image SBOM identity

The image build workflow saves one digest record per component after the image has
been pushed and attested. Each record binds the immutable GHCR reference to its
component, source commit, tooling commit, version label, workflow run, and attempt.
The three expected components are `zksync-airbender-prover`, `zksync-os-prover-fri`,
and `zksync-os-prover-snark`.

The collector downloads separate artifacts from the current run attempt, checks
the complete inventory and every record's identity, then supplies a digest map to
the reusable SBOM workflow. It does not rely on matrix job outputs retaining every
component's value. The reusable workflow validates that map before contacting
Dependency Track and scans each `ghcr.io/<owner>/<component>@sha256:<digest>`.
Reusing a version tag in another run cannot redirect that scan.

The uploaded CycloneDX 1.6 document keeps Syft's metadata and adds
`io.syscoin.prover.image-build.*` properties with the exact image/build identity.
The workflow also retains the bound SBOM and an `image-identity.json` sidecar in an
`image-sbom-<run>-<attempt>-<component>` artifact. Dependency Track's project version
remains the release label; use the SBOM identity or retained workflow artifact to
distinguish multiple builds of that label. Existing image attestations continue to
bind the source, tooling, guest artifacts, toolchain, and CRS inputs.

Retries deliberately require a complete build attempt: rerun **all jobs** if a
component build or digest collection fails. Rerunning only failed jobs can leave
successful components' digest artifacts in an earlier attempt, which the collector
rejects instead of mixing build attempts. Artifact names include the run and
attempt, so successful prior evidence is not overwritten.
An SBOM-only retry after successful collection can reuse the collected digests:
the caller also passes the original build attempt, so the regenerated SBOM does
not mislabel the images as having been rebuilt during the retry.

## Offline checks

Run from the repository root:

```sh
python3 -B .github/scripts/test_image_sbom_identity.py
git diff --check
```

The tests exercise the production helper with three different component digests,
missing/extra/duplicate inventories, malformed digests, mismatched source/tooling
and run identities, and CycloneDX evidence preservation. A local CLI round trip
mocks only the scanner's response and verifies that reusing a tag cannot alter the
digest passed from collection through the matrix into the evidence. These checks
do not build or push images, read credentials, or contact a registry or Dependency
Track; the next authorized workflow run still verifies those integrations.

## Origin

The mutable-tag scan was introduced by upstream SBOM workflow commit `991e3fa`
(`ci(ZKD-3716): SBOM workflows (#136)`). Syscoin commits `a1d2693`, `702e234`,
`3eb7712`, and `94bf26a` subsequently aligned release labels and pinned application
source and credentialed tooling, while preserving that scan expression. The
digest handoff and evidence binding extend those controls; changed upstream
workflow sections carry `SYSCOIN` rationale comments.

The handoff follows GitHub's [workflow artifact sharing](https://docs.github.com/en/actions/tutorials/store-and-share-data)
and [separate download directories](https://github.com/actions/download-artifact/blob/634f93cb2916e3fdff6788551b99b062d0335ce0/README.md#inputs)
semantics. Build identity uses the [CycloneDX 1.6 metadata properties](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json)
extension point.
