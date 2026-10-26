# Prover releases

Release-please runs on GitHub-hosted Linux using the repository's `GITHUB_TOKEN`.
Enable **Allow GitHub Actions to create and approve pull requests** in repository
settings. A maintainer must approve the checks for a pull request opened or
updated with `GITHUB_TOKEN`; GitHub places those runs in an approval-required
state. Merge only after those checks pass. When a release is created, the
workflow directly calls the binary and image builds with the returned tag and source SHA,
so it does not depend on the suppressed token-generated tag-push event.

Release-please updates the workspace version and release manifest in its PR.
Before merging a release PR, a maintainer must also update the matching local
package versions in **both** `Cargo.lock` and `patches/airbender.Cargo.lock`.
Do not refresh the dependency graph: inspect the diff and confirm only the five
workspace package version entries changed. Update `canonical_lock_sha256` and
`overlay_lock_sha256` in `patches/airbender-fork-source.json` to the SHA-256
hashes of the respective files.

The existing crypto-bigint exception is scoped to the exact manifests, locks,
source, and pins. Review the advisory exception and **all** scope-input diffs
against the checked-in main branch before recording a new scope. Once that
review is complete, regenerate the scope input hashes with:

```sh
python3 - <<'PY'
import importlib.util
import json
from pathlib import Path

script = Path('.github/scripts/check_crypto_bigint_scope.py')
spec = importlib.util.spec_from_file_location('scope', script)
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)
path = Path(scope.DEFAULT_SCOPE)
record = json.loads(path.read_text())
record['inputs'] = scope.collect_inputs(Path('.'))
path.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
PY
python3 -B .github/scripts/check_release_inputs.py
python3 -B .github/scripts/test_release_inputs.py
```

Review the lockfiles, pin and scope diffs in the release PR. The release-input
gate runs in PR CI and again before creating a release. It deliberately does
not authorize or automate the scope review. Release PR creation also depends on
the repository setting above; an installation-owned GitHub App can replace
`GITHUB_TOKEN` later if automatic PR check execution is desired.

## Recovering publication

If a release exists but the binary or image build fails, first rerun its failed
job in the original workflow run so it can use the existing build artifacts.
For a manual recovery, dispatch `Release binaries` and/or `Docker build and
release` from `main`, supplying the existing release tag and the exact commit
SHA obtained by peeling that tag. Both workflows validate this binding.

Binary publication downloads and hashes existing assets before it uploads any
missing assets. Matching files are retained; a different file with the same name
causes a failure without replacement. A rebuilt binary archive may not be
byte-identical, so an operator must investigate any mismatch and decide how to
resolve the existing release asset instead of overwriting it automatically.
