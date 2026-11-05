# Pinned native Intel audit candidate

This source patch lets the manual [native Intel workflow](../../../.github/workflows/native-intel-hvf-mmio.yml)
execute the pending, coupled backend changes in its disposable CI checkout.
It does not install those changes into the production source on master.
Native qualification remains pending until the actual guest observations pass.

An earlier real RAX run stopped during VM construction before guest entry.
The later run 41968179867 exceeded its 45-minute limit and retained neither
usable logs nor artifacts; whether it entered a guest is unknown. The
[retained build/execution workflow](../hvf-intel-pipeline/README.md) now preserves
the signed build before attempting native execution. SDK model tests and
cross-compilation do not establish native guest behavior.
Run 41978606771 retained its build and failure reports, but its first RAM-only
control did not return HLT. No passed case was recorded. The new
[frontier diagnostic](../hvf-intel-frontier/README.md) now prints the returned exit
and CPU projection when that assertion fails; run 41983036300 observes failed
VM entry with basic reason 33. The independent KVM RAM setup control passes.
The later 22-case SDK matrix reaches HLT in all five full-shadow variants.
The [public importer correction](../hvf-intel-frontier/control-shadow-import.md)
is in the published base. Actual RAX run 41992554080 passes 118 native cases
before private capture rejects SDK-normalized masks. The
[mask initializer](../hvf-intel-frontier/control-mask-policy.md) now finalizes
those masks before freezing producer controls and passes all 62 SDK owner tests.
The later run 42001141985 passes the mask check but rejects a changed exception
policy at private capture. The published base now
[preserves the SDK exception bitmap](../hvf-intel-frontier/exception-intercepts.md).
This candidate also includes the pending deadline owner, queued expiries and
versioned CPU/controller checkpoint records. All 65 local owner tests pass.
Actual RAX run 42006230493 passes all 130 preceding RAM/MMIO/PAT/MSR and private
checkpoint controls. Native deadline-specific qualification is outstanding.
This refreshed candidate requires a new actual RAX run. It contains the SDK
compatibility correction, software PAT state, interrupt and RAM integration, and the native consumer with
146 registered cases: 114 original cases, eight PAT cases, eight reserved-MSR
exception cases, and 16 deadline/TSC cases. It also retains the combined source
dependencies against which the local checks ran. The complete path inventory is in [candidate.json](candidate.json).

| Input | Value |
|---|---|
| Base source commit | `e264249d787791174486c5b84b457ef4fa202b20` |
| Changed source paths | 110 |
| Patch size | 619361 bytes |
| Patch SHA-256 | `5cdb0b251d436e1fe8de74a0f486ce8b55bd05f94bb000a4878540b8e2132457` |
| Base source fingerprint | `4621aefdee2e3b3c6f31d098f61c2c975e77011fafaa0d7ae36d4e633f07dc3e` |
| Candidate source fingerprint | `9bf5ddc0a0241f4a497622e3792f0bc8274a00796b15e479979cd63d2c1c8664` |

Fingerprints are SHA-256 of a JSON object mapping relative source paths to file
SHA-256 values, using sorted keys and compact JSON separators. The scope is all
Rust files under `src`, Rust and TOML files under `vendor/vm-memory`, the root
Cargo manifest and lockfile, `.cargo/config.toml`, and the two native consumer
files. It contains 4422 base inputs and 4473 candidate inputs. The Git commit is
provenance; exact content fingerprints enforce admission, independently of
later documentation or tooling commits.

From the repository root, dispatch the native runner with:

```sh
gh workflow run native-intel-hvf-mmio.yml --ref master -f candidate=true
```

With `candidate=false` (the default), the workflow tests the production source.
With `candidate=true`, it verifies the patch checksum, allowed path inventory,
and base source fingerprint before applying the patch. It then verifies the
resulting source fingerprint before any build or guest execution. It refuses a
changed base, renamed paths, Git metadata, workflows, binary patches, symlinks,
and mismatched diff headers. A failed post-apply check leaves the disposable CI
checkout available for inspection and fails the step; it does not qualify the
source or run guests. The artifact retains before/after input maps and command
results. The probe owns and removes its build directory.

To regenerate the sparse patch from this exact combined working source, use a
new output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/hvf/build_native_candidate.py \
  --repo . --base-ref e264249d787791174486c5b84b457ef4fa202b20 \
  --expected-target-digest 9bf5ddc0a0241f4a497622e3792f0bc8274a00796b15e479979cd63d2c1c8664 \
  --output /tmp/rax-native-candidate-new
```

The generator uses a temporary alternate index in the existing repository. It
verifies forward/reverse patch applicability and the candidate tree, then checks
that the real index and working source remain unchanged. It removes the
temporary index and creates no branch, worktree, or complete source export.
The command rejects a working source that differs from the explicitly supplied
qualified fingerprint. Patch generation is linear in the inspected source
bytes; retained output is proportional to the changed source bytes.

[Qualification](qualification.json) records all 31 current tooling regressions,
the actual generator roundtrip against the published base, and rejection of
the already modified local source before mutation. The updated single-runner workflow
passed all 15 declared CI policy tests. The integrated 146-case consumer compiled,
linked and passed signature verification against the corrected library on
Apple Silicon with optimization level 0; its temporary binary was removed,
and zero native Intel guest cases executed locally. Earlier prepared export/admission and
202-test SDK/model qualification and the original candidate evidence remain
in the historical record with their original source identities.

| Assumption | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|
| A1: the pinned content is the intended CI candidate | Native result attribution | Compare both source fingerprints; a changed input must reject before building | Confirmed for generation; checked again in CI |
| A2: model qualification predicts usable SDK construction | Actual native execution | Run the real backend on the Intel runner and require all registered cases to execute | Existing 130 cases pass natively after constructor corrections; 16 new deadline/TSC cases require native execution |

High-impact remaining boundary: a model or cross-build pass does not establish
native behavior. The workflow must retain the actual host identity, nonzero
case count, and guest outcomes. The candidate does not close the broader state,
SMP, A32-FP, or HVF audit findings by itself.
