# Pinned native Intel audit candidate

This source patch lets the manual [native Intel workflow](../../../.github/workflows/native-intel-hvf-mmio.yml)
execute the pending, coupled backend changes in its disposable CI checkout.
It does not install those changes into the production source on master.
Native qualification remains pending until the actual guest observations pass.

An earlier real RAX run stopped during VM construction before guest entry.
The later run 41968179867 exceeded its 45-minute limit and retained neither
usable logs nor artifacts; whether it entered a guest is unknown. The
[split build/execution workflow](../hvf-intel-pipeline/README.md) now preserves
the signed build before attempting native execution. SDK model tests and
cross-compilation do not establish native guest behavior.
Run 41978606771 retained its build and failure reports, but its first RAM-only
control did not return HLT. No passed case was recorded. The new
[frontier diagnostic](../hvf-intel-frontier/README.md) now prints the returned exit
and CPU projection when that assertion fails; the independent KVM RAM setup control
passes. The changed diagnostic requires a new native run. This candidate contains the SDK compatibility correction,
software PAT state, interrupt and RAM integration, and the native consumer with
130 registered cases: 114 existing cases, eight PAT cases, and eight reserved-MSR
exception cases. It also retains the combined source dependencies against which
the local checks ran. The complete path inventory is in [candidate.json](candidate.json).

| Input | Value |
|---|---|
| Base source commit | `1bef693b088fb9599c73233e0b0be45cc3625d96` |
| Changed source paths | 108 |
| Patch size | 592943 bytes |
| Patch SHA-256 | `c1718808d4e5c0e31da0d626d2defb544a17d14c54bd5985ac0e9bd381ed3fe9` |
| Base source fingerprint | `4b9fb339c8e56aabd2f141085a0632f78297d5ca800f91e87a3a05b3f84744af` |
| Candidate source fingerprint | `ca47a578eb499df09c6e21af559cde2c18f1917215ada845ffb47c6a1f71d584` |

Fingerprints are SHA-256 of a JSON object mapping relative source paths to file
SHA-256 values, using sorted keys and compact JSON separators. The scope is all
Rust files under `src`, Rust and TOML files under `vendor/vm-memory`, the root
Cargo manifest and lockfile, `.cargo/config.toml`, and the two native consumer
files. It contains 4412 base inputs and 4461 candidate inputs. The Git commit is
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
  --repo . --base-ref 1bef693b088fb9599c73233e0b0be45cc3625d96 \
  --expected-target-digest ca47a578eb499df09c6e21af559cde2c18f1917215ada845ffb47c6a1f71d584 \
  --output /tmp/rax-native-candidate-new
```

The generator uses a temporary alternate index in the existing repository. It
verifies forward/reverse patch applicability and the candidate tree, then checks
that the real index and working source remain unchanged. It removes the
temporary index and creates no branch, worktree, or complete source export.
The command rejects a working source that differs from the explicitly supplied
qualified fingerprint. Patch generation is linear in the inspected source
bytes; retained output is proportional to the changed source bytes.

[Qualification](qualification.json) records all 22 current tooling regressions,
the actual generator roundtrip against the published base, and rejection of
the already modified local source before mutation. The unchanged split workflow
passed all 15 declared CI policy tests. The integrated 130-case consumer compiled,
linked, exported, and passed signature verification on Apple Silicon with
optimization level 0; zero native Intel guest cases executed locally. Earlier
202-test SDK/model qualification and the original candidate evidence remain
in the historical record with their original source identities.

| Assumption | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|
| A1: the pinned content is the intended CI candidate | Native result attribution | Compare both source fingerprints; a changed input must reject before building | Confirmed for generation; checked again in CI |
| A2: model qualification predicts usable SDK construction | Actual native execution | Run the real backend on the Intel runner and require all registered cases to execute | Retained; hardware result unknown |

High-impact remaining boundary: a model or cross-build pass does not establish
native behavior. The workflow must retain the actual host identity, nonzero
case count, and guest outcomes. The candidate does not close the broader state,
SMP, A32-FP, or HVF audit findings by itself.
