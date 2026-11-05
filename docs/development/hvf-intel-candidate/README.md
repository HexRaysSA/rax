# Pinned native Intel audit candidate

This source patch lets the manual [native Intel workflow](../../../.github/workflows/native-intel-hvf-mmio.yml)
execute the pending, coupled backend changes in its disposable CI checkout.
It does not install those changes into the production source on master.
Native qualification remains pending until the actual guest observations pass.

The previous real RAX run stopped during VM construction before executing a
guest instruction. SDK model tests and cross-compilation do not resolve that
failure on hardware. This candidate contains the SDK compatibility correction,
software PAT state, interrupt and RAM integration, and the native consumer with
130 registered cases: 114 existing cases, eight PAT cases, and eight reserved-MSR
exception cases. It also retains the combined source dependencies against which
the local checks ran. The complete path inventory is in [candidate.json](candidate.json).

| Input | Value |
|---|---|
| Base source commit | `6c259f73a1a02d3259312010c8db937040bbb89d` |
| Changed source paths | 117 |
| Patch size | 617326 bytes |
| Patch SHA-256 | `aad2a3b86647ea6eb8d8937980d8b4a13bdac391bf34291fd3961e1c70add1af` |
| Base source fingerprint | `8c32fcba9da58a7241e50e8f7f2dc57d7e0765eeff0bc61a1100d48d4cf400fc` |
| Candidate source fingerprint | `a82c24ae4bdb7432f919518664555dc913bc45f4c02f2e71eaba69acfc500572` |

Fingerprints are SHA-256 of a JSON object mapping relative source paths to file
SHA-256 values, using sorted keys and compact JSON separators. The scope is all
Rust files under `src`, Rust and TOML files under `vendor/vm-memory`, the root
Cargo manifest and lockfile, `.cargo/config.toml`, and the two native consumer
files. It contains 4405 base inputs and 4455 candidate inputs. The Git commit is
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
  --repo . --base-ref 6c259f73a1a02d3259312010c8db937040bbb89d \
  --expected-target-digest a82c24ae4bdb7432f919518664555dc913bc45f4c02f2e71eaba69acfc500572 \
  --output /tmp/rax-native-candidate-new
```

The generator uses a temporary alternate index in the existing repository. It
verifies forward/reverse patch applicability and the candidate tree, then checks
that the real index and working source remain unchanged. It removes the
temporary index and creates no branch, worktree, or complete source export.
The command rejects a working source that differs from the explicitly supplied
qualified fingerprint. Patch generation is linear in the inspected source
bytes; retained output is proportional to the changed source bytes.

[Qualification](qualification.json) records eight complete tooling regressions,
15 complete CI policy tests, the actual generator roundtrip, and rejection of
the already modified local source before mutation. The combined engine passed
202 tests across eight complete Intel SDK/model binaries. Its 130-case native
consumer compiled, linked, and passed signature verification on Apple Silicon;
zero native Intel guest cases executed in that local check.

| Assumption | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|
| A1: the pinned content is the intended CI candidate | Native result attribution | Compare both source fingerprints; a changed input must reject before building | Confirmed for generation; checked again in CI |
| A2: model qualification predicts usable SDK construction | Actual native execution | Run the real backend on the Intel runner and require all registered cases to execute | Retained; hardware result unknown |

High-impact remaining boundary: a model or cross-build pass does not establish
native behavior. The workflow must retain the actual host identity, nonzero
case count, and guest outcomes. The candidate does not close the broader state,
SMP, A32-FP, or HVF audit findings by itself.
