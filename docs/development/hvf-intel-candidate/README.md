# Archived native Intel audit candidate

This source patch records the transition qualified by the manual
[native Intel workflow](../../../.github/workflows/native-intel-hvf-mmio.yml).
The production source on master now includes these changes. Run 42014912978
passes all 149 native cases, including actual VMM startup and IPIs across
1, 2 and 4 CPUs. The default `candidate=false` tests the integrated production
source. The archived patch still requires its original base fingerprint.

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
This candidate also includes the deadline owner, queued expiries and
versioned CPU/controller checkpoint records. All 65 local owner tests pass.
Actual RAX run 42006230493 passes all 130 preceding RAM/MMIO/PAT/MSR and private
checkpoint controls. The subsequent
[run 42010491792](../hvf-tsc-deadline/implementation.md) passes all 146 controls,
including deadline expiry, armed restore, HLT interrupt delivery and TSC-domain
alignment. The current candidate also implements INIT dispatch on the permanent
owner and adds three actual VMM startup/IPI controls. All four focused INIT owner
groups pass, and the complete owner binary passes all 69 tests without failures,
ignores or filters. The subsequent native run passes all 149 cases. See the
[startup qualification](../hvf-native-startup/README.md). This candidate contains the SDK
compatibility correction, software PAT state, interrupt and RAM integration, and the native consumer with
149 registered cases: 114 original cases, eight PAT cases, eight reserved-MSR
exception cases, 16 deadline/TSC cases and three VMM startup/IPI cases. It also retains the combined source
dependencies against which the local checks ran. The complete path inventory is in [candidate.json](candidate.json).

| Input | Value |
|---|---|
| Base source commit | `00ac46faf5298bb1f299089892e02aa4efd753d2` |
| Changed source paths | 111 |
| Patch size | 626883 bytes |
| Patch SHA-256 | `f582081403f8df17a59788a7647ab6cf5ed3755ce5db979fbd941dcd35549ead` |
| Base source fingerprint | `bcd990808cca8bc3b61749838e543462b69baa63f07349fb658542d1bb1b21b7` |
| Candidate source fingerprint | `b82dd8663a3a754eea05a7d987e8aba569fb17cfb48d5932d22eb8f198093893` |

Fingerprints are SHA-256 of a JSON object mapping relative source paths to file
SHA-256 values, using sorted keys and compact JSON separators. The scope is all
Rust files under `src`, Rust and TOML files under `vendor/vm-memory`, the root
Cargo manifest and lockfile, `.cargo/config.toml`, and the two native consumer
files. It contains 4422 base inputs and 4474 candidate inputs. The Git commit is
provenance; exact content fingerprints enforce admission, independently of
later documentation or tooling commits.

From the repository root, dispatch the native runner with:

```sh
gh workflow run native-intel-hvf-mmio.yml --ref master -f candidate=true
```

With `candidate=false` (the default), the workflow tests the production source.
With `candidate=true`, it verifies the archived patch checksum, allowed path inventory,
and base source fingerprint before applying the patch. It then verifies the
resulting source fingerprint before any build or guest execution. It refuses a
changed base, renamed paths, Git metadata, workflows, binary patches, symlinks,
and mismatched diff headers. A failed post-apply check leaves the disposable CI
checkout available for inspection and fails the step; it does not qualify the
source or run guests. Integrated master rejects the archived base check because
the changes are already installed; use the default production mode there.
The artifact retains before/after input maps and command
results. The probe owns and removes its build directory.

To regenerate the sparse patch from this exact combined working source, use a
new output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/hvf/build_native_candidate.py \
  --repo . --base-ref 00ac46faf5298bb1f299089892e02aa4efd753d2 \
  --expected-target-digest b82dd8663a3a754eea05a7d987e8aba569fb17cfb48d5932d22eb8f198093893 \
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
passed all 15 declared CI policy tests. The integrated 149-case consumer compiled,
linked and passed signature verification against the corrected library on
Apple Silicon with optimization level 0; its temporary binary was removed,
and zero native Intel guest cases executed locally. Earlier prepared export/admission and
202-test SDK/model qualification and the original candidate evidence remain
in the historical record with their original source identities.

| Assumption | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|
| A1: the pinned content is the intended CI candidate | Native result attribution | Compare both source fingerprints; a changed input must reject before building | Confirmed for generation; checked again in CI |
| A2: model qualification predicts usable SDK construction | Actual native execution | Run the real backend on the Intel runner and require all registered cases to execute | All 149 cases pass in run 42014912978 |

High-impact remaining boundary: a model or cross-build pass does not establish
native behavior. The workflow must retain the actual host identity, nonzero
case count, and guest outcomes. The candidate does not close the broader state,
SMP, A32-FP, or HVF audit findings by itself.
