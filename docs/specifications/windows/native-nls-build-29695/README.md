# NLS initialization and query-only MUI on Windows 29695

The finite NLS startup profile admits Windows 10.0 builds 29683 and 29695.
Initialization and query-only MUI acquisition and guest dispatch use the same
NLS predicate. It is independent of CSR, processor and other NT profile gates.
Adjacent builds, a different major version, and a different minor version
remain unmeasured. Selection captures installed bytes; guest addresses,
arguments and lengths never reach the native acquisition calls.

All new native observations use one ARM64 kernel, Windows 10.0.29695. Native
ARM64, compatibility x64, x86 and x86 with large-address awareness are process
views of that kernel. An independent AMD64 kernel remains unknown.

| Observation | New native evidence | Comparison with 29683 |
| --- | --- | --- |
| Initialization | 79 calls per process profile; 316 total | Identical status, guard, view delta and output bytes after relocating only actual base-output bytes |
| Protection and private free | 12 calls per profile; 48 total | Identical status and output fields; all 48 owned views explicitly unmapped |
| Query-only MUI | 1,680 calls per profile; 6,720 total | Exact row equality, including status, size, partial writes, aliases and last-error |
| Installed leaves | Three exports per profile; 12 captures | Current x86 initialization leaf ends with `C2 0C 00`, consuming three argument slots |
| Shared language generation | Three fresh query captures | Shared count before, payload count, and shared count after all equal 1 |

The corrected version-2 x86 producers use a three-argument stdcall declaration.
Their fourth logical matrix field is deliberately absent from the native call.
The earlier four-argument producers and observations remain unchanged. ARM64
and x64 controls reuse their frozen four-argument producers.

On each measured kernel, the four initialization process profiles produce
140 successes and 176 failures
without caller SEH. Eight late x86 pointer-copy faults retain mapped views;
the locale output has already been copied. Native64 stores base before locale;
x86 stores locale before base. Aliases and guarded destinations retain these
orders. Existing VM ownership, read-only sealing and interior-address unmap
implement the same contract on all hosts.

The installed `locale.nls` file is 862,808 bytes. Its selected mapping occupies
ceil(862808 / 4096) * 4096 = 211 * 4096 = 864,256 bytes, including 1,448 bytes of
zero padding. Each selected payload remains bounded to 8 MiB, and all retained
NLS data remains bounded to 64 MiB. Initialization takes O(N) time and owns O(N)
guest mapping bytes. MUI publication takes O(L + P) time until the first fault
and 4,096 bytes of scratch, with an immutable O(P) snapshot. Native cache clear
and commit remain explicitly unavailable.

`profile-29695-v1.json` binds sources, compilers, executable and output hashes,
canonical comparison hashes, the installed file, and generation observations.
The original result ZIPs remain in the task evidence archive under their
recorded byte counts and SHA-256 values. This typed projection omits native
addresses; comparison verifies each relocated output byte against the newly
enumerated native mapping before normalizing it. All other bytes remain exact.

Run `python docs/specifications/windows/native-nls-build-29695/check.py` to
verify retained source identities and semantic signatures. Supplying the two
recorded result ZIPs regenerates the projection and checks the original native
comparisons. The two frozen controllers record compiler commands, exit status,
before/after source identities and per-producer binary/output hashes. Their
temporary paths stay under the Windows source worktree.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| NI1 | 29695 retains the measured initialization ABI and mapping/copy contract | Independent native calls and actual current leaves | Finite initialization admission | Invalid, read-only, guarded, unaligned and aliased outputs; retained views; protection/free | Any status, copy order, ABI, extent or lifetime mismatch | Confirmed for the recorded ARM64 kernel and its four process profiles |
| NI2 | 29695 query bytes retain the immutable snapshot and generation contract | Exact native query rows, matching payload hashes, three generation captures | Query-only MUI admission and shared-page initialization | Pointer/length ordering, aliasing, partial zeroing and stable generation | Address-dependent payload or differing shared/payload generation | Confirmed for the recorded controls; runtime acquisition still checks repeated live captures |
| NI3 | ARM64 29695 retains the guest-owned WoW64 startup layout | Frozen x86/x86-LAA main/thread and resource observations | Installed x86 NLS startup | Companion geometry, shared information, section/header, aliases and lifecycle | Any captured layout or model ownership mismatch | Native observations confirmed; model results recorded in the validation ledger |

Shared regressions replay the retained initialization and MUI corpora for both
admitted builds. The installed Windows tests separately exercise real host
snapshot acquisition, actual ARM64/x86 NTDLL leaves, strict argument cleanup,
independent file bytes and the read-only guest shared page. The existing CI job
runs `nls` and `mui` filters alongside `csr`; no CI job is added.

The installed x86 NLS tests also require the independently measured
[29695 WoW64 startup state](../native-wow64-startup-information/README.md).
The first run passed ARM64 initialization but rejected x86 startup at its
existing finite profile gate. Four fresh native information/resource producers
established matching companion geometry and shared-section state before that
prerequisite was admitted. Its captured-profile and lifecycle tests run in the
same existing CI job. This adds no blanket admission of other NT profiles.

| Impact | Remaining scope | Effect |
| --- | --- | --- |
| High | Full installed-DLL startup and the unchanged hardware-fault fixture | This qualification establishes only NLS initialization and query behavior |
| High | MUI cache mutation and other unmeasured NT profiles | Remain separate implementation boundaries; no success stub or blanket version substitution |
| Medium | Independent AMD64 kernel and other Windows builds | Process ABI controls on ARM64 do not prove another kernel profile |

## Validation

Rust 1.95.0, locked dependencies and empty core features are used on every host.
The counts below are selected test functions; the initialization/MUI functions
internally replay 632 initialization cases and 10,080 query rows across the two
admitted builds. Every selected suite below has zero failures and zero ignored
tests.

| Host | `nls` | `mui` | WoW64 startup/lifecycle | Complete C API |
| --- | ---: | ---: | ---: | ---: |
| macOS ARM64 | 22 | 8 | 7 | 191 |
| Linux x64 container | 22 | 8 | 7 | 191 |
| Windows ARM64 native | 30 | 13 | 7 | 191 |

Windows also passes 39 object-namespace tests. Installed tests cover independent
file bytes/padding, actual ARM64 and x86 initialization leaves with real unmap,
and generation in the read-only guest shared page. The first Windows attempt
retains its 27-pass/3-failure result at the unqualified WoW64 prerequisite; the
final result follows its independent qualification, without relaxing assertions.
The seven existing startup-observer projection tests also pass.

The macOS/Windows source frames retain the separate native-entry draft. The
Linux frame excludes that draft and unrelated Windows-only leaf refinements;
the changed shared runtime and replay sources match. These are library/C API
checks; they do not establish a new linked Assist shipping artifact.

The unchanged original fault fixture now completes its ARM64 case, including
native VEH/context continuation and exit zero. The x86 case stops at
`NtQueryInformationProcess` class 37 because `ProcessImageInformation` copying
is not qualified for the installed 29695 kernel. The overall fixture therefore
still fails. Original binaries, source, assertions, 60 s per-architecture
deadline, 16,384 turns and 4,096-instruction slices remain unchanged.

The full Linux/macOS/Windows installed-library objective remains active.
