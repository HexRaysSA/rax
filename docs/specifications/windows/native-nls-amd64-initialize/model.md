# Finite AMD64 NLS initialization admission

Initialization admits native AMD64 kernels 10.0.20348 and 10.0.26100 for x64
and x86 guest views. Selection and guest dispatch use the same predicate,
receiving the already captured native-machine identity. Missing or foreign
machines, ARM64 guest views on those AMD64 profiles, adjacent builds and other
major or minor versions remain unavailable. Existing 29683/29695 behavior is
preserved. MUI snapshot acquisition, dispatch and generation retain their
independent prior predicate; these initialization controls do not qualify MUI.

The new path reuses fixed native initialization capture, immutable bytes,
checked native memory-query geometry, bounded ReadProcessMemory copy and RAII
unmap. No guest pointer, path, handle or length enters host acquisition. Guest
calls retain the existing native 64-bit base-before-locale and WoW64
locale-before-base copy order, including ignored outputs, guard consumption,
readonly faults and retained mapped views. Native argument counts remain four
for native 64-bit and three for x86. Each guest mapping owns its readonly bytes
and budget charge until guest unmap or process teardown.

Independent AMD64 controls in [run 40565964224](https://github.com/HexRaysSA/rax/actions/runs/40565964224)
record 474 initialization calls and 72 protection/free calls: 79 and 12,
respectively, for each x64, x86 and x86-LAA process view on two kernels. Raw
reports and bytes remain in `profiles-v1.json`. All compared statuses, guard
transitions, view deltas and output bytes match the prior contract. Comparison
verifies each actual returned-base byte before relocating its exact output
span; every other changed byte in the complete 4096-byte scratch page remains
exact. Native mapping extents come from installed data:

| Native kernel | locale.nls file bytes | Mapping bytes | Zero padding bytes |
| --- | ---: | ---: | ---: |
| 10.0.20348 | 819456 | 823296 | 3840 |
| 10.0.26100 | 862800 | 864256 | 1456 |

For file extent F and page extent P = 4096 bytes,
M = ceil(F / P) * P and padding = M - F. Thus 201 pages map 823296 bytes on
20348, and 211 pages map 864256 bytes on 26100. The existing 8 MiB
initialization bound, 64 MiB combined snapshot bound and guest VM budget are
unchanged. Capture and initialization take O(M) time and own O(M) immutable or
mapped bytes; profile checks and fixed output work take O(1). Synthetic fixture
bytes test copy and lifetime rules. Installed leaves independently compare
all actual file bytes and padding. x86-LAA observations qualify these calls,
without establishing high-address allocation policy.

The native driver's executed CRLF bytes have SHA-256
`57147c3fe5586b3de4fd5caa6b809aa3b5eabc4751c4edfd5774d57ddd92ec7a`.
Replacing every LF in the canonical 9158-byte source with CRLF reproduces that
9374-byte identity exactly. Frozen C++ producers retain their original
identities. No executed native producer is edited or substituted.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| NM1 | The two measured AMD64 kernels retain the initialization call and copy contract. | All 474 native initialization records agree, including complete first-page changes. | Finite initialization admission. | Invalid, readonly, guarded, unaligned and aliased outputs; retained mappings. | Replay the raw native corpus, exact guard/status/output bytes and VM charges. | Confirmed by native controls, full model replay and installed AMD64 leaves. |
| NM2 | Mapping extent and bytes come from the selected host snapshot. | Native readonly geometry and independent file extents differ across the two kernels. | Correct payload, bounds and lifetime. | Different file sizes, padded tail, missing snapshot and resource exhaustion. | Full installed-file and padding comparison, native leaf, actual mapped extent and unmap. | Confirmed by installed files, padding, native leaves and owned unmap. |
| NM3 | Initialization qualification cannot extend MUI implicitly. | Source consumer audit, independent admission and negative MUI tests. | Preserved unavailable MUI behavior. | AMD64 initialization admitted while MUI remains unavailable. | Exact machine/version/guest predicate matrix, installed snapshot and MUI regressions. | Confirmed by admission, missing-snapshot and unavailable-MUI tests. |

Clean master qualification excludes the separate exception-entry candidate:

| Host | `nls` passed/failed/ignored | `mui` passed/failed/ignored | C API passed/failed/ignored |
| --- | --- | --- | --- |
| macOS ARM64 | 26/0/0 | 10/0/0 | 191/0/0 |
| Linux x86-64 container on ARM64 host | 26/0/0 | 10/0/0 | 191/0/0 |
| Native Windows ARM64 build 29695 | 34/0/0 | 15/0/0 | 191/0/0 |

The clean Windows C API gate uses one test thread and unchanged per-test
execution deadlines. An earlier combined candidate run retains 190 passes and
one supplied-file x86 timeout at its original 5 s limit under heavy host load;
its complete serial rerun passes 191 tests using the identical executed binary.
The unchanged original ARM64/x86 fault fixture passes in that combined source
frame. These results are separate from clean master qualification. A clean
Windows v2 compilation was interrupted by an external VM reboot before any
test verdict; the cause is unknown, and this task requested no restart. Its
receipt and logs remain archived. The subsequent v3 run has its own source
preflight and results.

Native AMD64 C API tests pass 191 cases and the installed NLS leaves pass twice
in [run 40570458704](https://github.com/HexRaysSA/rax/actions/runs/40570458704).
Kernel 20348 and the positive CSR gate establish the captured native-machine
0x8664 branch, excluding an unavailable-profile interpretation of the NLS leaf.
The unchanged original x64 case completes fault, VEH and context continuation,
then exits with status 0. Both unchanged observers independently report x64
Exited(0) after 565 turns. The whole original test fails in x86 at
`NtWow64CsrClientConnectToServer`, requiring an unmeasured selected-server and
shared-section profile; observer v2 records 415 turns at PC `0x140000`.

The canonical native corpus records 16 retained late WoW64 mappings: four each
in x86 and x86-LAA on each kernel. The initial new aggregate assertion of eight
was incorrect; all individual comparisons and 72 protection cases already
passed. The corrected assertion of 16 and subsequent gates preserve all
original source, fixtures, assertions and execution limits.

High impact: the complete original AMD64 startup test still fails in its x86
case, so the separate exception-entry candidate remains excluded from master.
Full Linux/macOS/Windows host-library-backed process emulation, complete
WoW64 CSR startup, linked shipping artifacts, packages and installed Assist
runtime qualification remain incomplete. Public and private ABIs, dependency
pins, optional features and package layout do not change. The original fault
source, PE binaries, whole Rust test, assertions and execution limits remain
unchanged. The existing C API CI step moves before startup regressions with
its body unchanged, preserving independent results when startup fails.
