# SystemCodeIntegrityPolicyInformation

Class 164 supplies a pointer-free 32-byte policy record to installed CMD startup.
The qualified ARM64 CMD request uses length 32 and a null `ReturnLength`.
The dispatcher now serves a process-owned snapshot captured during native runtime
selection. It never forwards guest classes, lengths, pointers or policy changes
to the host kernel.
Returned policy metadata does not establish guest-loader signature enforcement.

The fixed host acquisition uses aligned private storage, requires success and
`ReturnLength == 32`, and compares samples initialized with opposite byte
patterns. At most three pairs are attempted. Missing, incomplete or unstable
metadata produces an explicit unavailable boundary; it does not supply guessed
policy flags. Acquisition takes constant space and at most six fixed queries.

The primary PHNT layout has `Options` at byte 0, `HVCIOptions` at byte 4,
`Version` at byte 8 and `PolicyGuid` at byte 16. All three native observer builds
assert these offsets and `sizeof == 32`. The original header and MIT license
are preserved byte for byte, with pinned Git blob and SHA-256 identities in
[sources.json](sources.json). The header's introductory comment incorrectly
names class 103; its enum associates this record with class 164. Independent
native calls establish the selector used here. Microsoft's shared reference
documents the four-argument API, without specifying this private layout.

Native ARM64 and x64 entries probe the entire declared output span, with
4-byte alignment when length is nonzero, and then the optional 4-byte
`ReturnLength`. They reject lengths below 32 after probing, return the required
length, and otherwise copy 32 bytes before the final length store. Bytes beyond
the record survive. Reached guarded pages lose their guard even when read-only.

WoW64 uses private conversion storage. A nonzero length with null output returns
access violation and stores zero to `ReturnLength`. Other short buffers return
the required length without accessing output. Valid buffers receive only the
32-byte record, without native alignment or tail probing, followed by the
optional length store. A later store fault preserves copied output. Read-only
guarded destinations fail before consuming their guard. The emulated conversion
workspace is bounded by the process arena and x86 address limit; excessive
lengths fail with `STATUS_NO_MEMORY` without allocating proportional host space.

`probe-v1.c` executes 2,916 cases per process ABI: 16 lengths times 14 output
roles times 13 `ReturnLength` roles, plus four opposite-poison controls.
The retained 8,748 cases cover ARM64, x64 and x86 processes on one Windows
10.0.29695 ARM64 kernel. They are not evidence of three physical kernel
architectures. ARM64 and x64 case rows agree exactly; WoW64 differs as described
above. Every retained status, observed byte and four-page protection transition
in this 8,748-case corpus is replayed through the actual RAX dispatcher on
Windows, macOS and Linux.
Kernel-private behavior on other builds remains subject to fresh native controls.

Two additional independent campaigns resolve specific review questions.
[WoW64 entry controls](wow64-entry/provenance-v1.json) show that
`NtWow64GetNativeSystemInformation` rejects class 164 with
`STATUS_INVALID_INFO_CLASS` before either destination is accessed. Eight calls
cover lengths 0, 31, 32, 33 and 64, null output, and null or invalid
`ReturnLength`; every output byte and the length sentinel survive. A separate
class-0 control reports required length 44 with `STATUS_INFO_LENGTH_MISMATCH`.
[Copy-boundary controls](copy-boundaries/controls-v1.json) add 372 native calls:
all 31 interior page-boundary positions, four following-page protections and
three process ABIs. No partial output store is observed. These supplemental
controls are distinct from the original guest replay matrix. Both campaigns
retain their standalone CMake projects and C sources alongside the observations.

The observer binds the actual mapped NTDLL using `GetMappedFileNameW` and
`QueryDosDeviceW`, rather than its logical module path. It hashes that backing
file before and after execution, checks PE architecture and image identity,
and retains compiler output and native records. The x86 process on this host
maps `SyChpe32/ntdll.dll` despite reporting a logical `System32` path.

Verify the retained producer and reference identities on any host:

```sh
python tools/ci/windows_code_integrity_policy.py --verify-corpus
```

On 64-bit Windows with MSVC, CMake and Cargo available, collect and replay fresh
native controls using an unused in-tree output directory:

```sh
python tools/ci/windows_code_integrity_policy.py
```

This captures x64 and x86 processes on AMD64 Windows, plus ARM64 on ARM64
Windows. Both retained and fresh replay tests run; missing declared observations
are failures. CI invokes this within its existing C API job and preserves the
native artifacts even on failure. No additional runner lane is required.

This feature addresses class 164 only. Subsequent startup services and protected
ordinary-token IFEO acquisition remain separate process-emulation boundaries.
Installed ARM64 CMD now advances from class 164 to an explicit unimplemented
`NtQuerySystemInformation` class 189 boundary; the command has not completed.

The frozen implementation passed complete, unfiltered owning-library tests,
C API tests, Windows CLI integration tests and all-target builds on each host:

| Host | Library passed | C API passed | CLI passed |
|---|---:|---:|---:|
| macOS ARM64 | 8,882 | 192 | 8 |
| Linux x86-64 container on ARM64 macOS | 8,872 | 192 | 8 |
| Windows ARM64 VM | 8,196 | 191 | 10 |

Each library run has zero failures, two existing ignored microkernel tests and
zero filtered tests. The ignored tests are
`smir::lower::validation::tests::test_lift_lower_full_microkernel` and
`smir::lower::validation::tests::test_roundtrip_exact_bytes_microkernel`.
macOS also passes Clippy with warnings denied and all 12 workflow-pin checks.
Fresh Windows controls add another 8,748 native cases; both retained and fresh
four-test selections pass, including installed NTDLL syscall leaves.
The public C header remains 73,534 bytes with SHA-256
`baaf643f62c525d923529ccbf75a97505a31831592a8aa91ab9be71f5ec144b5`.
The Linux container results are not physical x86 execution evidence.

| ID | Assumption and dependent result | Stress test and falsification probe | Status |
|---|---|---|---|
| P1 | Class 164 returns the fixed pointer-free PHNT policy layout; this permits fixed host acquisition. | Three compiled layouts, 8,748 native cases, opposite-poison controls; any different native size or layout falsifies it. | Confirmed on the recorded kernel and process ABIs; other kernels require fresh controls. |
| P2 | Two agreeing fully initialized samples define the initial process snapshot. | Change policy between captures or leave poisoned bytes unwritten; bounded acquisition rejects disagreement. Later host policy mutation is outside this immutable snapshot contract. | Retained. |
| P3 | The existing WoW64 native-system-information entry rejects class 164 before probing. | Eight direct native calls cover short and valid lengths plus invalid destinations; a different status or changed byte falsifies the assertion. | Confirmed on the recorded kernel. |
| P4 | A failing 32-byte output copy publishes no partial record. | All 31 interior byte positions and four protections across three native process ABIs; any changed output byte falsifies atomic copy behavior. | Confirmed for the 372 recorded boundary observations. |

High-impact scope finding: this service alone does not complete full installed
process startup. The existing ordinary-token IFEO acquisition failure and any
subsequent unimplemented service remain explicit blockers to that broader goal.
