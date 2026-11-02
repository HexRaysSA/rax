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

On the measured ARM64 kernel, native ARM64 and x64 entries probe the entire declared output span, with
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
The original retained 8,748 cases cover ARM64, x64 and x86 processes on one Windows
10.0.29695 ARM64 kernel. They are not evidence of three physical kernel
architectures. ARM64 and x64 case rows agree exactly; WoW64 differs as described
above. Every retained status, observed byte and four-page protection transition
in this 8,748-case corpus is replayed through the actual RAX dispatcher on
Windows, macOS and Linux.
A second retained campaign adds all 5,832 x64 and x86 cases from Windows
10.0.20348 AMD64. Its complete stdout and original manifest are preserved in
[amd64-20348](amd64-20348/provenance-v1.json), bound to the CI job, producer
hashes, image hashes, and actual mapped providers. The legacy collector reported
`host.machine=AMD64` on the `windows-2022` runner; it did not call
`IsWow64Process2`. That attribution is explicit in the provenance record.

The selected native kernel owns the length contract:

| Captured kernel | Native machine | Accepted output length |
|---|---|---|
| 10.0.20348 | AMD64 (`0x8664`) | Exactly 32 bytes |
| 10.0.29695 | ARM64 (`0xAA64`) | At least 32 bytes |
| 10.0.29698 | ARM64 (`0xAA64`) | At least 32 bytes |

The 20348 matrix changes 77 native64 and 510 WoW64 status/protection decisions
relative to 29695. Twelve WoW64 differences change only which guard remains;
checking status alone misses them. Native64 still probes the declared span and
optional length pointer before rejecting a mismatched length. WoW64 retains its
null-output and bounded-workspace checks, rejects the size before copying output,
and writes the required length through the caller's optional pointer. A failed
length store retains its observed guard and aliasing behavior.

The dispatcher reads `NativeRuntime.version` and the captured namespace's
`native_machine`; changing the guest-advertised version cannot choose a copy
profile for non-exact lengths. A successfully captured 32-byte record is served
for an exact-size request on any selected kernel: acquisition already validated
that native call, its returned size, and every byte. Unknown build/machine
combinations reject other sizes explicitly before record or length stores.
They do not inherit a nearby build. The fixed 32-byte host acquisition and
public C ABI are unchanged.

The portable retained replay now checks all 14,580 cases, including exact bytes,
output/length aliases, last-error sentinels, and all four page protections.
Additional cases cover arbitrary policy bits, both measured size rules, spoofed
guest versions, adjacent builds, wrong machines, and absent native identity.
Fresh manifests require `IsWow64Process2`'s actual native machine, independently
of the Python or probe executable ABI. Kernel-private behavior on other builds
remains subject to fresh native controls.

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
Windows, selected using `IsWow64Process2` rather than `platform.machine()`. Both retained and fresh replay tests run; missing declared observations
are failures. CI invokes this within its existing C API job and preserves the
native artifacts even on failure. No additional runner lane is required.

This feature addresses class 164 only. Subsequent startup services and protected
ordinary-token IFEO acquisition remain separate process-emulation boundaries.
At the time of the original class-164 campaign, installed ARM64 CMD advanced to
class 189. That historical stop is not a current full-process qualification.

The original 29695 implementation passed complete, unfiltered owning-library tests,
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

The profile correction reproduces the 20348 baseline mismatch
`x64/1638/0/0/33`: the old dispatcher returns success while the native observation
returns `STATUS_INFO_LENGTH_MISMATCH` (`0xC0000004`). The corrected dispatcher
passes all 14,580 retained cases and replays the current 29698 campaign's 8,748
cases on each of the three host systems. Complete, unfiltered owning-library
runs, C API tests, Windows CLI integration tests and all-target builds pass:

| Host | Library passed | C API passed | CLI passed |
|---|---:|---:|---:|
| macOS ARM64 | 8,934 | 192 | 8 |
| Linux x86-64 container on ARM64 macOS | 8,924 | 192 | 8 |
| Windows ARM64 VM | 8,251 | 191 | 10 |

Each library run has zero failures, the same two existing ignored microkernel
tests listed above, and zero filtered tests. The retained selection runs four
tests on macOS and Linux and five on Windows, where it also executes installed
NTDLL leaves; the fresh-corpus selection runs one exact replay test per host.
macOS passes Clippy with warnings denied and all 12 workflow-pin checks.
Archived executables, compiler dependency records and 7,438 frozen input hashes
bind these results to the corrected source. This qualification text was updated
after execution; it changes no compiled input. The Linux container results do
not establish physical x86 execution.

| ID | Assumption and dependent result | Stress test and falsification probe | Status |
|---|---|---|---|
| P5 | The legacy 20348 CI observations belong to AMD64, as attributed by its `windows-2022` runner and `host.machine`. This selects the retained exact-size profile. | x64 Python on ARM64 could confuse executable and native identity; the updated fresh collector requires `IsWow64Process2` and rejects a mismatched profile during replay. | Retained for legacy provenance; fresh captures use the direct native API. |
