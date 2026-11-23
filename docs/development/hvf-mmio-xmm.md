# XMM transfers through Intel HVF MMIO

## Legacy SSE2

Legacy SSE2 MOVD and MOVQ memory operands transfer 4 or 8 bytes. Loads
replace the destination XMM register with the zero-extended device reply.
Stores submit the low 4 or 8 bytes of the current lane in little-endian
order. All forms preserve RFLAGS, GPRs, and upper YMM/ZMM bits.
[Intel Software Developer's Manual, Volume 2, MOVD/MOVQ and MOVQ](https://cdrdv2-public.intel.com/825743/325462-sdm-vol-1-2abcd-3abcd-4.pdf)

The planner recognizes memory forms with mandatory prefix `66` and
opcodes `0F 6E` and `0F 7E`, as well as the `F3 0F 7E` load and the
`66 0F D6` store. At `6E` and `7E` under the `66` prefix, REX.W
selects an 8-byte transfer. The existing translated EPT exit checks
validate direction, linear address, exact device width, and RAM exclusion.

A pending load retains its XMM index, width and instruction length in
the native CPU checkpoint. Existing pending-record variant ordinals are
preserved. Stores use the existing output record with immutable bytes.
The deferred I/O owner retires the instruction after completion and
retains a failure without repeating the device transaction.

The native owner uses the full SDK XSAVE image. An inactive SSE component
reads as zero regardless of the stale lane bytes in the image. On a load,
the owner materializes inactive legacy state before activating the SSE
component. Compact images use the existing normalization path, which
retains the architectural contents of every present extended component.
One overlay takes O(N + C²) time and O(N + C) space for an N-byte XSAVE
image with C component descriptors.
[Intel Software Developer's Manual, Volume 1, XSAVE and XRSTOR](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The EPT record identifies one ordinary legacy SSE2 device operand. | High | Exercise all six encodings and reverse their reported directions. Require the exact width and reject the mismatched exits. |
| The owner changes only the destination architectural XMM lane. | High | Compare the complete standard image around XMM0 and XMM15. Seed inactive SSE bytes and live YMM upper bytes in both standard and compact images. |
| A detached callback can continue at the same RIP. | High | Capture a pending read and write, destroy the original VM, restore on a fresh SDK owner, and complete the same packet once. Check final RIP, RFLAGS and XSAVE state. |

The parent metadata rejected all six encodings as unsupported. The
candidate passed the 109-case MMIO suite and the 8-case translation suite.
Independent x86-64 Linux execution against ordinary RAM matched all six
encodings. It verified the transfer width and value, destination XMM
value, preserved upper YMM bits, RFLAGS and adjacent memory. This
exercise covers Intel instruction semantics. All 98 cases in the Intel
SDK-model owner suite passed with no exclusions. Its XMM regression
preserved the XMM and extended state, resumed read and write packets
after destroying the source VM, and verified a single retirement at the
expected RIP. The model replaces the hypervisor API with test storage.

The `legacy-xmm` hosted Intel profile runs all six cases directly and
after restoring a fresh vCPU. The Intel macOS consumer cross-build linked
and passed strict signature verification with the hypervisor entitlement.
All 21 prepared-consumer tests and 16 pinned-workflow checks passed.
The complete macOS library suite passed 13,220 tests with 5 ignored, zero
failures, and zero filtered cases.
The hosted Intel run executed all 12 cases on macOS 15.7.9 with the
real Hypervisor.framework backend. The runner verified the prepared
consumer signature and reported six successes on a fresh vCPU and six
after detached restoration. Its availability probe reported an
untranslated Intel process in a hypervisor guest. Physical Intel macOS,
wider vectors, and mixed RAM and device operands remain open.

[Hosted execution observations](https://github.com/HexRaysSA/rax/actions/runs/44711344124)

- Tested commit `44c81f236c7e2399913f2a5df4aafe88ef948370`
- Signed consumer SHA-256 `b489c25de09f64b800351ca8e3f6e459eafa55ed54f2eb3586e1e2e5abf42da4`
- Observation stream SHA-256 `89593872de38c050034d9e0e320510e64710af12c373dc5cb45d4ee7fbbf34c1`

## VEX scalar transfers

Six VEX MOVD/MOVQ forms use the same 4-byte and 8-byte device transactions.
VEX loads also clear the destination's architectural upper lanes. The
pending input record distinguishes legacy and VEX completion while retaining
the established serialization of legacy records. Stores use the same
immutable output packets as the legacy forms.

The composed portable MMIO suite passed all 117 cases, including the prior
pending-record formats. Both direct and detached-restore execution of all
six forms passed on Intel macOS 15.7.9 with SDK 15.5. The runner reported an
untranslated Intel process inside a hypervisor guest. The runtime archive
matched its published digest, and 4,883 engine inputs and 18 consumer and
runner inputs matched Git blobs at the tested revision.

- Tested commit `0a7ec6836fa0ab764a40debd8d9fdcb81882caf9`
- Runtime artifact `14646035309`, SHA-256 `21898e68b7d06c64c02e2c6943a0b06489489719e13d59a08f8d709a268e1fa3`

[Hosted VEX execution](https://github.com/HexRaysSA/rax/actions/runs/44763145540)

## Unaligned 16-byte transfers

The Intel HVF planner admits legacy `MOVDQU` and VEX.128 `VMOVDQU` for
ordinary translated device operands. Each accepted exit carries the full
16-byte operand. Legacy loads preserve upper vector state. VEX loads zero
the destination's upper lanes. Stores preserve both the source register and
flags. The pending CPU record uses distinct, appended variants for whole-XMM
reads and writes. Older scalar packets retain their established ordinals and
width constraints.

| Assumption | Falsification probe |
| --- | --- |
| The unaligned guest operand maps to a contiguous device range. | Reverse the exit direction, alter the reported GPA, or put RAM within the extent. A device callback before validation falsifies admission. |
| The load updates only the architectural destination. | Use independent low and upper lane patterns and compare all 16 registers after completion. Require the VEX form to clear the selected register's upper lanes. |
| The restored transaction retains its full data and retirement point. | Destroy the source after a 16-byte request, restore the native CPU record, send the complete response once, and verify data, RIP and flags after re-entry. |

The metadata baseline at `748b0a593` rejected the newly tested legacy memory
form before device dispatch. The complete repaired MMIO, Intel SDK-model
owner, and ISA oracle executables passed 122, 99, and 102 cases respectively.
Both pending-record codec regressions passed. The 21 prepared-consumer
tests and the 247 tests in the unfiltered ARM64 macOS C API suite passed.
Four independent RAM controls on physical Intel Linux validated the exact
guest encodings at an unaligned address, including preserved and cleared
upper YMM bits and adjacent store bytes. Device-hole behavior requires
native HVF execution.
[Intel Software Developer's Manual, Volume 2, MOVDQU and VMOVDQU](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf)

The first unfiltered Intel-target library invocation ended with SIGKILL
before libtest produced a summary. The log records a process-broker
failure and failure of the x86-64 Darwin `/usr/bin/true` guest at
`0x10005024c` before the kill. The 42-test broker module passed on the same
executable. A clean `748b0a593` parent and an exact candidate rerun both
reproduced the Darwin guest failure at that PC. Host logs did not identify
the SIGKILL sender. The interrupted log SHA-256 is
`4b54784cc26149a0ba3a07cad8b62da1130cb54415d99fd9fe4aeba8a35750e9`.

A separate native Intel Linux run timed out after 3,600 seconds before
libtest printed a summary. The retry used the unfiltered root library
target with optimization level 1 and KVM enabled. The six user-mode
failures observed by the time of publication reproduced in a separate
run at clean parent `11b9a053d3b31ad4456b76e57160d6a812de4b47` on the
same host. On the clean parent, five Darwin ptrace tests reached a
finished-child assertion and the Linux procfs test expected PID 101
and observed 102.
The clean-parent log SHA-256 is
`b7793ca4abcd2d2d565e133bb0c8b22477170a3b386b7a2e31743ee75307fced`.
The unfiltered retry and the hosted Intel macOS device-hole witnesses
remain in progress at publication.

## Aligned 16-byte transfers

The Intel HVF planner admits legacy `MOVDQA` and VEX.128 `VMOVDQA`
when the guest linear address is 16-byte aligned and maps to a contiguous
device range. It checks alignment before invoking a device. It uses the
same 16-byte completion record as the other whole-XMM transfers. Legacy
loads preserve the destination's upper state. VEX loads clear it.

| Assumption | Falsification probe |
| --- | --- |
| The alignment requirement applies to the guest linear address. | Run every offset from 1 through 15 for both encodings and directions. A device effect on a misaligned operand falsifies admission. |
| No guest register or memory update precedes a hardware alignment fault. | On physical Intel, compare the saved RIP and error code, destination bytes and adjacent memory. Under KVM, place the misaligned operand in an MMIO hole and count guest #GP entries and exits. |
| Whole-XMM continuation also covers the aligned forms. | Use independent low and upper lane values for loads and stores. The hosted probe includes direct execution, fresh-CPU restore with the request outstanding, and misaligned accesses without device replies. |

The pre-change planner rejected aligned memory metadata as unsupported.
The repaired Cargo targets `hvf_mmio`, `hvf_intel_owner`, and `isa_oracle`
passed 123, 99, and 102 cases respectively, with zero failures, ignored
cases or filters. The prepared consumer linked as an x86-64 Mach-O and
passed strict hypervisor signature verification. All 54 Python consumer
and workflow tests passed.

Four ordinary RAM controls passed on a physical Intel Xeon E5-1650 v3.
All 60 misaligned encoding/offset combinations took `#GP(0)` at the
instruction RIP. Independent KVM executions of the four forms at
misaligned device address `0x40000083` entered the guest #GP handler
once, resumed after IRET, and reached HLT without an MMIO exit. These
controls cover Intel instruction and KVM device-hole behavior. The
hosted Intel HVF profiles separately exercise Hypervisor.framework.
[Intel Software Developer's Manual, Volume 2, MOVDQA and VMOVDQA](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf)

- Physical Intel RAM log SHA-256 `ff7b7c8844402513015663ac5de4206a72efe5b87b1250c56a418e07f9f9e0b7`
- KVM device-hole log SHA-256 `b559a75016c7604e4633a4f4c657aa1b9bbfe2ef8777f959a58018a7a5f4ce8c`

## Hosted Intel macOS execution

All 76 cases passed on Intel macOS 15.7.9 with SDK 15.5. The runners
reported an untranslated Intel process and a hypervisor guest. The
unaligned commit was `79cd65ea38adee94c316f4d649f9d04320ed7b81`.
The aligned commit was `8be5c610f84c67b90aa893d2e1d3687321d27240`.

| Profile | Direct transfers | Transfers after restore | Guest alignment faults | Hosted run |
| --- | ---: | ---: | ---: | --- |
| Unaligned legacy | 8 | 8 | 0 | [45100578896](https://github.com/HexRaysSA/rax/actions/runs/45100578896) |
| Unaligned VEX.128 | 8 | 8 | 0 | [45100578487](https://github.com/HexRaysSA/rax/actions/runs/45100578487) |
| Aligned legacy | 10 | 10 | 2 | [45100739580](https://github.com/HexRaysSA/rax/actions/runs/45100739580) |
| Aligned VEX.128 | 10 | 10 | 2 | [45100739545](https://github.com/HexRaysSA/rax/actions/runs/45100739545) |

Each restored transfer resumed the outstanding request from a saved
native CPU record after destroying the source VM. The aligned profiles
included four misaligned guest accesses across the two encodings.
Each reached the guest #GP handler once, observed error code zero, and
continued through IRET without an MMIO exit. The verifier matched the
archived executable's signature and hypervisor entitlement, all 4,894
engine inputs and 18 consumer inputs to Git, and the exact guest rows.

| Run | Runtime artifact ID | Artifact SHA-256 |
| --- | ---: | --- |
| 45100578896 | 14785961487 | `f0119c58bfcd5c520cfd920cba3185ee4ee2391f3b2dc61d5ee45bf7776aa4fd` |
| 45100578487 | 14785706347 | `7f09f38e8777c67b3bfb86b0c63039bb2af6bc465261807eb0659ee751e0c19b` |
| 45100739580 | 14785273262 | `c506fe3c85790f7632901db8c920173aba63622c95db6ae5223efab709b20907` |
| 45100739545 | 14785449261 | `48dcc8ff89f6310d2007bc5aec3a360f6042649f5b78ebc37445e1eb4c9b0c2b` |

### Full library result on Intel Linux

The unfiltered library run for the unaligned MOVDQU and VMOVDQU change
finished with 14,246 passed, six failed and 100 ignored. The clean parent
`11b9a053d3b31ad4456b76e57160d6a812de4b47` reproduced all six failure names,
locations and assertion results on the same Intel host and profile. Five
Darwin ptrace cases stopped at the child-status guard in `family.rs:311`.
The Linux procfs lifetime case observed PID 102 when it expected PID 101.

| Run | Log SHA-256 |
| --- | --- |
| Unfiltered library with the unaligned change | `b27c4a3dd848b853eef9de1b295c6c4c8ac186277d8204586d9789200b5a3f42` |
| Same six tests on the clean parent | `b7793ca4abcd2d2d565e133bb0c8b22477170a3b386b7a2e31743ee75307fced` |

## Packed floating-point moves

Legacy MOVUPS, MOVUPD, MOVAPS and MOVAPD and their VEX.128 forms use the
same full-XMM request and completion records. Loads replace all 16 bytes
of the XMM destination. Legacy loads preserve the upper YMM half, and
VEX loads clear it. Stores publish exactly 16 bytes and preserve the
source register. The APS and APD forms check 16-byte alignment of the
guest linear address before preparing a device request.
[Intel Software Developer's Manual, Volume 2, MOVUPS, MOVUPD, MOVAPS and MOVAPD](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf)

| Assumption | Falsification probe |
| --- | --- |
| The SIMD element type leaves the 16-byte transfer unchanged. | Check byte identity and surrounding canaries for both element types, both directions, high XMM indices and VEX2/VEX3. |
| Aligned forms fault before device I/O. | Use the same encoding with nonzero low address bits. The Intel control requires #GP(0) at the transfer RIP and no modification. The native profile requires uninterrupted progress through the guest handler with no device request. |
| A pending checkpoint retains the width and retirement frontier. | Destroy the producer before restoring the native record. Check exactly one re-emitted request, one completion, preserved flags and the first following RIP. |

On a physical Intel Xeon E5-1650 v3, 24 operand-form and direction
combinations matched 204 ordinary RAM transfers and 180 #GP(0) controls.
The control checked all input and output bytes and both halves of YMM15.
Its log SHA-256 is
`5a2e9ad941fd9d82a27e1a4fb2c6fd2bbdecfde90a8f219e4cd121083ab9460b`.

The preceding source rejected the new packed-move test with
`Unsupported`. With both decoders and native planning updated, the
unfiltered `hvf_mmio` and `isa_oracle` binaries passed 124 and 102
cases on Intel Linux. Their combined terminal log SHA-256 is
`58147b088ca49f4f21f94d1e07b74ae72abb2b8c9e8caab30a225a605c718a58`.

The Intel macOS target executed under Rosetta with 99 `hvf_intel_owner`,
124 `hvf_mmio`, and 102 `isa_oracle` passes. A separate signed Intel
consumer linked successfully, and all 54 harness tests passed. The Cargo
log SHA-256 is `d0ed3fdae3851dd4f6c56bc3e7558570734dd2728d1e869dd078040394bae0e0`.
