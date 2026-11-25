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

### Packed moves on hosted Intel macOS

Both profiles passed at `fe94eaf17b034575179b4a3b6a4fbed1ece32a52`
on Intel macOS 15.7.9 (24G830) with SDK 15.5, inside hosted VMs.
Each profile ran 18 direct transfers, 18 transfers after restoring the
outstanding request, and six guest #GP(0) cases. The newly admitted
packed moves account for eight direct transfers and eight restored
transfers in each profile. The full transfer set covered
all 16 destination bytes and the architectural upper YMM state. Each
alignment case entered the guest handler without a device access.

| Profile | Hosted run | Runtime artifact ID | Artifact SHA-256 |
| --- | --- | ---: | --- |
| Legacy | [45105063520](https://github.com/HexRaysSA/rax/actions/runs/45105063520) | 14787347682 | `6aba4a0d0c2f7b66a5239def51d2166aa1c289058370b565a3454fd7e321bd54` |
| VEX.128 | [45105064902](https://github.com/HexRaysSA/rax/actions/runs/45105064902) | 14787268668 | `b386157a4b4124b4c14d4e578fe082f91a18b133b64aba7d355d11dbbf00e937` |

The independent verifier checked 4,895 engine and 18 consumer inputs
against Git, the complete guest result rows, and the archived signed
consumer's hypervisor entitlement. The signed executable SHA-256 was
`3aa79d8ffeecb3df1dae4f82ed8df59222551d317287965b048bb386fee9e254`.

## Scalar floating-point moves

Legacy MOVSS and MOVSD and canonical VEX.128 VMOVSS and VMOVSD
transfer exactly 4 and 8 bytes, respectively. Memory loads clear the
unused upper bits of XMM. Legacy loads preserve the upper YMM half,
while VEX loads clear it. Stores publish the scalar bytes and preserve
the source register. Legacy register-to-register forms retain a
separate merge dependency in decode metadata. Device admission
requires a memory operand, the reserved VEX.vvvv value, and the
canonical L=0 encoding for VEX forms.
[Intel Software Developer's Manual, Volume 2, MOVSS and MOVSD](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf)

| Assumption | Falsification probe |
| --- | --- |
| The scalar register is carried in the low bytes, while the legacy memory load clears the rest of XMM only. | Seed both halves of YMM and compare all lane bytes after both directions and prefixes. |
| A scalar store has no effect on adjacent bytes. | Use byte canaries at every offset from 0 through 15 for all 12 raw Intel encodings. |
| A restored request has the original scalar width and retirement frontier. | Destroy the source before rebuilding the CPU with a held request. Check one completion, the exact next RIP and unchanged flags. |

The scalar regression failed at the preceding source with a decode
result of `Unsupported`. On physical Intel Linux, the unfiltered
`hvf_mmio` and `isa_oracle` targets passed 125 and 102 tests.
The two test logs have SHA-256 digests
`b8f892ba77d1f5ef40ba51e5703b61a76f1eaa73e1f812fdf6d2b44a17b617d3`
and `70f377f0afc9b911c2afe860c7932c717bfa942de4b1758c629f5865349ff896`.

On a physical Intel Xeon E5-1650 v3, 192 ordinary RAM transfers matched
the expected operand and adjacent bytes. Four reserved VEX.vvvv
controls took #UD at the expected instruction RIP. The standalone
oracle log SHA-256 is
`880cff1fd2ef24cf9b8c4a9e6bd30d87a0aa3fd6109552fa64d6925c459f9bfc`.

Under Rosetta, all 99 Intel owner, 125 MMIO and 102 ISA oracle cases
passed, with zero failures, ignored or filtered cases. The signed
Intel consumer linked and passed strict signature verification.
All 54 harness tests passed. The Cargo log SHA-256 is
`e9f430de60565360bc1f7ea43f79bda0dba4a07dd87b7df33a0a86c0bd0ebaad`.

### Scalar moves on hosted Intel macOS

The legacy and VEX profiles both passed at
`0413b84d0984633de7bb9798dcf3c7621368d631` on Intel macOS 15.7.9
(24G830) with SDK 15.5, inside hosted VMs. Each profile ran 22 direct
transfers, 22 after destroying the source and restoring the held
request, and six guest #GP(0) cases. The newly admitted scalar
forms account for four direct and four restored transfers per
profile. The guest checks the full vector state, exact device width
and bytes, and the instruction retirement boundary.

| Profile | Hosted run | Runtime artifact ID | Artifact SHA-256 |
| --- | --- | ---: | --- |
| Legacy | [45106991272](https://github.com/HexRaysSA/rax/actions/runs/45106991272) | 14787898106 | `8351e7abbbc3694787aef02d2393bdbeb4f910cb6f0b40542f15d7c989131029` |
| VEX.128 | [45106994761](https://github.com/HexRaysSA/rax/actions/runs/45106994761) | 14788491444 | `fd00bf0ac0454b9e67928e76fd8f2a7c6548e3dd6b9d1da6f24d1844aa06a897` |

The independent verifier matched 4,895 engine and 18 consumer inputs
against Git, verified the signed consumer's hypervisor entitlement,
and checked all 100 guest observation records. Both runs used the same
signed executable SHA-256
`ee0bdd05d6cd9e92f79877fdf64ff177a50af24d293a5e97c13b5b4d9c98eaf9`.
The observation digests are
`e5c4bf74f0b80870a10e1a6cf70df3b45bd243f93ad9657328c7960ff89dd456`
for legacy and
`41a708193462f3974824704721ac5301fd05135f9c541f2b6107922da7fcaeff`
for VEX.128.

## 256-bit VEX moves

Intel HVF handles the memory forms of VEX.256 VMOVDQU, VMOVDQA,
VMOVUPS, VMOVUPD, VMOVAPS and VMOVAPD as 32-byte transfers. The planner
validates the entire operand as contiguous device space. The owner checks
CR4.OSXSAVE and the SSE/AVX bits of XCR0 before publishing the request.
The aligned forms require a 32-byte boundary.

A read completion replaces the low XMM lane and the YMM upper lane,
clears any higher destination lane, and preserves the other registers and
MXCSR. A store publishes all 32 source bytes and preserves the vector
state. An inactive upper bank must become architectural zero before
activating it, so a load cannot expose stale upper bytes from neighboring
registers. State overlay takes O(n) time and space in the bounded XSAVE
image length. A held request records its width, operand provenance, and
retirement boundary. Older record variants keep their original encoding.
[Intel Software Developer's Manual, Volume 2, VMOVDQA and VMOVUPS](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf)

| Assumption | Falsification probe |
| --- | --- |
| The selected VEX forms transfer 32 bytes and use only the affected register. | Run both directions through both VEX prefix lengths across offsets 0 through 31. Compare canaries, the complete register, and precise #GP(0) state. |
| The selected VEX width governs alignment and data breakpoints. | Attempt an aligned form at offset 16 and watch the last operand byte and the first byte beyond it. |
| A held transfer can resume without source CPU state or repeated device dispatch. | Capture with a request pending, destroy the source CPU, import the native record, and require the same request, one completion, and the exact next RIP. |

The preceding source rejected the VEX.256 planner regression as
unsupported. On physical Intel Linux, the updated source passed all
126 MMIO planner cases, all 102 ISA oracle cases, and the full x86-64
suite with 28,561 passes and 3 ignored. The combined Cargo log SHA-256
is `a060515ac38f2dc7bbf73fe04bd97c86c7929172aab5c85a0a8a4db90caaa9cd`.

The independent physical Intel Xeon E5-1650 v3 control exercised 24
operand-form, direction, and prefix combinations over 32 offsets. It
observed 396 ordinary RAM transfers and 372 precise #GP(0) alignment
faults. Its stdout SHA-256 is
`ca9b7a778b636b05e734db8a69068908c566956664ca43703b2b5446d79c2f8d`.

The Intel macOS target running under Rosetta passed 100 simulated owner,
126 planner, and 102 ISA oracle cases. The Cargo log SHA-256 is
`77912c739089f9e8d25c8c9cc59f00eabdfecae712520c4e78fcd696974d0eb1`.
The signed Intel consumer linked and passed strict verification.
All 54 Python harness tests passed with compatibility-mode and VEX.256
profiles both registered.

The 46 Intel context and XSAVE library tests passed on Linux,
including both new YMM cases. Their Cargo log SHA-256 is
`274641761a820882722de192ac9ea7654a057022901aac516cb2fa71795cc53a`.

Hosted run [45109199728](https://github.com/HexRaysSA/rax/actions/runs/45109199728)
at `fdd58e2f543652573319a794c852f8892979dc5a` recorded all 24 new YMM
transfers among 74 completed cases. Verification matched 4,895 engine
inputs and 19 consumer inputs against Git and checked the executable's
signature and entitlement. The first YMM fault case reached HLT with the
correct next RIP and marker, then the fixture compared RDI
`0x40000090` against the XMM offset `0x40000083`. The fixture now compares
the unchanged register with the actual input. That first run did not
qualify the six YMM fault cases. Runtime artifact `14789082181` has
SHA-256 `b75f09c05cfeba237afde432489a16824b801e26abf8b6d98b9c9b4b58cc74ce`.

### VEX.256 on hosted Intel macOS

After the fixture correction, hosted run
[45110104241](https://github.com/HexRaysSA/rax/actions/runs/45110104241)
passed all 80 cases at revision
`7aa582e930482130d5386e9148b78e2a246b5b5b` on Intel macOS 15.7.9
(24G830), SDK 15.5, inside a hosted VM. The 256-bit cases account for 12
direct transfers, 12 transfers after restoring the pending request into
a fresh CPU, and six #GP(0) cases. Each fault verified one handler
visit and the saved fault RIP, and checked the continuation marker,
RDI, RFLAGS and vector banks after IRET. The six 128-bit alignment
controls and all 44 other transfers also passed.

Independent verification matched all 4,895 engine inputs and 19
consumer inputs against Git, checked all observation rows, and verified
the Intel executable's signature and hypervisor entitlement. Runtime
artifact `14789423250` has SHA-256
`f76825086d7ae99c73e14578a1b67b1ae516bfd5232c315f013ba8d1a0b718db`.
Its observation SHA-256 is
`4e71f004e31b07850d41f6ef347a6f7160984c4be26bd356c444ffaf4d8b4abe`.
The signed executable SHA-256 is
`30adf73b5b75863f78f887a45ba03e4211a9df35142e61afaf7d9e4334705f74`.

## IA-32e compatibility-mode MMIO

### 32-bit code segments

The 32-bit compatibility profile enters with CS.L=0, CS.D=1, and
IA32_EFER.LMA=1. It uses nonzero DS or FS bases, general-purpose
register and moffs encodings, both address sizes, and scalar and
packed XMM operations. The profile checks the resolved GPA, all
payload bytes, register lanes and flags, and the continuation RIP
and marker. Restore cases destroy the source CPU and VM, recreate
the CPU, check the saved execution mode, and reobserve the same held
request before completing it.

| Width | Native direct | Native after restore |
| --- | ---: | ---: |
| 1 byte | 2 | 2 |
| 2 bytes | 2 | 2 |
| 4 bytes | 2 | 2 |
| 8 bytes | 2 | 2 |
| 16 bytes | 2 | 2 |

Hosted run [45108768817](https://github.com/HexRaysSA/rax/actions/runs/45108768817)
at `6da3000e5367d878b8ebed3aa6cd8d232e1d2d1d` completed all 20
cases in an untranslated Intel process on virtualized macOS 15.7.9
(24G830), SDK 15.5. Verification matched 4,895 engine inputs and
19 consumer inputs against Git, checked the signed executable and
hypervisor entitlement, and checked all 20 rows. Runtime artifact
`14789405159` has SHA-256
`8b68e9ccca7c1a07e50d526d5ce8a2335336ac63534e2674c3b3065e87b02faa`.
Its observation SHA-256 is
`e8a1b7fb42dfdcc678d582c90d5e0674ead95cc675b9c8c28a46a2ffae265c0b`.

After the two compatibility profiles began sharing VM construction and
request checks, hosted run
[45111980380](https://github.com/HexRaysSA/rax/actions/runs/45111980380)
at `f3fb15f9d2dbc2da8b360365f8fb09aabefeccab` passed all 20 cases
again on the same macOS and SDK versions. The observation file is
byte-for-byte identical to the first run. Verification matched 4,896
engine inputs, 19 consumer inputs, and the signed executable. Runtime
artifact `14790696209` has SHA-256
`2d19cf16697aba4f579cc3909facb90e9f053e30d10d4686cd992d0deb799a8e`.

The direct KVM API witness on a physical Intel Xeon E5-1650 v3
executed all ten forms with the same addressing and bytes over
ordinary RAM and verified eight device-hole forms. KVM split each
16-byte transfer into two consecutive exits and reported internal
emulation error 1 for both MOVSD hole accesses before dispatch. Both
MOVSD RAM controls completed. The witness output SHA-256 is
`bba2954cb814e1bd7b12e006da3ae314a3531ab6242f5f3f0b54f6f27a1bb67c`.

### 16-bit code segments

This profile uses CS.L=0, CS.D=0, CS.base=`0xe000`, and a guest entry
offset of `0x2000`. The instruction fetch resolves to `0x10000`. It
checks DS, the implicit SS selection for BP+SI, a GS override, and a
32-bit address override with an offset beyond 16 bits. The expected
operand GPA is `0x40000080`. The same continuation and held-request
checks apply to the scalar and packed operands.

| Operand width | Native direct | Native after restore |
| --- | ---: | ---: |
| 1 byte | 2 | 2 |
| 2 bytes | 2 | 2 |
| 4 bytes | 2 | 2 |
| 8 bytes | 1 | 1 |
| 16 bytes | 1 | 1 |

Hosted run [45110996856](https://github.com/HexRaysSA/rax/actions/runs/45110996856)
passed all 16 cases at revision
`172afefd95f52c1bce725d6b76fa4095aa930d87` on Intel macOS 15.7.9
(24G830), SDK 15.5, inside a hosted VM. Independent verification
matched all 4,895 engine inputs and 19 consumer inputs against Git,
verified the signed executable and hypervisor entitlement, and
checked all observation rows. Runtime artifact `14790161199` has
SHA-256 `ac14ed84fdf7c45853d398bab8be19b2fbf1396d1bd0485844ba187123e8142d`.
Its observation digest is
`5f2696c080e5f3411150277c7e445adf124788c19193bcc105988a81bdb1fb7c`.

The physical Intel Linux KVM witness completed all eight forms against RAM
and seven against a device hole. The MOVSD load from the hole reported
KVM internal emulation error 1 before device dispatch. The same MOVSD
form completed on both hosted HVF paths. The KVM witness output SHA-256 is
`28ab44a169011735a21ea4011cb9cd35c1d1782258cdeac4bfe9c0df85ee56e4`.

## Streaming vector stores

Legacy MOVNTPS, MOVNTPD and MOVNTDQ publish 16-byte device writes.
Their VEX forms publish 16 bytes from XMM or 32 bytes from YMM. The
planner checks natural alignment and the full guest physical range before
publishing a request. Device dispatch and acknowledgment use the existing
vector store path. The source register and flags survive completion and
pending-request restore. Address validation and payload copying take
O(width) time and at most 32 bytes of payload storage.
[Intel SDM, Volume 2B, MOVNTDQ, MOVNTPD and MOVNTPS](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf)

| Assumption | Falsification probe |
| --- | --- |
| Each encoding writes the full vector without modifying its source. | Test every legacy, VEX.128 and VEX.256 form with register 15 and compare all operand bytes, source bytes and neighboring memory. |
| Misalignment faults before a device effect. | On Intel hardware, test every nonzero in-width alignment offset and verify #GP(0), exact fault RIP and unchanged memory. In HVF, require the guest #GP handler, with no device request. |
| A pending write preserves its width and bytes through restore. | Destroy the source VM and vCPU, restore the native record into a fresh CPU, and compare the request, completion RIP and both vector banks. |

The parent rejected `44 0f 2b 3f` as unsupported metadata. The failing
regression log has SHA-256
`8cbd25ba2dad720c6456b176a6950286fa64e9dd11fe44284255a0d286b19ea3`.
On a physical Intel Xeon E5-1650 v3, all 15 aligned ordinary-RAM stores
published the expected bytes after SFENCE and preserved YMM15. All 321
misaligned cases reported #GP(0) at the instruction and preserved the
entire memory range. The hardware log SHA-256 is
`3ed7b623176855fb3591139329aebc26ffff845d5d9d5fb75630eb57f558c940`.

On Intel Linux the fixed regression passed. The unfiltered `hvf_mmio`,
`isa_oracle`, and `x86_64` targets passed 127, 102, and 28,561 cases
respectively. The x86-64 target reported three ignored cases. The
combined Cargo log has SHA-256
`8f4db62039746a3c8f04bd6806379aec04843e625bc1ffc1aaddaf80a52db399`.

The direct KVM witness on physical Intel completed all 15 forms over
ordinary RAM, including exact payload and source-register checks. All 15
misaligned device-hole cases reached #GP(0) with no device write. The
three aligned legacy stores reached device dispatch as two contiguous
8-byte writes each. The twelve aligned VEX stores reported KVM internal
emulation error 1 before writing any device byte. The aligned and
misaligned MOVDQA controls also passed. The output SHA-256 is
`6960b7685365c0ef1a64cf15df7d25aacd17f7c0ce3a3d93433d93e0190c0590`.

The macOS Intel-target build on Apple Silicon passed all 100 modeled
Intel owner cases, 127 MMIO planner cases, 102 ISA oracle cases and 16
workflow pinning cases. All 54 Python tooling tests passed. The linked
x86-64 consumer passed strict Hypervisor entitlement signature
verification. The Cargo log SHA-256 is
`7dfe7180267c19022641ddc11146e2c29ef9cc0395b579a12333105838b8b0c9`.

### Streaming stores on hosted Intel macOS

Both streaming profiles passed at
`64231ad19dfc9bf6dd728d8387b2ac23b77aedfb` in an untranslated Intel
process on virtualized macOS 15.7.9 (24G830), SDK 15.5. The restore cases
checked the re-emitted held write and its exact bytes before completing
it and reaching the first following instruction. The fault cases checked
the saved RIP and error code, exactly one guest #GP handler visit, and
continuation through IRET.

| Profile | Bytes | Direct | Restored | Faults | Hosted run |
| --- | ---: | ---: | ---: | ---: | --- |
| Legacy | 16 | 3 | 3 | 3 | [45116138845](https://github.com/HexRaysSA/rax/actions/runs/45116138845) |
| VEX.128 | 16 | 6 | 6 | 6 | [45116138484](https://github.com/HexRaysSA/rax/actions/runs/45116138484) |
| VEX.256 | 32 | 6 | 6 | 6 | [45116138484](https://github.com/HexRaysSA/rax/actions/runs/45116138484) |

Independent verification matched 4,896 engine inputs and 19 consumer
inputs to Git and checked the consumer's signature, entitlement and all
45 rows. The signed executable SHA-256 was identical across the runs,
`32588ee308bf51765f6563b461c44809e67946c1b059b5e26eb199238964f873`.

| Runtime artifact | Artifact SHA-256 | Observation SHA-256 |
| ---: | --- | --- |
| `14792705624` | `c75495bdb706661c315f051052f4ea33147d00e46aaa729f215cee51811a945e` | `ad6529032cdb61647d5faad2eab4304d337260b23130cebc72ae59564ad38634` |
| `14791784352` | `9d6a371b961235dd4238cf05e1ffdd8674413085af3814b3ae5f9925ff6d9758` | `42d2851855036373f743425e48d8e334da922e5427711f31d2781f12ad131ba2` |


The same signed build repeated all 130 ordinary vector cases after the
shared harness change. All 50 legacy rows and 80 VEX rows matched the
prior observation files byte for byte. Runtime artifacts `14792091707`
(legacy) and `14792350901` (VEX) have SHA-256 digests
`fae81ef664b561912ab5660b8f970f10dea822ac52ea6bbe429d256fb862302b`
and `e106a7ab8cee66745afcfb6d0421e1aac1b4e309563e602fd34d759bc4b818ba`.
[Hosted legacy repeat](https://github.com/HexRaysSA/rax/actions/runs/45116138869)
[Hosted VEX repeat](https://github.com/HexRaysSA/rax/actions/runs/45116138813)

## High and low XMM lane transfers

The memory forms of MOVLPS, MOVHPS, MOVLPD and MOVHPD transfer exactly
8 bytes. An SSE load preserves the other lane of the destination and its
upper YMM state. An AVX load reads the other lane from its explicit
merge source and clears the upper destination state. Stores publish the
selected lane and preserve all registers. The pending read stores the
eight merge bytes before device dispatch. Read completion and write
acknowledgment use the common bounded vector retirement path. The new
pending-read discriminant follows the existing variants. Payload selection
and merge use constant time and space.
[Intel SDM, Volume 2B, MOVHPD, MOVHPS, MOVLPD and MOVLPS](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The unaligned memory operand is eight bytes wide. | High | Use an operand at RDI+3 for both directions, both lanes, both prefixes and legacy, VEX2 and VEX3 encodings. Check the translated address and memory width. |
| The preserved lane is independent of the device reply. | High | Use separate destination, merge source and input values. Round-trip pending reads with both lanes, then complete with exactly eight bytes. Reject seven and nine bytes without register or RIP changes. |
| VEX.128 uses vvvv only for the load's merge source. | High | Reject L=1 and store encodings with nonreserved vvvv. Reject register-only forms at the device interface. |

The baseline rejected `44 0f 12 7f 03` before planning an MMIO load.
The candidate passed the full local `hvf_mmio`, `isa_oracle` and
`ci_actions_pinned` targets with 130, 102 and 16 cases, respectively.
On Intel Linux, `hvf_mmio`, `isa_oracle` and `x86_64` passed 28,793
cases with three ignored, zero filtered and zero failures. The
complete Cargo log SHA-256 is
`5b316f2a4549f594d44a89d6824c151233fc5cc35cd33624ea29933b5dca2521`.
The Intel macOS cross-target run passed 348 tests, including all 100
simulated SDK owner tests, and built and signed the Intel guest consumer.
All 54 probe-tool tests passed. The cross-target Cargo log SHA-256 is
`189bc0acb5af7e2cfce6a3ee5764b71ecbe3027d398769e5d65cde22d5d18564`.
An independent user-mode test on a physical Intel Xeon E5-1650 v3
confirmed the exact low and high lane behavior for all 16 legacy and
VEX2 forms. A KVM guest on the same host confirmed all 24 legacy,
VEX2 and VEX3 forms against RAM. KVM reported internal emulation error
1 before device dispatch for all 24 MMIO-hole attempts. The user-mode
and KVM log SHA-256 digests are
`12033c9d100b7fd6c284b0edceaf92a87ca1f8f3c3ef426f91fb0721150ac2fc`
and `ff145b1a95d27f3f5d24638649acd50f7e739df224bf92c10532caaaf08e7ce4`.

Hosted Intel macOS executed all 48 lane cases at
`1ce5f5a0ccfde47fcaff4903d05cd9e14a4ffc7b`. The cases covered 24 direct
transfers and 24 transfers completed by a fresh owner from a raw stopped-CPU
record. The signed consumer SHA-256 was
`d390d5e095a2f62f5df9cf5eff081456e28e7ca0d6bdd82c5e893a986ae05f7d`.
Verification matched 4,899 engine inputs and 19 consumer inputs to the
dispatched commit. The ordered lane observations SHA-256 was
`8cc519ffc9bb9457224ee7812ab8bb661239c71e4962c899b1d450a47fd1d10e`.
The host reported a GenuineIntel CPU, an untranslated process, and a
hypervisor guest. [Lane execution artifacts](https://github.com/HexRaysSA/rax/actions/runs/45123636044)

The broad profile independently passed all 952 cases with the same signed
consumer. Its ordered observations matched the earlier run byte for byte
at SHA-256 `f316c6b261debf8afb68c175859bfc438d4f71098ee3fae282361d71df7faec1`.
All 17 stage markers matched, including native startup IPIs, VMM-file
continuation and CPUID at 1, 2 and 4 vCPUs. The VMM-file cases capture
after guest shutdown.
[Broad execution artifacts](https://github.com/HexRaysSA/rax/actions/runs/45123636232)

## Pending XMM transfer in a native VMM file

The whole-VMM pending-XMM run at `e41891df` reached the hosted 45-minute
library build limit before guest entry. The artifact contains dependency
build and HVF availability records. The checkpoint workflow now builds
the same test harness with only the required `hvf` feature enabled.
Cross-building on Apple Silicon produced a signed Intel macOS harness
and listed the exact pending-XMM test. The cross-build Cargo log
SHA-256 is `4d252cad70768fdd5a844ae92306d8e49c6deb8cface8247cd0d891ad64c3be1`.
[Hosted build timeout](https://github.com/HexRaysSA/rax/actions/runs/45134222791)

Two later hosted Intel runs reached checkpoint capture. The artifact from
`349dc81a9` contains a two-vCPU VMM file with AP1 stopped at the pending
read and the original guest instruction replaced by UD2. The file
SHA-256 is `b5d92a20abef91d1d72828779daa1e32f3a4daaec3da2ac106ef7a09a36408fc`.
Both runs stopped at restore configuration validation because the fixture
set 16 MiB after constructing the configuration. The fixture now supplies
128 MiB through `VmConfig::from_sources`, which enforces the same minimum
as the restore path. The updated Intel macOS harness cross-built and
passed strict signature verification. All 16 workflow policy tests passed.
[First stopped AP1 capture](https://github.com/HexRaysSA/rax/actions/runs/45140821048)
[Second restore-validation failure](https://github.com/HexRaysSA/rax/actions/runs/45141965732)

The corrected run at `43e93dd77e1f787e37b5003bb041c7a765d433d7` passed
both file continuations. The workflow signed and verified the harness,
then ran it untranslated on a hosted Intel Core i7-8700B with macOS
15.7.9 and SDK 15.5. The test destroyed the source VM and removed its
kernel file before constructing the target from the checkpoint.

| Configured vCPUs | Restored vCPU | Pending transaction | Checkpoint SHA-256 |
| --- | --- | --- | --- |
| 2 | AP1 | `MOVLPD` read of 8 B | `ccff306f3c8bbb1531ac62f3e3dce41fb42dfc12bef65e01ab89fed5af0f7643` |
| 4 | AP3 | `MOVHPD` write of 8 B | `cea2ae31c0306011c1573e52cc12b059d1b6b5a27209180024831a760af117bc` |

| Assumption | Falsification probe |
| --- | --- |
| The target resumes a saved transaction from the VMM file. | Replace the stopped instruction with UD2 before capture, inspect the saved execution and HVF records and require `Vmm::run` to advance the selected AP to the instruction after shutdown. |
| The pending access completes once at the right address and width. | Require zero callbacks before resume, one matching read or write callback after resume, the expected XMM15 state and rejection of a second completion. |

Independent inspection confirmed both files' topology, stopped state and
UD2. The retained log SHA-256 is
`5d4aa1ae646ac35af1cddc2d467cb6429e87e6ff53aadefaef5f6451537e74e8`.
The signed harness digest reported by the workflow is
`7c275f15020b4a91de1869c7021f5879afa5e0fd16b9a8ae8661e96d40ead82d`.
The downloaded archive matched GitHub's SHA-256
`e17ea1e1fe194f82294c6405c5ba1a2a138de70ace60ed5dad33282124d41fd9`.
The fixture prepares the APs directly and reattaches a test MMIO device
on the target. Device-private restoration, guest-driven AP startup in
the same test, and bare-metal Intel macOS execution remain open.
[Passing native VMM-file execution](https://github.com/HexRaysSA/rax/actions/runs/45148465791)

## Packed logical reads

Intel HVF handles device reads for the packed AND, AND-NOT, OR, and XOR
forms with PS, PD, and integer operands. Legacy SSE reads an aligned
16-byte operand, updates its destination XMM register and preserves the
upper YMM state. VEX.128 reads 16 bytes and clears the upper destination
state. VEX.256 reads 32 bytes and writes the full YMM result. Both VEX
encodings use the explicit vvvv source and accept unaligned operands.
The completion leaves RFLAGS and other registers unchanged. The pending
record retains the source bytes alongside the operation and width and
appends its discriminant after the existing wire variants. Bytewise
completion takes O(width) time and O(width) space, with width bounded at
32 bytes.
[Intel SDM Volume 2, ANDPS/ANDPD/PAND, ANDNPS/ANDNPD/PANDN, ORPS/ORPD/POR, XORPS/XORPD/PXOR](https://cdrdv2-public.intel.com/843829/325383-sdm-vol-2abcd-dec-24.pdf)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The memory operand is read-only and the vector length determines its width. | High | Plan legacy, VEX2 and VEX3 encodings with both VEX lengths. Check the exact address, width and operand roles. Test a write exit, register-only instructions and illegal prefixes. |
| Legacy alignment and destination preservation differ from VEX. | High | Run all 12 legacy operations on aligned RAM and require a fault at offset 3. Run all 48 VEX forms at offset 3, using distinct source and destination registers and populated upper lanes. |
| The pending input can retire once without refetching the instruction. | High | Restore into a fresh owner after replacing the original opcode with UD2. Check the re-emitted request, result bytes, PC and untouched flags and vector registers. Reject short and long replies without publishing a write or retiring. |

All 60 MMIO planning cases rejected the source operand before the fix.
The failing log SHA-256 is
`8f5041f624f46b5a28c222a96d6ac3991c9bcfb6487b92c94663a2f9f2598b11`.
An independent test on a physical Intel Xeon E5-1650 v3 executed all
60 encodings against ordinary RAM, verified every destination byte and
unchanged flags, and observed SIGSEGV for all 12 misaligned legacy
controls. The 60 ordered hardware result fingerprints have SHA-256
`a028d8357966a7cd97eac40c6f75410cb87f527661e572c8b78903228b1ffc2c`.

The complete Intel Linux runs passed 133 `hvf_mmio`, 102 `isa_oracle`,
and 28,561 `x86_64` tests. The x86-64 suite reported three ignored
cases. All three suites reported zero failures and zero filtered tests.
The combined log SHA-256 is
`07720149f7d9a637605658409f86991c88125a8e3a5afbf64f1c85da5d79b40b`.
The complete Intel Linux C API library suite passed 250 cases with five
ignored, zero failures and zero filtered. Its log SHA-256 is
`4abc0ae62c8efe00a9682c90e466acdb8b604f7589fa17c9e6d86a7b625b6a02`.

On Apple Silicon the Intel-target tests passed all 351 cases, including
100 simulated SDK owner cases and 16 CI pinning cases. The consumer
linked for Intel macOS and passed strict signature verification with
the Hypervisor entitlement. All 54 Python tooling tests passed.
The test log SHA-256 is
`c1be95f8a566ce29ec9a3a121adcf9d62f8e556e98610a02c611488750cff505`.
Hosted Intel macOS passed 132 cases at
`a201e8be7d7a03a37df9b4d2d83f8a5169ad596d`. The 60 direct cases and
60 fresh-owner restores independently matched the physical Intel RAM
fingerprints. All 12 misaligned legacy forms reported a guest fault at
the original RIP. Verification matched 4,901 engine inputs and 19
consumer inputs to the dispatched commit and checked the executable's
signature and Hypervisor entitlement. The executable SHA-256 was
`7e607b8fe99fa5ddea78f5ac2c54a5f3e7d9d2080bc70dc03ab48cb63ddafd1f`.
The ordered observations SHA-256 was
`ca06a8d927b8b872a3b9c9f5d1a9cc8e876af668224368d373db9f0e99ccca16`.
[Hosted packed logical execution](https://github.com/HexRaysSA/rax/actions/runs/45134602125)

## Packed bit-test reads

Intel HVF handles memory-source PTEST, VPTEST, VTESTPS and VTESTPD on
an MMIO hole. PTEST reads an aligned 16-byte operand. VPTEST accepts
VEX.W values zero and one. VTESTPS and VTESTPD require VEX.W=0 and use
only bit 31 or bit 63 of each element, respectively. Both VEX widths
accept unaligned operands and consume exactly 16 or 32 bytes. No
vector register is written. Retirement clears OF, SF, AF and PF,
sets ZF when the operands have no selected bits set in common, and
sets CF when every selected bit set in the device reply is also
set in the register operand. Other flags are preserved. The pending
record carries the original register bytes, flags, length and form.
Reduction takes O(width) time with width bounded at 32 bytes and
O(1) working space.
[Intel SDM Volume 2, PTEST, VPTEST, VTESTPD and VTESTPS](https://cdrdv2-public.intel.com/782156/325383-sdm-vol-2abcd.pdf)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Memory is the second, read-only operand. | High | Vary all nine legal forms, then present a write exit, register-only form, reserved vvvv, missing mandatory prefix and illegal VEX.W. Confirm no device data is read during planning. |
| Legacy memory alignment and VEX width belong to the decoded form. | High | Vary all 15 misaligned offsets on the Intel reference and use unaligned x86 VEX controls. Check the guest fault RIP and the exact device request width. |
| A saved request retains the full reduction inputs and changes flags only. | High | Restore after replacing the opcode with UD2, exercise all four CF/ZF outcomes and check the original XMM and upper YMM bytes, unchanged unrelated RFLAGS, one retirement and rejection of short and long replies. |

The baseline rejected all nine encodings in the portable MMIO planner.
The failing log SHA-256 is
`0971edf902c1b07c58649775388e40f788b7561bd94597070a0eca0b94ada978`.
On a physical Intel Xeon E5-1650 v3 an independent process executed
36 ordinary-RAM flag cases, observed SIGILL for all four VEX.W=1
floating controls, and observed SIGSEGV at every misaligned legacy
offset. The 55 ordered hardware observations have SHA-256
`d2672ca52d96783954eb4033f4123d6b7c612bb52cec419f827c764d38c9fa6c`.

The complete Intel Linux suites passed 136 `hvf_mmio`, 102
`isa_oracle` and 28,561 `x86_64` tests with three x86-64 cases ignored
and zero failures or filtered cases. Cargo log SHA-256 is
`87b050bdedd47473d26eece240c59ada321001e5a829a023e6d5fdd3fc7bc4fa`.
The Intel macOS cross-target run passed 354 cases on Apple Silicon,
including all 100 simulated SDK owner cases and 16 CI pinning checks.
Its Cargo log SHA-256 is
`3861a8d925213fdf2e443ed2196a408c08fac3279170b404bbe2e91dcd6f105d`.
The cross-target guest consumer linked and passed strict signature and
entitlement checks. All 54 Python tooling tests passed. The complete
Intel Linux C API library suite passed 250 cases with five ignored,
zero failures and zero filtered. Its log SHA-256 is
`bd9b4ff898c54f04b7b64f9fdfee2e8f48c0e796ecdcf4d246b5357dbfcdcf97`.

Hosted Intel macOS passed all 73 cases at
`d69e2efb28bcc5042d016849a58179db7c35f4c1`. The 36 direct cases and
36 fresh-owner restores independently matched the physical Intel flag
results. The unaligned legacy control reported the original fault RIP.
Verification matched 4,902 engine inputs and 19 consumer inputs to
the dispatched commit and checked the executable signature and
Hypervisor entitlement. The executable SHA-256 was
`677c7949e9bdf274377b7a3a8cbdc6c6a5ba041e64bc5ffa66ef6447197e0bd2`.
The ordered observations SHA-256 was
`ae35bd61e771aa6164af072a1ed2823931b41d7bdbb90cf6de19332d62fa9ba0`.
[Hosted packed bit-test execution](https://github.com/HexRaysSA/rax/actions/runs/45139966944)

## Packed integer comparisons

Legacy SSE and VEX encodings of packed integer equality and signed
greater-than comparisons now admit one vector input from the device.
The decoder identifies the distinct legacy and VEX source registers
and the opcode map. Each 8-, 16-, 32- or 64-bit element becomes all ones
or all zeroes. Legacy forms preserve the upper YMM half, VEX.128 clears
it, and VEX.256 writes both halves. RFLAGS is unchanged. The existing
pending vector record appends a typed comparison operation after its
original operation values. Completion takes O(width) time and bounded
storage for a maximum width of 32 B.
[Intel SDM Volume 2B, PCMPEQB through PCMPEQQ and PCMPGTB through PCMPGTQ](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| Legacy and VEX operands have different source roles. | High | Compare a device reply with distinct XMM15 and XMM8 seeds. Check the destination, upper half, unchanged flags and exact next RIP. |
| Signed order is determined per element. | High | Rotate equal, negative, boundary and opposite-sign pairs through every vector position. Compare each lane against the hardware mask. |
| The pending read retains the original comparison. | High | Serialize the pending read and complete it once after restore, then require a duplicate reply to make no further writes. Replace the original opcode with UD2 in the native restore fixture. |

The parent rejected the metadata for all 24 selected legacy and VEX3
encodings. The regression log SHA-256 is
`e487208b2f63d435c3babc07add2618a6723fb8e28fd38e3000428c07c5a7d63`.
The physical Intel RAM oracle recorded 96 correct masks with unchanged
flags and eight legacy misalignment faults. Its ordered results have
SHA-256 `c7c15dbc88300b974e3f2c647a6d7526a8ed01063d9249980b3d824bc88be5ed`.

The unfiltered Intel Linux targets passed 137 `hvf_mmio`, 102
`isa_oracle` and 28,562 `x86_64` cases, with three ignored x86-64
cases. The Cargo log SHA-256 is
`4ae02b53c5cf1a4a9dc32962a3c4e5830a9988118f7b425f7ede4d2c9fa97ed2`.
On Apple Silicon the Intel macOS target passed 355 modeled and portable
tests, including 100 SDK-owner and 16 CI policy tests. The Cargo log
SHA-256 is `2f1c310b8a912252a6f1d632a50c2eadf0658eb51866e2ac0279f45493d119ec`.
All 55 Python tests passed and the Intel guest executable passed strict
signature verification.

Hosted Intel macOS passed all 104 cases at
`c01cfd0b0b6c2357035781cb40904b6b8bd3a0de`. The 48 direct and 48
fresh-owner pending read cases matched the independent physical Intel
RAM results. Eight legacy misalignment controls reached the guest fault
handler at the original instruction. Verification matched 4,902 engine
inputs, 19 consumer inputs and the signed, entitled executable with
SHA-256 `9990814b59bfb91ebf441be0f1a2965a58d897ac6d9f03c47b4e95e7ac6ab4ad`.
The ordered observations SHA-256 is
`0dc1462173443300f5058ee7a47ec027ae1f533be678513b4b07ed319e9de211`.
The process ran untranslated on Intel inside a hosting hypervisor.
[Hosted packed comparison execution](https://github.com/HexRaysSA/rax/actions/runs/45148267711)

## Packed integer addition and subtraction

Legacy SSE and VEX `PADDB/W/D/Q` and `PSUBB/W/D/Q` read one 16 B or
32 B device operand. Subtraction uses the legacy destination or the
explicit VEX register source as the minuend. Each lane computes its
result modulo 2^w, where w is 8, 16, 32 or 64 bits. There is no carry or
borrow across lanes. Legacy forms preserve the upper YMM half, VEX.128
clears it, and VEX.256 writes the full destination. RFLAGS is preserved.
The new operation values follow the existing comparisons in the pending
record. Completion takes O(width) time and bounded storage for at most
32 B of device input.
[Intel SDM Volume 2B, PADDB/PADDW/PADDD/PADDQ and PSUBB/PSUBW/PSUBD/PSUBQ](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The device operand supplies the second source and never receives a write. | High | Plan both VEX prefixes at both widths and the legacy forms. Check the selected source and destination, then present the same operand as a write exit. |
| Overflow and underflow wrap within the encoded lane width. | High | Rotate an all-ones plus one, zero minus one, signed boundary, and unequal operands. Check every result byte, all unrelated vector registers, RFLAGS and the following RIP. |
| The pending operation survives a fresh owner and legacy alignment still faults. | High | Serialize every encoding and complete once. The native profile replaces the opcode with UD2 before rebuilding the owner. Test all eight legacy forms at a misaligned address. |

All 40 legacy, VEX2 and VEX3 encodings failed baseline MMIO planning.
The regression log SHA-256 is
`8b446c71d5638a719bf95bc854f44bef74fad885bdde113321c2cfd31e788be8`.
The physical Intel Xeon E5-1650 v3 RAM oracle confirmed 160 operand
cases with unchanged flags and eight legacy alignment faults. Its
observation stream SHA-256 is
`bf563321c24809c4631f801cdb2f6d93361e241bd6943e5f91ee19507ef2f884`.

With the fix applied to `cd34ff1ca`, unfiltered validation on physical
Intel Linux passed 138 `hvf_mmio`, 102 `isa_oracle` and 28,562 `x86_64`
tests, with three `x86_64` tests ignored. Its log SHA-256 is
`242ddb2e2c289c2d7ba6b22cd22208a0d503ab1afce026a70f06cf87f0441091`.
The Intel Darwin cross-target run under Rosetta passed 138 `hvf_mmio`,
100 `hvf_intel_owner`, 102 `isa_oracle` and 16 `ci_actions_pinned`
tests. Its log SHA-256 is
`5617ea5dfbab5cd48cd5cb6ce49226a03c16c3e7ae696594e327ded39df34d12`.
The native consumer built and passed strict signature verification.
All 55 local Python tests passed.

Hosted Intel HVF run `45152935165` at
`7979b0e029b1d6172ab4eb0f9dd9a891a70f1f66` passed 160 direct reads,
160 reads completed on fresh native vCPU owners, and eight legacy
alignment faults. All 328 observations matched the independent physical
Intel RAM oracle. Verification matched the uploaded archives, signed
executable and hypervisor entitlement, 4,903 engine inputs and 19
consumer inputs. The observation stream SHA-256 was
`cd4b7d8a1f681d25f7debfa126cf81e1044821b54bab2340095f94d095b9b86e`.
The Intel process ran untranslated inside a hosted macOS VM.
[Hosted packed addition and subtraction execution](https://github.com/HexRaysSA/rax/actions/runs/45152935165)

## Packed saturating integer addition and subtraction

Legacy SSE and VEX `PADDSB/W`, `PADDUSB/W`, `PSUBSB/W` and
`PSUBUSB/W` read one 16 B or 32 B device operand. Subtraction uses
the legacy destination or the explicit VEX register source as its
minuend. Signed lanes clamp to −128 through 127 or −32,768 through
32,767. Unsigned lanes clamp to 0 through 255 or 0 through 65,535.
The largest intermediate is 131,070, so widening each lane to a signed
32-bit integer covers every sum and difference. Legacy instructions
require 16 B alignment and preserve the upper YMM half. VEX.128 clears
that half and VEX.256 writes the full register. RFLAGS is preserved.
The pending vector record appends the saturation operations after its
existing values. Completion takes O(width) time and bounded storage for
at most 32 B of device input. MMX and EVEX are separate profiles.
[Intel SDM Volume 2B, PADDSB/PADDSW, PADDUSB/PADDUSW, PSUBSB/PSUBSW and PSUBUSB/PSUBUSW](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The second operand supplies exactly one device read. | High | Exercise legacy SSE, VEX2 and VEX3 at each legal width. Check the register roles, reject a write exit and a register-only form, and require legacy misalignment to fault before requesting device data. |
| Saturation is independent in every lane. | High | Rotate distinct register and device inputs through each signed and unsigned limit and an in-range result. Compare each lane, the upper YMM half and unchanged RFLAGS. |
| The saved request contains enough state for one retirement. | High | Round-trip each pending operation, complete it twice and verify one register update and one RIP advance. Rebuild the native owner after replacing the instruction with UD2. |

All 40 encodings failed baseline MMIO admission. The regression log
SHA-256 is
`c8150cff2a01c6ae5869395d9037dee1a3f58680bed0787268fa89c97d70a23d`.
An independent physical Intel Xeon E5-1650 v3 RAM oracle confirmed
320 operand cases with unchanged flags and eight legacy misalignment
faults. The observation stream SHA-256 is
`27b2eb1489b3fb324465a0cd4742560987e25614e2dec0a71ad49e6264e1777b`.

On Apple Silicon under Rosetta the Intel macOS target passed all 141
portable MMIO tests. Their log SHA-256 is
`2ea1406bc7cd0a1a0da614f7f99a852d0d4907135c94b716869193c159dff426`.
All 55 Python host-tool tests passed. The Intel guest consumer linked
and passed strict signature and Hypervisor entitlement checks. The
`vector-saturating` workflow profile exercises 160 direct device reads,
160 reads completed on fresh vCPU owners and eight legacy alignment
faults.

Physical Intel Linux passed the unfiltered `hvf_mmio`, `isa_oracle`
and `x86_64` targets with 141, 102 and 28,562 cases, respectively.
Three `x86_64` cases were ignored. The Linux qualification log
SHA-256 is
`5ad29bbc95a3fa06a7b09748da890078bac68184ce2e2286f26adacc014e202d`.
The full Intel macOS cross-target run also passed 104 SDK-owner tests,
102 ISA-oracle tests and 16 Actions policy tests under Rosetta. The
combined cross-target log SHA-256 is
`dcf1f20ca4ddc36c523dc5b59a0de7626a52e0e4de91e76889ac77a137a0d8f9`.

Hosted Intel HVF run `45313352560` at
`1584b55ef3cad979fbdc556c2cb9944aa9806b70` passed all 160 direct
reads, 160 fresh-owner restores and eight legacy alignment faults.
All 328 observations matched the independent physical Intel RAM oracle.
Verification matched both uploaded archives, the signed executable and
Hypervisor entitlement, and all 4,920 engine inputs and 20 consumer
inputs to the dispatched revision. The observation stream SHA-256 is
`17c728b61b4f45028fecead4d642e48b4fe1f0e276681cf2b1521c9e120b3565`.
The executable SHA-256 is
`229f67a93cad45920e1a5b040d9cb5a3e8c9b938b993421bf14263e9ee837cb2`.
The job ran untranslated on Intel inside a hosted macOS 15.7.9 VM.
Bare-metal Intel macOS remains unverified.
[Hosted packed saturation execution](https://github.com/HexRaysSA/rax/actions/runs/45313352560/job/138174178991)

## Packed integer minimum and maximum

The Intel HVF MMIO planner admits the twelve signed and unsigned byte,
word and doubleword minimum and maximum mnemonics in legacy SSE and VEX
forms. Each selects one input element per lane and requests one 16 B or
32 B device read. Legacy SSE requires 16 B alignment and preserves the
upper YMM half. VEX.128 clears it and VEX.256 replaces the full
register. The operations preserve RFLAGS. The pending record appends
two operation values to retain the lane width and signedness. Completion
uses O(width) time and bounded storage for at most 32 B of input.
MMX and EVEX are separate profiles.
[Intel SDM Volume 2B, sections PMAXSB through PMINUD, and Volume 2D, Table B-35](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The memory source has the encoded width, and each lane compares independently. | High | Check 12 legacy, 24 VEX3 and 8 VEX2 encodings. Rotate signed extrema, unsigned extrema and equal operands, with distinct legacy and VEX register roles. |
| A stopped owner can reproduce the pending result with no instruction reread. | High | Round-trip every descriptor through the typed codec and submit the reply twice. The native profile also replaces the instruction with UD2 before reconstructing the owner. |
| Legacy and VEX have different alignment and upper register rules. | High | Check upper-half preserve, clear and replacement. Send VEX reads at offset 3 B, reject legacy misalignment during planning, and check the guest fault on Intel HVF. |

At parent `3a246941a`, all 44 memory encodings failed MMIO admission.
The unfiltered baseline passed 141 tests and failed the new regression.
Its log SHA-256 is
`b9291462b3cfdbb233871817b30b36d34659a195acd5e46420577617feeb8bea`.
The repaired Apple Silicon build passed 142 MMIO, 102 ISA-oracle,
16 Actions policy and 28,561 x86-64 tests. Three x86-64 tests were
ignored. All 55 Python HVF tool tests passed. The cross-built Intel guest
consumer linked and passed strict signature verification. The
`vector-min-max` profile expects 176 direct reads, 176 fresh-owner
completions and 12 guest alignment faults.

An independent RAM executable under Rosetta matched all 176 result and
flag checks. Rosetta allowed all 12 misaligned legacy cases, so that
run qualifies result bytes and flags only. The physical Intel Linux
host was unreachable from this session. The observation stream
SHA-256 is
`aa082edda24bed64dc24b8231e35223bfd3920477c2771173bd8cbc59370b44c`.

The hosted Intel job at `bd7f3ffcbe978b67fa7b0a1ba321f6308f7aa7f4`
passed all 364 cases. The untranslated Intel process ran inside a macOS
15.7.9 VM (build 24G830). All 176 direct and 176 reconstructed-owner
destination signatures matched the independent RAM run. The 12 legacy
misalignment cases reported guest #GP(0) at RIP `0x10000`. Bare-metal
Intel macOS remains unverified.
[Hosted minimum and maximum execution](https://github.com/HexRaysSA/rax/actions/runs/45318040784/job/138189559507)

Verification checked both artifact ZIP digests against GitHub metadata,
the Hypervisor entitlement, the executable signature, and the hashes of
4,921 engine input paths and 20 consumer input paths at the tested
revision. The 364-row execution stream SHA-256 is
`63b3cc22c31f61b36670b876d3ed59d687347ed1aab638f74bb035d7b3d03a45`.

## Packed uniform shifts with a device count

Intel HVF plans one 16 B device read for each legacy SSE and VEX memory
form of PSLLW/D/Q, PSRLW/D/Q, and PSRAW/D. VEX.256 reads a 32 B source
register and still reads 16 B from the device. Only the low 64 bits of
the reply supply the unsigned count shared by every lane. Logical
shifts zero the lane at or above its width. Arithmetic right shifts
saturate the count at the lane width minus one. The operations
preserve RFLAGS. Legacy SSE preserves the upper YMM half, VEX.128
clears it, and VEX.256 replaces it. VEX.W is ignored.
[Intel SDM Volume 2B, PSLLW through PSRLQ](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf)

The decoder, address validation, data-breakpoint range, live SDK exit,
and pending-read descriptor use the encoded count operand width. The
checkpoint appends one operation variant and holds the captured source
register and instruction length alongside the destination. Completion
takes O(n) time for n lanes and bounded storage for a 32 B result.
MMX, EVEX, immediate, register-count and per-element shifts are outside
this MMIO profile.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The count read is exactly 16 B even with a YMM destination. | High | Place the last count byte at a page boundary with RAM immediately after it. Verify the saved descriptor width and reject both 15 B and 32 B replies before any architectural write. |
| The instructions use the full low qword and ignore the high qword. | High | Set the high qword to all ones and exercise counts 0, 1, width minus 1, width, width plus 1, 256, and 2^64 minus 1 across all 56 encodings. |
| The captured request is sufficient to retire once. | High | Serialize every descriptor, reload it, and submit the same reply twice. The native profile replaces the original opcode with UD2 before restoring a fresh SDK owner. |
| The selected memory forms have distinct alignment and upper-register behavior. | High | Reject misaligned legacy SSE during planning and check #GP(0) in the native guest. Use unaligned VEX reads and inspect the full vector banks and RFLAGS before and after completion. |

At parent `33c1dd8d3`, all 56 encodings failed MMIO metadata
admission. The baseline log SHA-256 is
`360fad236fced8e233235815bb3d72eb5be745d4b0fa22e62115a68de3fb1b0d`.
The repaired Apple Silicon build passed 144 MMIO, 102 ISA-oracle,
16 Actions policy, and 28,561 x86-64 tests. Three x86-64 tests were
ignored. All 55 Python HVF tool tests passed.

An independent RAM executable under Rosetta matched 392 results,
upper register halves, and before/after RFLAGS pairs. Its observation
stream SHA-256 is
`68bcbac5b403ce36464518db90136f4e410c4cdcf49a5254fd767c2f009174af`.
The Intel macOS cross-target `hvf_intel_owner` and `hvf_mmio` targets
passed 104 and 144 tests, respectively, under Rosetta. The owner
target supplies model SDK calls. The verification log SHA-256 is
`5609fb8ed6a800c1f425db48f78def33777e514fc76a29c502fdd22645e5a3bc`.
The guest consumer cross-built from `0d6097e60` and passed strict
signature verification. Its executable SHA-256 is
`ffd0aedf792ba587cbf7af9fe381b3b149d3dffa66c17a7a5614638250dabce8`.
At `870127acc`, the `vector-uniform-shifts` profile passed 392 direct
reads, 392 fresh-owner completions, and eight legacy alignment fault
cases on GitHub-hosted Intel macOS.
[Hosted uniform-shift execution](https://github.com/HexRaysSA/rax/actions/runs/45478645398/job/138745518634)

## AVX2 per-element shifts with device counts

Intel HVF supports the AVX2 VEX memory forms of VPSLLVD/Q, VPSRLVD/Q, and
VPSRAVD. The instruction requests 16 B with an XMM destination or 32 B
with a YMM destination. Each destination element uses the full unsigned
32-bit or 64-bit count in the corresponding little-endian device
element. Logical shifts produce zero when the count reaches the element
width. Arithmetic right shifts at that boundary produce the sign fill.
The VEX.128 form clears the upper half of the destination YMM register.
The VEX.256 form replaces the full register. RFLAGS are preserved.
[Intel SDM Vol. 2C, VPSLLVW through VPSRLVQ](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

The pending-read descriptor derives the input width from the vector
encoding and stores the source vector, destination and instruction
length. Completion processes at most eight
lanes in O(n) time for n lanes and uses a fixed 32 B result buffer. The
new operation follows the existing wire variants. The supported VEX
encodings use map 0F38 with mandatory prefix 66. The public instruction
metadata API reports all three operands and the encoded count width
for both memory and register forms. Register forms use the ordinary
execution path. EVEX uses a separate instruction profile.

| Assumption | Dependent behavior | Validation probe |
| --- | --- | --- |
| VEX.L determines the device width for this family. | The requested width is 16 B or 32 B. | Place the read across a page boundary and RAM immediately after it. Move RAM one byte earlier and require planning to reject before any device access. |
| Each lane consumes its own full-width count. | Large counts zero logical lanes or sign-fill arithmetic lanes. | Rotate counts 0, 1, width minus 1, width, width plus 1, 256 and the all-ones element through all lanes. |
| The saved source is sufficient for completion. | A pending read can write and retire once after restore, including when source and destination alias. | Restore each descriptor, submit the reply twice and verify one write and one retirement. Reject replies one byte short or long. |

The baseline rejected all 30 legal cases in the MMIO planning matrix.
The Apple Silicon build passed 146 MMIO, 102 ISA-oracle, 16 Actions
policy, and 28,561 x86-64 tests, with three x86-64 cases ignored.
The Intel-target build passed all 100 owner model tests and all 146
portable MMIO tests under Rosetta. All 55 Python HVF tooling tests
passed. The C API suite passed 259 tests with 21 ignored. An independent
RAM probe executed 140 raw x86-64 cases under Rosetta and matched the
full vector results and before/after RFLAGS. At `870127acc`, the
`vector-variable-shifts` profile passed 70 direct guest reads and 70
fresh-owner checkpoint completions on GitHub-hosted Intel macOS.
[Hosted variable-shift execution](https://github.com/HexRaysSA/rax/actions/runs/45478695798/job/138745701864)

## Packed integer unpack with a device operand

Intel HVF supports the SSE2 PUNPCKL/H forms and their VEX.128 and
VEX.256 equivalents for 8-, 16-, 32-, and 64-bit elements. The MMIO
path reads the full 16 B or 32 B encoded memory operand. Within each
16 B lane, it alternates elements from the selected 8 B halves of the
register and device operands. The result preserves RFLAGS. Legacy SSE
preserves the upper YMM half, VEX.128 clears it, and VEX.256 replaces
both halves. [Intel SDM Volume 2B, PUNPCKHBW and PUNPCKLBW](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf)

The pending read stores the register operand and appends two operation
variants to the existing checkpoint format. Completion takes O(w) time
and uses a w-byte result buffer for w equal to 16 or 32 B.

| Assumption | Impact | Validation probe |
| --- | --- | --- |
| The device read width follows the encoded memory operand. | High | Check the planned width and reject writes, wrong prefixes and unsupported operand forms. |
| VEX.256 selects halves independently in both lanes. | High | Use distinct bytes across both operands and all lanes, then compare the full YMM result and RFLAGS against two independent RAM patterns under Rosetta. |
| A restored read can complete without decoding the original instruction. | High | Round-trip the pending descriptor and submit the reply twice. The native profile also replaces the original instruction with UD2 before restoring a fresh owner. |

At parent `646a25452`, all 40 legal encodings failed MMIO metadata
admission. The baseline log SHA-256 is
`278ad984c1b32445f625aeb80b6ed9f65a8a88ef20dbf93347c3675293b8c71f`.
The independent RAM probe matched 80 results and RFLAGS pairs. Its
observation stream SHA-256 is
`50eeba1759a2b951d921ec68174f9d7ed61cdc411bc400fb70110b35be40ea99`.
The Apple Silicon build passed 147 MMIO and 28,561 x86-64 tests, with
three x86-64 tests ignored. All 55 Python HVF tool tests passed.
The Intel-target guest cross-built and passed strict signature verification.
At `870127acc`, the `vector-unpack` profile passed 40 direct reads, 40
fresh-owner checkpoint completions, and eight legacy alignment fault cases
on GitHub-hosted Intel macOS.
[Hosted unpack execution](https://github.com/HexRaysSA/rax/actions/runs/45478730327/job/138745819912)

## Packed integer multiplication with a device operand

Intel HVF handles the memory forms of PMULLW, PMULHW, PMULHUW,
PMULUDQ, PMADDWD, PMULLD, PMULDQ, PMULHRSW, and PMADDUBSW in legacy
SSE and VEX encodings. The device read covers the full 16 B or 32 B
encoded operand even when an operation uses only the even doublewords.
The low-product and signed pairwise sum operations wrap to their
destination width. PMULHRSW rounds the signed word products before
truncation. PMADDUBSW multiplies unsigned register bytes by signed
device bytes and clamps each adjacent sum to the signed 16-bit range.
Legacy SSE preserves the upper half of the destination YMM register,
VEX.128 clears it, and VEX.256 writes both halves. RFLAGS are preserved.
[Intel SDM Volume 2B, PMADDUBSW through PMULUDQ](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

The pending read captures the source vector, destination, and
instruction length. Completion uses O(w) time and a fixed 32 B result
buffer, where w is the encoded operand width in bytes. The new
operation follows the existing checkpoint variants. MMX and EVEX
encodings are outside this profile.

| Assumption | Dependent behavior | Validation probe |
| --- | --- | --- |
| The encoded vector width determines the full read size. | The device supplies 16 B or 32 B, including any lanes ignored by the operation. | Check the planned width for all 55 encodings and reject write exits, wrong prefixes, and unaligned legacy reads. |
| Signedness, wraparound, and saturation apply independently to each result element. | Each product or pairwise sum matches the architecture, including endpoint cases. | Compare the full XMM or YMM destination and the before/after RFLAGS against two RAM operand patterns per encoding. |
| The retained source vector is sufficient to retire the instruction. | A completed read updates the destination and advances the instruction pointer once. | Serialize and reload the pending read and submit the reply twice. The native profile also replaces the original instruction with UD2 before restoring a fresh owner. |

At parent `1c46b4fcb`, all 55 legal encodings failed MMIO metadata
admission. The baseline log SHA-256 is
`00218da9187e3c2d796eeacac4bf7defadd8c027eb3ef4a28116a2c1ee434b8c`.
The independent x86-64 RAM probe under Rosetta matched all 110 vector
results and RFLAGS pairs. Its observation stream SHA-256 is
`401154183c32f63ec23f431da3ad2a43ccff39b7c65dbdb4be6c24341f16af0d`.
The Apple Silicon build passed 149 MMIO, 102 ISA-oracle, 16 Actions
policy, and 28,561 x86-64 tests. Three x86-64 tests were ignored. All
55 Python HVF tool tests passed. The Intel macOS guest consumer cross-built
and passed strict signature verification. Its executable SHA-256 is
`ac228aecd29ed97e922986f3f9aedc40b6edac3d98c46c1f51a5b62bae5a9f0b`.
At `870127acc`, the `vector-multiply` profile passed 110 direct reads, 110
fresh-owner checkpoint completions, and nine legacy alignment fault cases
on GitHub-hosted Intel macOS.
[Hosted multiply execution](https://github.com/HexRaysSA/rax/actions/runs/45478777263/job/138745997273)

## Packed byte shuffle with a device control operand

Intel HVF handles XMM `PSHUFB` and VEX.128 and VEX.256 `VPSHUFB`
memory forms. Each control byte selects a byte in its own 16 B lane
using bits 3:0, or produces zero when bit 7 is set. The full encoded
control operand is read once. The SSE form requires 16 B alignment
and preserves the upper half of the destination YMM register. VEX.128
clears that half, and VEX.256 replaces both halves. RFLAGS are preserved.
[Intel SDM Volume 2B, PSHUFB](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

The pending read retains the shuffle source before the device access.
The operation follows the previous packed operations in the checkpoint
encoding. Completion takes O(w) time and uses a w-byte result buffer for
w equal to 16 or 32 B.

| Assumption | Dependent behavior | Validation probe |
| --- | --- | --- |
| VEX.W is ignored for both lengths. | W=0 and W=1 request the same width and select the same operands. | Decode and prepare both encodings at each length. |
| The control is lane-local. | VEX.256 never selects data from the other 16 B lane. | Use distinct source bytes in each lane and compare the full destination against x86-64 RAM execution. |
| The retained source is sufficient at completion. | A pending read completes once after a checkpoint round-trip. | Decode the saved pending descriptor, submit the reply twice, and verify one register write and retirement. |

The `vector-shuffle` native profile runs five direct reads, five
fresh-owner checkpoint continuations, and a misaligned SSE guest #GP
control. It uses the same operands as the portable planner tests.

At parent `c616f1fb0`, the two regression tests failed because the MMIO
metadata decoder did not recognize the shuffle. The baseline log SHA-256
is `47955693667cab7b3020e2184d3dcbc646a757efd139e5cd983216838e7f9157`.
The Rosetta RAM probe covered every control byte value at each width
and matched all 85 complete YMM and RFLAGS observations. The stream
SHA-256 is `e27b0fec1a5854e185158c5d899b59ac7367c1e15f4f4ef1ed99e220ce322770`.
The Apple Silicon build passed 151 MMIO, 102 ISA-oracle, 16 CI-policy,
and 28,561 x86-64 tests, with three x86-64 tests ignored. All 55 Python
HVF tool tests passed. The Intel macOS guest consumer cross-built and
passed strict signature verification.
