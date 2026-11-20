# Legacy XMM transfers through Intel HVF MMIO

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
AVX and wider MMIO, string moves, and mixed RAM and device operands
remain open.

[Hosted execution observations](https://github.com/HexRaysSA/rax/actions/runs/44711344124)

- Tested commit `44c81f236c7e2399913f2a5df4aafe88ef948370`
- Signed consumer SHA-256 `b489c25de09f64b800351ca8e3f6e459eafa55ed54f2eb3586e1e2e5abf42da4`
- Observation stream SHA-256 `89593872de38c050034d9e0e320510e64710af12c373dc5cb45d4ee7fbbf34c1`
