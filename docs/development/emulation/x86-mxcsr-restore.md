# x86 MXCSR restore boundary

## Contract and source

The direct interpreter rejects selected MXCSR values with reserved bits before
restoring any x87 or vector payload. The implemented MXCSR profile is
`MXCSR_SUPPORTED_MASK = 0x0000FFFF`: bits 15:0 are supported, and bits 31:16
must be zero. The image's `MXCSR_MASK` field does not change this profile.
Legal values include unmasked exceptions and pending status flags. Loading
that combination does not itself raise a SIMD floating-point exception.

The architectural source is [Intel SDM 086, December 2024](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf):
Vol. 1 sections 10.2.3.1, 10.5.1.2, 10.5.3, 13.8.1, 13.8.2, and 13.12;
Vol. 2A FXRSTOR and Vol. 2D XRSTOR/XRSTORS instruction entries.
[Archive provenance](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.provenance.md)
records its identity, checksum, and unknown historical retrieval fields.

## Selection and faults

All offsets below are bytes from the state area's linear base address. MXCSR
occupies offsets 24 through 27 inclusive, a 32-bit little-endian value.
The exact 64-bit requested-feature bitmap is:

```text
instruction_mask = u64(u32(EAX)) | (u64(u32(EDX)) << 32)
RFBM = instruction_mask & XCR0
```

The casts discard the upper 32 bits of RAX and RDX. XRSTORS architecturally
uses `XCR0 | IA32_XSS`; RAX implements IA32_XSS as zero, so its current
selection is identical (assumption A2 below).

| Restore form | MXCSR action |
| --- | --- |
| FXRSTOR, either REX.W value | Load and validate the memory value. |
| Standard XRSTOR, either REX.W value | Load and validate if `RFBM & 0x6 != 0`, independently of XSTATE_BV; otherwise preserve. |
| Compacted XRSTOR | Preserve if `RFBM[1] = 0`; initialize to `0x1F80` if `RFBM[1] = 1` and `XSTATE_BV[1] = 0`; otherwise load and validate. |
| XRSTORS | Same MXCSR selection as compacted XRSTOR. |

Consequently, an SSE initialization request still reads MXCSR in standard
XRSTOR. An AVX-only request reads MXCSR only in the standard form. An ignored
or initialized memory MXCSR cannot itself cause a reserved-bit or memory
fault. Selection uses the form identified by XCOMP_BV, not the opcode alone.

The direct FXRSTOR path checks CR0.TS/CR0.EM (`#NM`) and 16-byte alignment
(`#GP(0)`) before reading MXCSR. The direct XRSTOR(S) paths check
CR4.OSXSAVE (`#UD`), CR0.TS (`#NM`), and 64-byte alignment (`#GP(0)`) before
reading the header. XRSTORS also requires effective CPL0 before the header
read. Real mode has effective CPL0; VM86 has effective CPL3. Existing decode
validation rejects illegal LOCK and register forms before these transfers.

Header validation precedes selected MXCSR access:

| Form | Header constraints |
| --- | --- |
| Standard XRSTOR | `XSTATE_BV & !XCR0 == 0`; header bytes 8 through 23 inclusive are zero. Bytes 24 through 63 are not checked. |
| Compacted XRSTOR(S) | `XCOMP_BV[63] = 1`; `(XCOMP_BV & !(1 << 63)) & !XCR0 == 0`; `XSTATE_BV & !XCOMP_BV == 0`; header bytes 16 through 63 inclusive are zero. |

The compacted subset test includes bit 63 of both fields. XSTATE_BV[63] is
therefore permitted when XCOMP_BV[63] is set; it does not select a component
for restoration. The standard form still rejects XSTATE_BV[63]. Unsupported
component bits remain invalid even when both header bitmaps set them.

For a valid header, the helper reads 24 header bytes for the standard form or
64 header bytes for the compacted form, then zero or four MXCSR bytes according
to selection. Malformed-header paths may stop after an earlier failed check.
This validation is O(1) time and O(1) auxiliary space. Accesses retain checked
guest-MMU behavior. Invalid selected MXCSR or malformed headers raise
`#GP(0)` at the restore instruction; a genuine selected memory fault retains
its memory-fault classification. No payload is committed by this preflight.
This is not a claim of all-or-none hardware restoration for faults in later
payload reads; the existing payload-transfer behavior is otherwise retained.

## Snapshot and SMIR behavior

`VCpu::set_emulator_state` returns `Error::InvalidConfig` for an invalid MXCSR
before changing any emulator snapshot field or private VSIB restart marker.
It does not inject a guest exception. A successful call preserves the existing
snapshot representation and resets the private restart marker as before.
The capture/restore helpers are in
[`cpu_emulator_state.rs`](../../../src/isa/x86_64/cpu_emulator_state.rs).

SMIR FXRSTOR now reports misalignment and reserved MXCSR as
`ExitReason::GeneralProtection { addr: guest_pc, error_code: 0 }`, not as a
memory fault. Actual read failures remain memory faults. The compacted
XSTATE_BV subset correction also applies to SMIR XRSTOR(S). Existing typed
restore operations, optimizer effects, native rejection, and state layouts
are unchanged.

## Change-surface map

| Plane | Effect |
| --- | --- |
| Direct decode/execute | Existing encodings retained; restore-only guards, header validation, and MXCSR selection corrected. |
| CPU state | No layout change; snapshot setter validates before mutation; helper extraction preserves transfer fields. |
| Memory/MMU | Checked reads retained; validation makes selected access/fault order explicit. No MMU implementation change. |
| SMIR lift/IR | Existing FXRSTOR/XRSTOR typed operations retained; no new operation or exception enum. |
| SMIR interpreter | FXRSTOR fault classification and compacted header subset correction only. |
| Optimizer | No implementation change; direct/SMIR parity tested at O0/O1/O2. |
| Native lowering/JIT | No admission or host-MXCSR policy change; restores remain unsupported native instructions. |
| Backend/machine/device | No adapter, board, interrupt, or device changes. |
| Oracle/C ABI | Existing decode and typed effects retained; no public layout or enum change. |
| Tests/docs | Portable direct, snapshot, lifted-SMIR, optimizer-level parity, and fault-selection regressions. |

## Assumption Register

| ID | Assumption and basis | Dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- | --- |
| A1 | RAX retains its existing FXRSTOR choice to restore SSE state with CR4.OSFXSR=0; SDM Vol. 1 section 10.5.1.2 leaves that behavior implementation-dependent. | FXRSTOR always selects MXCSR in this implementation. | Test CR4.OSFXSR=0/1 and CS.L=0/1 with valid unmasked values; an explicit profile change to ignore SSE with OSFXSR=0 would falsify this retained choice. | Retained, tested. |
| A2 | IA32_XSS is fixed to zero by the current MSR implementation. | XRSTORS uses XCR0 as its enabled-component bitmap. | Inspect `execute/system/msr.rs` reads and writes of MSR `0xDA0`; acceptance of a nonzero write would falsify the assumption and require propagating supervisor enables. | Confirmed. |

The bit-63 subset condition is a specified rule, not an assumption inferred
from the previous SMIR implementation. Its regression failed in both engines
before the predicate corrections.

## Bounded exclusions

These existing issues do not block the selected-MXCSR validation contract:

| Impact | Evidence and scope boundary |
| --- | --- |
| High | Standalone lifted restore operations do not yet reproduce all CR0/CR4/CPL guards; SMIR has no precise `#NM` exit variant. Parity here explicitly uses enabled controls. |
| High | Arbitrary low-level native frames or callbacks can bypass direct/snapshot validation. Entry/callout host-LDMXCSR defenses and unmasked-integer native admission are separate work; this patch does not establish those invariants. |
| High | Compacted extended-component restoration still omits initialization when a requested component is in XCOMP_BV but absent from XSTATE_BV; the extraction preserves that existing behavior. MXCSR/SSE initialization is covered here. |
| High | Save-side AVX-only MXCSR selection and other save-side checks are unchanged; extracted save helper bodies are preserved. |
| High | Existing raw-x87 layout/tag differences and non-64-bit high-XMM behavior are excluded from parity; XMM0-XMM7 and MXCSR are compared exactly. |

## Reproduction

The focused portable regressions run without an x86 host or host vector
feature requirement:

```sh
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib mxcsr_restore -- --nocapture
cargo +stable test --locked --no-default-features --features x86_64-suite,smir-jit --lib fxsave_restore -- --nocapture
```

Before publication, follow the focused run with the complete affected library
and x86_64 integration binaries, formatting, and an all-target build. These
tests establish implemented direct/SMIR parity, not an independent physical
x86 execution oracle. Encodings used by the tests were independently checked
with LLVM MC: `0F AE /1`, `0F AE /5`, and `0F C7 /3`, with and without REX.W.
