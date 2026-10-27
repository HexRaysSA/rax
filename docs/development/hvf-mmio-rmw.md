# Scalar HVF MMIO read/modify/write

The native x86 HVF exit planner decodes modifying scalar memory instructions
before issuing device I/O. It captures source registers, incoming flags, operand
width, effective address and instruction length. The VMM services a typed
`VcpuExit::MmioRmw` through one device transaction, releases the model lock, then
returns the old operand to the producing vCPU. Only that completion publishes
register/flag effects and retires the instruction.

| Family | Represented effects |
| --- | --- |
| ADD, ADC, SUB, SBB | Fixed-width arithmetic, carry/borrow and arithmetic flags |
| AND, OR, XOR | Memory result and defined logical flags |
| INC, DEC | Arithmetic flags with incoming CF preserved |
| NOT, NEG | Complement without flag changes; arithmetic negation |
| XCHG, XADD | Old memory value written to the named source register part |
| CMPXCHG | Comparison flags; accumulator writeback only on failure; a write cycle on both outcomes |
| BTS, BTR, BTC | Selected-bit update and CF; signed register bit-string offsets |

Widths are 1, 2, 4 and 8 bytes; bit-string instructions use 2, 4 or 8 bytes.
Partial/high-byte registers and 32-bit zero-extension retain their architectural
meaning. Register bit offsets adjust the addressed word before translation;
an immediate selects a bit within the addressed operand. Both write-only and
read/write EPT qualification encodings are admitted for these instructions.

`MmioRmwOp` contains a pure little-endian byte transformation. The default
`MmioDevice` transaction performs one read and one write. Shared PCI, LAPIC,
PL011 and 16550 adapters hold one model mutex across both callbacks. In
particular, a failed CMPXCHG writes the old value back. Other CPU/device users
of the same shared model cannot interleave a read or write within that guard.

The backend keeps a pending completion until register/flag updates and
instruction completion succeed. Bad input or an SDK failure latches an error;
re-entry and repeated completion cannot repeat device effects. The VMM queries
that status before automatic checkpoint capture, including for port-input
completion. This is error propagation, not complete recovery of failed native
operations or a representation of every backend's in-flight state.

## Independent regression corpus

`tools/hvf/mmio_rmw_oracle.py` executes 9,320 actual CPL0 long-mode instructions
under QEMU 11.1.2 TCG. The corpus has 9,176 unique inputs: the repeated inputs
retain RDI's simultaneous address-base/bit-source alias. It covers all 16 GPR
fields, high-byte aliases, the represented widths, LOCK presence/absence,
incoming carry/flag states, both CMPXCHG outcomes, register/immediate arithmetic,
and signed/immediate bit offsets. No product helper computes expected outputs.

Each guest record contains all 16 GPRs, a 24-byte memory span and before/after
RFLAGS. AF is excluded for logical operations; OF/SF/AF/PF are excluded for the
bit-string operations. All other flags and every recorded memory/register bit
are compared. The registered `hvf_mmio` test replays each record against both
permitted EPT encodings: 18,640 product plans/completions.

The immutable fixture is `tests/fixtures/hvf/mmio-rmw-v1`. Its 172-byte inputs
occupy 1,603,040 bytes; its 168-byte records plus 20-byte framing occupy
1,565,780 bytes. The total 3,168,820 bytes retain the full stated matrix without
requiring LLVM/QEMU in ordinary CI. The manifest records source/tool/artifact
hashes and commands. Fresh generation uses a new evidence directory; capture
refuses to overwrite an existing fixture.

```sh
cargo +stable build --locked --no-default-features --features x86_64-suite,smir-jit,hvf,debug --lib
python3 tools/hvf/mmio_rmw_oracle.py \
    --out /tmp/rax-hvf-rmw-new-run \
    --llvm-bin /path/to/llvm/bin \
    --qemu /path/to/qemu-system-x86_64 \
    --product-rlib target/debug/librax.rlib
```

The guest reserves separate regions for the operand, probe code, stack and
corpus/output buffers. Its 64 MiB RAM bound and maximum corpus count are checked.
RAM execution proves instruction effects; it does not prove physical device
delivery or Intel VMX behavior. Bus tests separately verify callback widths,
the failed-comparison write cycle, concurrent shared-model updates, poisoning,
and rejection before effects. Actual VMM tests verify lock release, completion
on the producing CPU and automatic-checkpoint frontiers. Their mock backend
does not establish native retirement accounting; its checkpoint assertions
cover published CPU registers, not serialization of an arbitrary test device.

## Assumption register

| ID | Assumption / selected domain | Stress test / falsification probe | Status |
| --- | --- | --- | --- |
| H1 | A modifying scalar EPT exit sets write; its read bit is implementation-specific | Same guest records through qualifications 0x182 and 0x183 | Primary-defined; 18,640 comparisons passed |
| H2 | One shared-model mutex spans the complete device transaction | Two competing adapters; deterministic guard checks in both callbacks; exact final counter and callback pairs | Tested locally |
| H3 | Metadata/flag helpers implement the represented instruction effects | Independent QEMU full-register/memory/defined-flag comparison, including comparison success/failure and aliases | Tested within the frozen corpus |
| H4 | Instruction bytes and page tables remain stable during inspection | Existing range/truncation tests; concurrent modification requires a separate ownership protocol | Full concurrent-inspection requirement remains open |
| H5 | A physical Intel host is available for native validation | Identify an Intel host and run nonempty VMX/device guests | Host availability unknown; local software and cross-build checks do not establish physical Intel execution |

## Remaining full-goal boundaries

| Impact | Required follow-up |
| --- | --- |
| High | Cross-mapping RMW needs one ownership protocol across every participating device; the current bus rejects it before effects |
| High | Wide CMPXCHG, shifts/rotates, other read-compute instructions, string/vector/segment/APX profiles and guest TF/debug completion remain required |
| High | Complete pending/native/backend state, coordinated capture/restore and recovery after native publication failures remain required |
| High | Native per-vCPU LAPIC/CR8/IRQ coherence, bounded scheduling/startup and physical Intel execution remain required |

Pure transformations take O(1) time/space with at most 8 operand bytes. Bus
mapping selection takes O(D) time for D registered mappings. Inspection is
bounded by 15 instruction bytes, 8 data bytes and the represented paging depth.

Primary expectations come from the pinned Intel SDM revision 086:
`docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`, SHA-256
`6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73`.
Volume 3C 29.2.1/Table 29-7 specifies EPT qualification; Volume 2A CMPXCHG
specifies the comparison/write-cycle contract. BTC/BTR/BTS Flags Affected
specifies unchanged ZF and undefined OF/SF/AF/PF. Their instruction entries and
the arithmetic/logical entries define the remaining effects.

This component does not close C-HVF, C-STATE, C-SMP or A32-FP.
