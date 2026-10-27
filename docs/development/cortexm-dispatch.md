# Cortex-M VM factory dispatch

The emulator VM factory now selects the existing `CortexMVcpu` adapter for
`ArchKind::CortexM`. It previously returned `Unsupported architecture: CortexM`
even though the interpreter, backend adapter, machine loader and initial-state
builder already existed. The selected adapter retains its existing Cortex-M4
software profile. Other selector branches and legacy board handling are unchanged.

Eight regressions cover configured/direct backend factories, the full u32 CPU-ID
representation at its boundaries, actual Thumb data operations, WFI/wake retirement
boundaries, vector-table boot state and existing base snapshot import. A same-source
existing-API consumer checks an x86 creation control and Cortex-M selection against
actual predecessor/current libraries. The predecessor rejects Cortex-M; current
code constructs the adapter. Independent LLVM 23 encoding receipts retain the
exact program bytes.

The independent model creates seven separate CPU objects in groups of 1/2/4 and
checks 21 retired instructions and 336 observation bytes: group size, CPU ID,
retirement count, PC, register result and stored memory word. It rejects a one-bit
corruption in each of the 42 result words. These groups do not execute concurrently.

| ID | Assumption and dependent result | Basis; stress and falsification probe |
|---|---|---|
| M1 | The architecture selector chooses the existing adapter. | One factory arm; exact old/current creation probe and state-kind/stepping checks through both factories. |
| M2 | Selection enables actual execution. | LLVM-produced MOVS/STR/ADDS/WFI/MOVS bytes; exact register, PC, memory and retirement observations. |
| M3 | Existing loader state reaches the selected CPU. | Actual VMM construction reads vector SP/reset entry; verify MSP, Thumb PC/xPSR and VTOR, then base save/load/restore. |
| M4 | Other backend behavior is unchanged. | Entire factory source is byte-identical after removing the added arm; unsupported ARM selectors retain explicit errors. |
| M5 | CPU-object groups are construction/execution observations. | Separate objects and direct calls only; no SMP scheduling or shared interrupt-controller claim. |

Dispatch adds O(1) selection work. CPU creation and instruction execution retain
the existing adapter's costs. The fixture/model storage is linear in the seven
observation rows. No native latency or complete instruction-set bound follows.

High impact: peripheral/UART and IRQ routing, complete private Cortex-M/FPU/lazy
exception state, CPU-model configuration and full machine validation remain open.
ARMv8 AArch32 and Cortex-R selection are separate unresolved work. Medium impact:
the current generic Cortex-M selection uses the existing M4 profile. Low impact:
future profile selectors must carry explicit capabilities and checkpoint identity.
