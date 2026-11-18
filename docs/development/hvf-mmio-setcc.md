# Intel HVF scalar SETcc writes

A translated write exit for legacy `SETcc r/m8` previously failed MMIO
planning. The planner now uses the decoded condition and captured RFLAGS
to emit one byte, with value 0 or 1. It checks the decoded effective address,
the recorded GLA/GPA, and that the destination is outside mapped RAM.
The existing output acknowledgement path retires the instruction and
preserves the prepared byte across checkpoint serialization. Preparation
uses constant time and auxiliary space for this fixed-width instruction.

The Intel SDM defines all 16 conditions, an 8-bit destination in every
represented code size, unchanged flags, and #UD with LOCK.
[Intel SDM revision 086, volume 2B, SETcc, pages 4-619 to 4-621](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

| Dependent result | Stress test |
| --- | --- |
| The captured flag image determines the byte | All 32 combinations of CF, PF, ZF, SF and OF across all 16 condition codes in 16-, 32- and 64-bit planner contexts. On physical Intel Linux, 512 independent 64-bit instruction executions also verify the result, unchanged flags and adjacent bytes. |
| The plan represents a single translated byte write | Register operands, LOCK, read-only and read/write EPT qualifications, and a mismatched GLA all reject. |
| A restored pending byte retires once | Both SETE outcomes survive a portable output-state round trip. RIP and host-step completion advance on acknowledgement. General registers and condition flags remain unchanged. |

On Apple Silicon the full `hvf_mmio`, `hvf_memory`, `hvf_guest_translation`
and `hvf_port_io` targets passed 82, 18, 8 and 8 tests, respectively.
Workspace all-target Clippy and the Intel macOS HVF cross-check passed.
The physical Intel oracle uses ordinary memory on Linux. Intel macOS HVF
guest execution for this opcode and the remaining MMIO and interrupt
profiles remain open.
