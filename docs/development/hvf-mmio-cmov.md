# Intel HVF scalar CMOVcc reads

A legacy CMOVcc memory operand is read before the condition selects the
destination value. On a successful read with a false condition, a 32-bit
destination also clears its upper half in IA-32e mode. A fault leaves the
destination intact. The instructions preserve the condition flags.
[Intel SDM revision 086, volume 2A, CMOVcc, pages 3-175 to 3-178](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

Intel HVF uses the normal scalar MMIO address and direction checks before
issuing either condition outcome as a read. The pending record captures the
conditional destination effect. The extension variant is appended to the
existing codec enum so older records keep their discriminants. A valid reply
publishes the captured register effect, if any, and retires the instruction
once. Planning and completion use constant auxiliary space and time for the
fixed-width operand.

| Dependent result | Stress test |
| --- | --- |
| The source is read for either condition outcome. | All 16 conditions, 32 flag patterns and three sizes through the portable planner and checkpoint codec. Reject LOCK, register sources, mismatched exit addresses or direction, and a short reply. |
| A fault occurs before any destination change. | Physical Intel Linux executed 1,536 mapped operands and 1,536 inaccessible operands. The latter preserved the destination and condition flags and reported the precise access address and instruction pointer. The direct interpreter checks the delivered page-fault frame. |
| A successful 32-bit result follows the IA-32e rule. | The portable planner distinguishes legacy and compatibility modes. The x86-64 SMIR test checks both condition outcomes and faults at O0, O1 and O2. |
| The native SDK delivers a device read and retains it across owner replacement. | The `cmov` workflow profile checks both condition outcomes at each width, with and without restoring the pending read into a fresh native CPU. It verifies RIP, the later guest marker, destination, and RFLAGS. |

The physical Intel oracle uses ordinary memory on Linux. Intel macOS execution
is tracked separately from local cross-compilation and portable coverage.
