# DIV and IDIV on Intel HVF MMIO

The baseline rejects a valid translated `DIV` byte read during MMIO
planning. The division planner admits legacy `F6/F7 /6` and `/7` memory
operands and retains the dividend until the device supplies exactly 1,
2, 4, or 8 bytes. Completion assembles the double-width dividend and
checks whether the quotient fits before publishing either result.
The byte form writes AL and AH. The wider forms write both accumulator
registers. Time and auxiliary storage are bounded per instruction.
[Intel SDM 086, Vol. 2A DIV and IDIV](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

Zero divisors and out-of-range quotients deliver `#DE` at the saved
instruction pointer. The hardware-exception entry carries vector 0
without an error code. Fault completion leaves the result registers
and RIP at the original instruction, omits retirement, and discards the
data-breakpoint causes for that instruction. If the host cannot install
the event, the pending record fences further execution and retains the
reply. Once installed, the event occupies the same VM-entry slot used
by IRQ and NMI delivery.
[Intel SDM 086, Vol. 3A Interrupt 0 and Vol. 3C §28.6.1.1](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

| Assumption | Stress test |
|---|---|
| The exit describes one translated device read. | Vary operand width, code width, prefix, ModR/M form, exit direction, and reply length. |
| Arithmetic completion can fault after the device supplies the divisor. | Exercise zero, signed and unsigned overflow, the minimum signed dividend divided by -1, and remainder sign at all widths. Check the call sequence and holds on host failure. |
| An owned entry event must survive interrupt attempts. | Exercise occupied entry slots and failed VMCS writes. The native profile also tries IRQ and NMI delivery between divide completion and guest re-entry. |
| A pending dividend is independent of guest instruction fetch after restore. | Round-trip the pending record and finish with the original dividend. The native profile recreates the vCPU both before the reply and after queuing the fault. |

The native `implicit-divide` profile compares 80 MMIO observations
with the same guest encodings using RAM. It checks both result registers,
fault RIP, saved flags, DR6, and the continuation marker. Native
qualification requires the workflow and its guest observations.
