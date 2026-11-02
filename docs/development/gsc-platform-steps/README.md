# GSC platform-aware bounded execution

The production coordinator uses the stepping interface for GSC. Previously
that interface called only the RISC-V hart, bypassing platform work in `run`.
Actual guest tests observed five failures: frozen timer reads, omitted UART
interrupt delivery, missing WFI UART arming, an undrained warm reset and a
bypassed entropy hook. Two actual factory/coordinator witnesses independently
read timer 0 instead of 1 and cold RSTSRC 0x01 instead of warm RSTSRC 0x22.
Their production implementation was byte-equal to the recorded parent.

`run` and `step_insn` now share one platform-aware operation. Each operation
synchronizes timer/UART IRQ sources and PC/time observations, retains existing
bring-up hooks, attempts at most one guest instruction and drains its reset
request. State-only hooks return control without retiring an instruction or
executing the replacement PC. A PLT reset event drains its reset before any
additional guest instruction. Zero-budget calls still perform no work.

The represented RISC-V core **preserves** its diagnostic counters across warm
reset. An initial test incorrectly assumed it cleared them, and observed 4
rather than 0 after the reset store. That falsified the assumption; a redundant
adapter counter was removed before final qualification. The original reset red
stopped at the missing reset before that incorrect expectation was evaluated;
the independent VMM witness also observed cold RSTSRC. The original counter
source remains, with reset, terminal-exit and wrap checks. No architectural
counter policy or new checkpoint field was introduced.

The actual timer witness retires 24 NOPs and one LUI before the MMIO load:
floor(25 instructions / 24 instructions per model tick) = 1 model tick. The load
brings retirement to 26; EBREAK does not retire. The reset witness retires 8
instructions before resetting and 4 after restarting: 8 + 4 = 12. The bounded loop
guard handles 33 reset requests after 4 instructions each: 33 * 4 = 132 completed
instructions, then a terminal exit. These are model counts, not SI time or
physical GSC measurements.

| Validation | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| GSC runtime, including all 40 existing tests | 53 | 0 | 0 |
| Actual factory/coordinator, isolated child processes | 2 | 0 | 0 |
| Complete root library, zero filters | 11,658 | 0 | 35 |
| Complete C API library | 239 | 0 | 0 |

Workspace formatting and all-target check/build/Clippy passed. Doctests
executed zero examples with five ignored. The 15 instruction words were checked
with installed LLVM assembly, linking and disassembly. See
[qualification.json](qualification.json) for exact hashes, commands, the
assumption register, its falsification probes and the initial failed assertion.

The touched GSC implementation and all 40 existing tests moved into smaller
modules without changing their test names. The inherited runtime file shrank
from more than 3,500 lines to fewer than 2,000; new modules remain below 1,500.
Child-process board selection does not mutate the parent process environment.
No global setting or new worktree is needed.

| Impact | Remaining requirement |
| --- | --- |
| High | Complete GSC/S5L8900 private/platform checkpoint restoration remains open. This group adds no private producer. |
| High | Full startup/IRQ/clock/replay, other backend profiles and physical Intel requirements remain open. |
| High | The independent native streaming-FPSR failure remains unresolved. |
| Medium | Physical GSC conformance and complete real firmware/TPM hook behavior were not qualified. |

Each operation performs at most one core attempt or a state-only transition;
existing MMIO/memory and optional diagnostics retain their own costs. No hard
host-time scheduling bound or physical multicore GSC claim is made. Native
HVF/KVM, C ABI layout, context framing, ISA/SMIR and native admission did not
change. Native and extra C/C++ execution are outside this group's affected
planes. All four original full findings remain open.
