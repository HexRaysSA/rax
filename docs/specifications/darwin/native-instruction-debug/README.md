# Native ARM64 instruction breakpoint control

The own-process probe creates three workers, suspends each before it can enter the target, installs comparator 0 through `thread_set_state(ARM_DEBUG_STATE64)`, reads the normalized state, and releases that worker. Its SIGTRAP handler records PC/ESR and clears only the current worker's debug state before returning. Every worker is joined and every semaphore destroyed. The process exits naturally with zero only when all expected outcomes hold.

| Control | Read-back BCR | Trap count | Result |
| --- | --- | --- | --- |
| Disabled comparator | `0x0` | 0 | Target completes |
| Enabled, exact instruction address | `0x1e5` | 1 | SIGTRAP at the target, ESR `0xc2000022` |
| Enabled, different address | `0x1e5` | 0 | Target completes |

Observed on Darwin 27.3.0 arm64, 2026-11-12. The ESR encodes EC `0x30`, IL 1 and FSC `0x22`; the faulting instruction has not executed when the signal is delivered. Only comparator 0 was exercised. This does not establish the native comparator count, watchpoint behavior, other kernel revisions or Windows/Linux native behavior.

The source and exact compiler invocation, source/image hashes, return code and stdout are preserved in `provenance.json`. Reproduce with Apple clang using `-std=c++20 -O0 -g0`, building inside the current checkout and placing all temporary files there. Only the probe's own threads and objects are affected.

The implementation contract comes from the existing Arm shared ASL 2025-12 copy. The existing Linux kernel 6.19 `ptrace_hbptriggered` source maps an instruction comparator to SIGTRAP/TRAP_HWBKPT without replacing the saved fault record. Existing XNU `sleh.c` maps EC 0x30/FSC 0x22 to EXC_BREAKPOINT, EXC_ARM_BREAKPOINT and PC. These source references and their repository provenance are distinct from the observed host kernel revision.
