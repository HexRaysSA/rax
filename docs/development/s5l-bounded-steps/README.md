# S5L8900 bounded platform execution

S5L8900 now exposes the production stepping/retirement-budget interface. The
coordinator can stop at its exact 1,000-unit quantum instead of treating the
legacy 65,536-attempt batch boundary as a guest HLT, and records completed work.
Both interfaces retain the existing platform operation: timers, IRQs, WFI,
bring-up hooks, crypto and DMA. Shutdown detected inside an attempt is returned
immediately rather than first appearing as HLT.

The original counter now excludes executed undefined/access/data-fault attempts.
Fault delivery yields before a handler instruction. Successful SVC and WFI still
complete once; condition-failed FP instructions complete without FP access or
status effects. The counter wraps modulo 2^64: (2^64 -2) +2 becomes 0. Zero budget
performs no entry. There is no second counter or new checkpoint wire field.
Existing model timer/idle pacing remains; these are model units, not physical
ARM1176 timing measurements.

Nine baseline cases failed: seven platform and two actual factory/coordinator
witnesses. The parent charged denied FP and aborted loads as 1 rather than 0,
reported a newly detected shutdown as HLT, rejected bounded entry, recorded 0
rather than 2 completed units, and fabricated HLT at a host batch boundary.
Baseline matrix tests stop at their first failure; not every partition ran red.

An initial repaired multi-context fixture assumed all configured CPUs started
online. Source and the actual failure falsified that assumption: cold startup
intentionally admits CPU0 only. Selection tests now explicitly prepare online
contexts and separately verify the unchanged cold policy. This does not establish
S5L secondary startup or physical multicore support. Those full-scope requirements
remain open; the production startup/coordinator implementation was not changed.

| Validation | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| Complete S5L runtime, including all 10 existing tests | 19 | 0 | 0 |
| Actual factory/coordinator, cold policy and prepared 1/2/4 contexts | 3 | 0 | 0 |
| Exact recovered historical S3C fixture compatibility | 1 | 0 | 0 |
| Complete root library, zero filters | 11859 | 0 | 35 |
| Complete C API library, zero filters | 240 | 0 | 0 |
| CI workflow regression binary | 12 | 0 | 0 |

Workspace format and all-target check/build/Clippy passed. Doctests executed 0
examples with 5 ignored. Counts overlap: focused cases are also in the owning
library. Instruction fixture bytes were independently assembled/disassembled with
LLVM; that is encoding evidence, not physical ARM1176 admission conformance.

The runtime shrank from 5,429 to fewer than 1,500 lines. Sixty original parent
method bodies and 21 bridge method bodies are token-identical after relocation;
all 10 old test names remain. New modules stay below 1,500 lines. A mechanical
visibility error on six trait methods was caught by compilation and corrected
before qualification. No unsafe blocks, core ISA semantics, SMIR/native admission,
C ABI layouts or dependency versions were added or changed.

The first primary-checkout build also exposed an ignored pre-FHM S3C binary
required by a tracked include. Its exact archived 5,160 bytes and recorded SHA-256
were recovered, explicitly tracked and marked binary. No new legacy fixture was
synthesized. See [recovery](../arm-fhm/fixture-tracking-recovery-2026-11-02.json).
Current compiled project inputs are audited as tracked or exact owned inputs;
final readback verifies tracking after both commits.

See [qualification.json](qualification.json) for exact commands, executable/source
hashes, observed failures, the startup assumption correction and falsification
probes. Both semantic groups use the exact staged `red` workflow directly on
master. Their idle external build/scratch directories are removed after commit;
the primary live executable, user files and unrelated branches are preserved.

| Impact | Remaining boundary |
| --- | --- |
| High | Complete S5L core/device/in-flight/NAND/UART/resource state and coordinated checkpoint publication remain required. |
| High | The full A32-FP/C-STATE/C-SMP/C-HVF findings, architectural startup/clock/replay and physical Intel validation remain open. |
| High | The independent native streaming-FPSR failure remains unresolved. |
| Medium | A bounded guest quantum retains variable synchronous crypto/DMA/diagnostic cost; no hard host-time bound or physical multicore claim is made. |
