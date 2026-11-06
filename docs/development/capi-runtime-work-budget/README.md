# Installed-runtime C API functional-test work bound

The installed-runtime functional test used a 30 s host deadline while checking
real installed `true` and `printf` programs. A complete unoptimized C API run
passed 245 tests and failed this check with `RAX_PROCESS_TIMEOUT` on `true`.
The same unchanged executable, run in isolation, completed `true` and timed
out on `printf`: zero passed, one failed, 245 filtered. Both failures are
retained; the isolated run is diagnostic rather than a complete gate.

The functional test now requests batches of at most 256 scheduler turns,
with a total bound of 16,384 turns and `timeout_us = 0`. A budget result must
report progress and may not report more turns than requested. Exit status,
exact stdout, closed host capabilities and malformed dependency precedence
assertions remain active. Production code and dedicated timeout/cancellation
checks are unchanged.

The [public contract](../../../capi/include/rax.h) defines a turn as at most
`slice_instructions`, or a wait/service boundary. With 4,096 instructions per
slice, the CPU-work ceiling is 16,384 × 4,096 = 67,108,864 guest instructions;
wait/service turns can retire fewer instructions. This is a cooperative work
bound. One turn is not hard-preempted. The loop uses constant space and at
most 16,384 turns. This follows the corresponding engine test correction in
commit `9e6e463a892a98cea43a536e91d60f0930de2e38`.

[Qualification](qualification.json) records the actual complete rerun, source
identity and original failure hashes. The local build also contains the
separately owned A32 scalar-prefix correction; it is excluded from this
commit. The observed timeout does not identify host speed, descheduling or
guest work as its sole cause. Completing both programs under a finite work
budget is the falsification probe for a guest nontermination defect.

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| T1 | Both installed programs complete within the finite work budget | Full unfiltered C API suite, exact stdout/exit/dependency precedence; falsified by 16,384 exhausted turns or wrong output/status | Actual outcome in qualification |

High-impact full A32-FP, C-STATE, C-SMP and C-HVF requirements remain open.
Physical Linux/Windows runtime behavior is outside this macOS test result.
No architecture, public API, ABI, dependency, runtime deadline or capability
change is made by this group.
