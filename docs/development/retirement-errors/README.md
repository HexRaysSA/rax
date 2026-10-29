# Completed retirement before a host completion error

The software AArch64 system adapter publishes CPU retirement before it completes
a firmware call. A host error during that completion can therefore occur after
the instruction has retired. Its budget result and retirement clock must retain
that completed unit, while returning the original error.

Failed instruction meters have different semantics. eBPF/SBPF can charge a failed
attempt without retiring it. The default budget policy retains that existing
behavior. Error status alone cannot distinguish those cases.

## Internal accounting contract

The architecture-neutral budget helper has two internal error policies:

| Policy | Failed-step accounting | Selected by |
| --- | --- | --- |
| `NoRetirement` | Return the original error with earlier successful retirements; preserve any charged backend meter. | Default `VCpu` implementation and AArch64 user-mode budgets. |
| `CounterDelta` | Validate and publish the counter's completed-retirement delta before returning the original error. | AArch64 software system budgets. |

The policy and helper remain crate-internal. Public trait signatures, C ABI,
and serialized private fields are unchanged. The AArch64 system observation
count already records completed retirement; its publication precedes firmware
completion. The previously qualified
[system-entry](../a64-system-entry/README.md) and
[private-counter](../a64-retirement-counters/README.md) contracts remain in force.

For the committed-counter policy:

```text
delta = counter_after - counter_before (mod 2^64)
require delta <= 1
retirement_clock += delta
budget.retired += delta
return Fault(original_error)
```

An error takes precedence over budget exhaustion, including an error after the
last requested retirement. A zero delta remains nonretiring. A delta greater
than one remains a contract failure and cannot publish unverified clock units.
A zero budget does not probe or enter the backend under either policy.

## Actual adapter reproduction

The receipts and frozen source archives are retained under
`/Users/int/dev/rax-audit-work/four-findings-aarch64-cluster/a64-host-error-retirement`.
The baseline ran four tests: healthy firmware and zero-budget controls passed;
the actual HVC and SMC error cases failed. Both observed one published CPU
retirement while the returned budget and retired clock reported zero.

The fixture uses the normal clustered adapter constructor. It performs an
`AFFINITY_INFO` query through HVC or SMC, with a deliberately poisoned host
cluster-control lock. The injection changes no guest inputs or cluster contents.
The test catches its deliberately injected panic and requires the resulting
adapter error to remain `Error::Emulator("AArch64 cluster: control lock poisoned")`.
That injected panic is distinct from the observed failing accounting assertion.

LLVM MC independently verifies `HVC #0` as bytes `02 00 00 d4` and `SMC #0` as
`03 00 00 d4`. These fixtures qualify internal retirement accounting through a
real software adapter; they are not a physical PMU, KVM, or HVF retirement oracle.

The final actual-adapter matrix covers two calls, three amounts of prior work,
two observation-counter phases, and two budget positions: 2 * 3 * 2 * 2 = 24
failure scenarios. The guest PC and an untouched following ADD verify the
stopping frontier. After repairing the injected host failure, one subsequent
instruction executes without replaying the firmware call or losing a clock unit.
This is accounting-continuation coverage, not general host-failure recovery.

Separate helper tests cover default charged/uncharged failures, prior progress,
counter wrap, zero and invalid deltas, error precedence at the budget boundary,
zero budgets, and unsupported stepping. The complete existing retirement-budget
integration binary exercises actual eBPF and every supported SBPF version.

After selecting an explicit disposable Cargo target and existing scratch
directory, run from the repository root:

```sh
cargo +stable test --locked --offline --lib --no-default-features \
  --features x86_64-suite,smir-jit,hvf retirement_error_tests:: \
  -- --test-threads=1 --nocapture
cargo +stable test --locked --offline --test retirement_budget \
  --no-default-features --features x86_64-suite,smir-jit,hvf
```

Final acceptance requires complete owning library and integration binaries,
C API tests, workspace format/Clippy/build, interpreter-only and x86-64
compilation, source verification, an exact-path commit, and idle-cache cleanup.
Focused passing tests alone do not establish completion.

## Assumption register and remaining boundaries

| ID | Assumption and dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- |
| ER1 | Completed guest retirement precedes some host firmware errors and must remain in the budget and clock. | Actual HVC/SMC, prior work, wrapping observation phase, budget-edge errors and continuation. No prior CPU retirement, or divergent returned/clock units, falsifies it. | Confirmed within the recorded real-adapter host-error matrix. |
| ER2 | A charged failed attempt is not necessarily a retirement. | Both internal policies and actual eBPF/SBPF meter regressions. Charging the failed unit to the clock or changing its error falsifies it. | Confirmed by both policy tests and actual eBPF/SBPF integration controls. |

High impact: complete backend/private/in-flight state, pending completion frames,
coordinated external writers, transactional late-failure restoration, hardware
and other-ISA native entry, additional ARM/wait/event profiles, and physical
Intel HVF remain separate requirements. The four full findings remain incomplete.
Medium impact: other backend completion-error classifications require their own
evidence before adopting committed-counter accounting. The helper adds O(1)
time and O(1) auxiliary space per attempt; a K-attempt budget remains O(K), apart
from the backend instruction and completion work.

Final qualified source: all 10 focused tests and all 13 complete budget
integration tests passed. The complete library passed 11,288 tests with two
ignored; all 47,694 integration tests across 22 complete binaries and all 223
C API tests passed. Workspace format/Clippy/build, interpreter-only and x86-64
compile checks, documentation links and frozen-source checks passed. Doctests
executed zero cases with five ignored. Physical Intel runtime validation did
not run.
