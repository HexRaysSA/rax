# VM-owned AArch64 system counter

System-mode software AArch64 VMM CPUs now derive the generic physical counter from their owning VM's selected clock. All PEs use the fixed platform frequency of 62,500,000 Hz. Guest CNTFRQ writes change the frequency-description register without changing that rate; each PE retains its own CNTVOFF subtraction. A waiting PE's timer output is refreshed after another PE retires, without executing the waiting PE.

Previously, each core added 16 counter ticks for every system-step attempt, including zero-retirement WFI attempts, and could privately jump to a timer deadline. The baseline executes two regressions: both fail. The change prevents those attempts from advancing a shared counter. Wall time continues independently; Retired time retains its existing zero-retirement freeze. No idle policy or default-clock change is included.

The architectural basis is [Arm Generic Timer](../../specifications/arm/generic-timer/arm-102379_0100_02.pdf), document 102379_0100_02_en, pages 8, 10, 12 and 13: a common system counter, firmware-populated frequency description, per-PE timer outputs and virtual-count offset. The retained primary PDF, digest, LLVM assembly/disassembly and exact validation commands are indexed in qualification.json. Timer comparison remains unsigned; an initial signed-wrap hypothesis was rejected after checking primary definitions.

## Arithmetic and execution

For elapsed nanoseconds n, one-third-nanosecond phase p in {0,1,2}, and frequency f in Hz:

```
physical = floor(((3*n + p) * f) / 3,000,000,000)
virtual  = physical - CNTVOFF_EL2 (modulo 2^64)
```

The widened integer calculation avoids intermediate u64 overflow. One tick is 16 ns, or 48 retirement units at the existing three-units-per-nanosecond scale; downward conversion error is at least zero and less than one tick. This uses the existing u64 nanosecond domain: at this fixed frequency the derived count wraps after a span of 2^60 ticks, rather than modeling a separately continuous full-width physical counter. It does not redefine the existing clock's wrap contract. Counter sampling uses constant time and space. Coordinator refresh uses O(P) time per existing selection/retirement boundary and O(1) additional space, where P is the number of configured CPU slots. No performance qualification is claimed.

## Checkpoint contract

Earlier subgroup qualifications describe tags produced at their recorded commits. The new shared-clock profile changes bound system-adapter records; unbound producers still write schema 03.

| Record | Counter domain | Prefix before unchanged context body |
| --- | --- | --- |
| RAXA6404 | Target VM clock | 8-byte tag; 1-byte mode; 8-byte little-endian fixed frequency |
| RAXA6403 and earlier readers | Explicit legacy instruction counter | Existing 8-byte tag |

When any CPU declares the new shared-counter profile, every CPU must declare the same mode and frequency, with complete CPU, VM-clock and coordinator state. Marker-free public/base projections retain existing legacy admission; the shared-domain guarantee requires the private records. Mixed legacy/shared sets, invalid headers and incompatible target bindings fail before publication. The record remains capped at 16 MiB including the new header. Runtime clock Arcs are never serialized. Offside preparation retains the target Arc without sampling its clock or publishing timer lines; coordinated restore supplies the captured clock state.

CNTVOFF now uses its dedicated architectural bank and denies EL0/EL1 access. Old generic-bank aliases are canonicalized after the original public/private equality check; complete public-state imports also migrate the alias. New shared records reject an ambiguous legacy shadow. Unbound standalone and user adapters retain the existing instruction/external-input domain. Legacy-domain preservation does not claim preservation of the corrected offset-bank defect or silent poisoned-controller handling.

## Evidence boundaries

Existing full-state continuation fixtures select Retired time explicitly; independent Wall continuations cannot have bit-identical live counter samples. The event fixture records its direct prepared-CPU steps in the owning clock and coordinator, including the preparatory instruction in its expected total. Complete CPU-state equality assertions remain. The superseded root run exposed five counter-sample equality failures and one diagnostic compatibility failure; it was cancelled and is excluded from full-suite evidence.

Tests use actual software VMM adapters, guest register instructions and guest GIC MMIO, 1/2/4 prepared PEs, real source-free checkpoint files, fresh and skewed in-place targets, fractional phase and nanosecond/retirement-total wrap. Peer timer assertion and deassertion cross a real file frontier. Wall-mode coverage brackets counter reads on two PEs; exact source-free file/phase/wrap comparisons use Retired mode. A bounded hot loop requires native execution participation on this host; it does not prove native lowering of the MRS instruction itself. The legacy schema-03 file is explicitly transformed from a current payload, not produced by an archived parent executable.

CPU startup in these tests uses platform requests. It is not guest PSCI startup proof. The software shared-counter component does not close A32-FP, C-STATE, C-SMP or C-HVF. Other clocks, all-waiting idle policy, complete native/private/IRQ/replay profiles and physical Intel execution remain open. The macOS AArch64-native integration target is cfg-empty and counts as compilation only; ignored tests and doctests are itemized separately.

## Final local validation

| Gate | Outcome |
| --- | --- |
| focused-prior-root-failures-v9 | 8 passed / 0 failed / 0 ignored |
| doctests-workspace-v9 | 0 passed / 0 failed / 5 ignored; 0 passed / 0 failed / 0 ignored |
| owning-root-library-v9 | 11962 passed / 0 failed / 35 ignored |
| owning-arm-v9 | 46850 passed / 0 failed / 0 ignored |
| owning-arm_vfp_a32-v9 | 521 passed / 0 failed / 0 ignored |
| owning-aarch64_smir_programs-v9 | 75 passed / 0 failed / 0 ignored |
| owning-aarch64_smir_native-v9 | 0 passed / 0 failed / 0 ignored |
| owning-smir_jit_aarch32_aarch64-v9 | 26 passed / 0 failed / 0 ignored |
| owning-smir_jit_thumb_aarch64-v9 | 25 passed / 0 failed / 0 ignored |
| owning-checkpoint_cpus-v9 | 12 passed / 0 failed / 0 ignored |
| owning-checkpoint_resume-v9 | 10 passed / 0 failed / 0 ignored |
| owning-checkpoint_config-v9 | 1 passed / 0 failed / 0 ignored |
| owning-retired_clock-v9 | 13 passed / 0 failed / 0 ignored |
| owning-checkpoint_clock-v9 | 16 passed / 0 failed / 0 ignored |
| owning-retirement_clock-v9 | 10 passed / 0 failed / 0 ignored |
| owning-counter_ticks-v9 | 12 passed / 0 failed / 0 ignored |
| owning-retirement_budget-v9 | 14 passed / 0 failed / 2 ignored |
| owning-user_linux-v9 | 43 passed / 0 failed / 1 ignored |
| owning-capi-library-v9 | 241 passed / 0 failed / 0 ignored |

Formatting, all-target build/check/Clippy, without-debug and without-JIT compilation passed. Exact feature sets, commands, durations, source and executable hashes are retained in qualification.json.
