# Explicit VMM clock construction and retired-clock files

`Vmm::new_with_clock(config, mode)` and `Vmm::new_resume_with_clock(config, mode)`
select the VM `TimingContext` before backend devices and CPUs are constructed.
The complete-file constructor `Vmm::new_resume_bundle` selects the saved clock
mode before constructing those objects, so target LAPICs retain the target VM's
clock identity and saved relative timer age is rebased against the correct epoch.

The software backend admits `ClockMode::Retired` only when every created vCPU
supports its validated single-step retirement interface. `Wall` retains the
existing path. Native KVM/HVF retired mode is rejected before host VM creation,
RAM allocation or kernel access. No configuration field, serialized clock or
CPU record, C ABI, ISA semantic or native lowering format changes.

The default constructors continue to select wall time. The audit's intended
deterministic default remains unfinished: switching it requires a defined idle
advance and conversion of independent board clocks. S5L boot/heartbeat anchors,
for example, still use host `Instant`; RTC and entropy remain separate inputs.
This component does not establish whole-machine determinism, native retirement,
architectural secondary startup, physical cycle accuracy or record/replay.

## Retirement and restore contract

The existing software budget path publishes one clock unit per validated retired
instruction (Hexagon packet), before the next instruction. At the selected
3,000,000,000 units/s, each unit is exactly one third of a nanosecond. Host delay,
diagnostic tick calls, failed attempts without committed retirement and waits
with zero retirement do not advance this selected clock. A fully waiting retired
clock therefore remains frozen; automatic idle advancement is an open default-
scheduling requirement, not an implicit host-time fallback.

For incoming phase p and N retired units:

```
q       = p + N
elapsed = initial_elapsed + floor(q / 3)  (u64 nanoseconds, wrapping)
phase   = q mod 3                       (0, 1, or 2)
units   = initial_units + N             (u64 retired units, wrapping)
```

Arithmetic and the 44-byte `RAXCLK01` section remain unchanged. The coordinator's
retired count must equal the retired clock's units. Retired files require the
coordinator, complete ordered CPU table and every private CPU record. Capture,
configuration admission and in-place restore check this contract. New retired
VMs reject base-only capture/restore and bundles missing a clock section;
otherwise a legacy projection could lose fractional phase or the timeline.
Clock-mode mismatch remains rejected before CPU, RAM or device publication.
Legacy wall-mode projection behavior is unchanged.

The new mode selection and admission cost O(C) time for C CPU records and O(1)
additional state. Existing codec, RAM and device capture costs retain their
independent bounds. These are algorithmic bounds, not measured throughput.

## Evidence

The observed parent-engine regression writes a real complete retired-clock file
through a fixture-only binding to the existing producer, removes the source
kernel, decodes the file, and reaches the public configuration/constructor path.
It fails with the old unconditional retired-file rejection. That injection does
not claim that an old public explicit constructor existed or that a guest timer
executed under the injected binding.

Repaired tests cover both modes for the six implemented architecture selectors
and explicitly retain both-mode denial for the unresolved Armv8a32/CortexR
selectors. They also cover a real
cold-constructed AArch64 NOP/WFI raw guest, early native denial, and 1/2/4 prepared
x86 CPU files with actual RDTSC/store/NOP/HLT execution. Each CPU retires eight
instructions; its timestamps observe the initial counter plus 8*CPU_ID and
8*CPU_ID+4. All three incoming fractional phases and u64 counter/time wrap are
exercised. Restored CPU/private bytes, RAM timestamp results, exact coordinator
state and selected LAPIC counters are compared. Foreign ambient timing scopes
and varied host delays must not change those observations.

Additional admission cases remove clock/coordinator/CPU/private records or
corrupt the coordinator/clock count relation. The live retired target's full RAM,
CPU/private bytes, clock and coordinator remain unchanged after rejection.
Native configuration denial and base-only loss prevention are exercised too.
Prepared online contexts do not substitute for guest architectural AP startup.

`qualification.json` records source hashes, the reconciled Assumption Register,
exact commands and counts, implementation planes and bounded limitations. The
audit ledger retains all four original findings as partially validated.

The follow-up [S5L elapsed-clock group](../s5l-selected-clock/README.md) now
binds S5L boot/heartbeat elapsed consumers to this selected clock and restores
them from the incoming logical publication epoch. Synthetic timer profiles,
PMU RTC, other board consumers, default/idle policy and full replay remain open.
