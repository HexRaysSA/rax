# Explicit VMM clock construction and retired-clock files

`Vmm::new_with_clock(config, mode)` and `Vmm::new_resume_with_clock(config, mode)`
select the VM `TimingContext` before backend devices and CPUs are constructed.
The complete-file constructor `Vmm::new_resume_bundle` selects the saved clock
mode before constructing those objects, so target LAPICs retain the target VM's
clock identity and saved relative timer age is rebased against the correct epoch.

The software backend admits retirement clock modes only when every created
vCPU supports its validated single-step retirement interface. Native KVM/HVF
reject these modes before host VM creation, RAM allocation or kernel access.

The default constructors select wall time. A deterministic default requires
idle policies for the other machine models and control over independent clocks
and external inputs. The retirement clock is a software time model.

## Retirement and restore contract

The existing software budget path publishes one clock unit per validated retired
instruction (Hexagon packet), before the next instruction. At the selected
3,000,000,000 units/s, each unit is exactly one third of a nanosecond. Host delay,
diagnostic tick calls and failed attempts without committed retirement do not
advance retirement time. `ClockMode::Retired` freezes when every CPU is waiting.

On retired-clock PCs, the coordinator services the software PIC, PIT and local
APIC before the selected CPU's next instruction. The clock advances when a step
retires, so a timer that becomes due during a turn can interrupt the next step
without waiting for the remainder of the 1,000-instruction quantum. An already
queued PIC request gets precedence over a fresh IRQ0 on the BSP. The PIT also
publishes an edge to I/O APIC pin 2. The local APIC services pending NMIs at
the same boundary even when the PIC delivers an interrupt.

For incoming phase p and N retired units:

```
q       = p + N
elapsed = initial_elapsed + floor(q / 3)  (u64 nanoseconds, wrapping)
phase   = q mod 3                       (0, 1, or 2)
units   = initial_units + N             (u64 retired units, wrapping)
```

The 44-byte `RAXCLK01` section stores the clock mode. The coordinator's retired
count must equal the clock's retired units. Retirement-mode files require the
coordinator, complete ordered CPU table and every private CPU record. Capture,
configuration admission and in-place restore check this contract. New retired
VMs reject base-only capture/restore and bundles missing a clock section;
otherwise a legacy projection could lose fractional phase or the timeline.
Clock-mode mismatch remains rejected before CPU, RAM or device publication.

## AArch64 idle advancement

Pass `ClockMode::RetiredWithIdle` to the explicit software AArch64 constructor
to let the coordinator advance the common counter during WFI. At each turn it
services CPU power requests and polls timer outputs. Once every online PE is
in WFI, with no pending wake interrupt and no debugger-excluded online PE, it
advances to the earliest level change on an enabled, unmasked timer and polls all
online PEs again. WFE and a pending synchronous exit leave instruction entry
eligible at the current time. With no future timer output, elapsed time freezes.

The platform counter runs at 62,500,000 Hz, so one counter tick spans 16 ns or
48 quanta of one third of a nanosecond. For physical counter tick `p`, virtual
offset `o` and a future comparator `c`, assertion occurs at physical tick
`p + (c - (p - o mod 2^64))`. A local counter wrap withdraws an asserted level
if `c > 0`. The clock rounds up to the first representable quantum at the
transition. At elapsed wrap the physical sample becomes zero, which can also
change the comparator immediately. The scheduler scans the online
set and calculates two deadlines per PE in O(P) time and O(1) auxiliary space.
Idle advancement changes elapsed nanoseconds and phase. The retired count still
counts committed instructions and remains equal to the coordinator count.

Mode code 2 is stored in both the VM-clock and the per-CPU system-counter record.
Files require a complete set of matching shared-counter records. Fresh restore
selects the saved mode before device construction and in-place restore requires
a matching mode. Modes 0 (`Wall`) and 1 (`Retired`) retain their file encodings.
The runtime test saves a four-PE VM in WFI, removes the file source and continues
from the loaded checkpoint with the same wake order, counter values and retired
counts. The machine has a distinct virtual timer on one PE and physical timers
on the others. The same transition tests run at one and two PEs.

The new mode selection and admission cost O(C) time for C CPU records and O(1)
additional state. Existing codec, RAM and device capture costs retain their
independent bounds. These are algorithmic bounds, not measured throughput.

## RV64 idle advancement

The software RV64 VMM also accepts `ClockMode::RetiredWithIdle`. WFI retires
once, yields the turn, and leaves the hart waiting until a locally enabled
interrupt is pending. The usual trap rules still determine whether the hart
takes an interrupt or resumes at the following instruction. A pending
machine-timer interrupt can wake WFI with global MIE clear when MTIE is set.
Wall time and plain retirement time keep their existing WFI hint behavior.

When every online hart is waiting, the coordinator advances to the earliest
eligible ACLINT machine-timer deadline and polls the shared interrupt
controllers again before selecting a hart. The 10,000,000 Hz counter advances
one tick every 100 ns, exactly 300 retirement-clock quanta. For current base
tick `t`, unsigned MTIME `m`, and MTIMECMP `c > m`, the first candidate is
`300 * (t + c - m)` quanta since the start of the elapsed-clock epoch.
At the epoch wrap the base tick restarts at zero and the guest MTIME offset
persists, so the coordinator checks the wrapped epoch for the first assertion.
The deadline scan takes O(H) time for H harts and O(1) auxiliary space.

Complete idle-enabled RV64 checkpoints require the shared interrupt and timer
record. A waiting hart uses the `RAXRV006` private tag with the same payload
layout as `RAXRV005`. A runnable hart can still use `RAXRV005`. Earlier tags
restore without a latched wait. The runtime test compares an uninterrupted VM
with a VM restored from a real file after removing the source kernel. For
one, two, and four harts it checks the order of the wakes, the guest's exact
`rdtime` observations, and the coordinator, CPU and clock records.

| Assumption | Falsification probe |
| --- | --- |
| A locally enabled timer wakes WFI with global MIE clear | A bare-metal QEMU virt fixture at each of the three hart counts checks MTIP and rejects a wake before the programmed comparator. |
| Idle time preserves the first possible assertion | Step to a fractional boundary and across the elapsed-clock epoch wrap. Assert the level is low until the reported deadline and high at the deadline. Include a comparator the next epoch cannot reach. |
| A latched wait survives file restoration | Remove the kernel and compare wake order, timestamps and execution state against uninterrupted execution. Verify that time stops once every hart waits with MTIE masked. |

The RISC-V privileged ISA specifies local enable behavior for WFI and an
unsigned MTIME/MTIMECMP comparison. The QEMU witness covers those wake
conditions. The RAX runtime test covers its own deterministic time and file
format. Physical RV64 timing and replay of external inputs are outside this
qualification. [RISC-V Privileged ISA](https://docs.riscv.org/reference/isa/priv/machine.html)

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
other board consumers, idle policy outside AArch64 and RV64, and full replay
remain open.
The [selected RTC calendar follow-up](../rtc-selected-clock/README.md) now binds
PC CMOS and S5L PMU calendars; Wall external input is still not replayed.
