# Native KVM secondary startup

The VMM now refreshes native scheduling eligibility from the in-kernel IRQchip.
KVM's MP-state query accepts pending INIT/SIPI events. UNINITIALIZED, INIT_RECEIVED
and AP_RESET_HOLD CPUs wait; RUNNABLE/SIPI_RECEIVED and HALTED CPUs remain eligible
for finite host entry, including interrupt wakeup. Managed IRQchip creation is
tracked explicitly; software backends and native VMs without an IRQchip retain
coordinator ownership.

Polling defers while any native I/O completion is pending, even after an input
reply or all output acknowledgments. The next native entry completes that
instruction before the pending controller event is observed. The expanded native
INIT/input/public-observation case passed within all16 native public-state cases.

```text
BSP INIT/SIPI -> kernel AP state -> eligibility poll -> finite AP entry
AP HLT       -> fixed IPI       -> finite AP entry   -> handler -> EOI -> HLT
```

The actual `Vmm::run` guest runs1/2/4 native CPUs. APs execute a real-mode
trampoline at0x20000, enter protected mode, write fresh per-CPU RAM flags and
handle two fixed IPIs around HLT, acknowledging each with EOI. The BSP uses a
bounded wait and requests ACPI shutdown with an explicit success/failure marker.
The trampoline avoids the PC loader's page tables. Every selected case requires
usable native KVM; no replacement CPU or missing-hardware skip establishes green.

The unchanged production baseline passes the1-CPU control and fails2/4 startup.
After the bridge, startup and both IPI rounds pass, exposing physical-host CPUID
IDs7/7 and7/7/7/7. The corrected full library applies the shared per-CPU identity
projection before SET_CPUID2. All three complete native cases then pass with
IDs0/1 and0/1/2/3, and all ten native I/O cases pass again. Source/library hashes
and actual command/results are retained in the adjacent receipts.

This host reports no populated topology level and no leaf1F. Conditional checks
do not establish those unsupported profiles. Configured topology counts/cache
sharing and AMD extended topology remain open; identity correction does not
claim their reconciliation. Complete backend/private/in-flight restoration,
coordinated native timers/IRQs/RAM, native source-free files, clocks/replay and
physical Intel HVF remain full requirements. See `qualification.json` for the
completed component qualification, assumptions and probes.

The corrected combined production library also passes the independent pending
INIT public-observation probe, all three complete SMP cases and all ten IO cases.
Public reads no longer accept INIT; exact source/library identities are retained
in `public-observation-corrected.json`. The final current-source Cargo checks
include the expanded native public-state selection.

Final combined IO/SMP qualification passed all14 gates. The actual expanded native
public-state selection passes16 cases; IO8, port3, XSAVE15, coordinator20, native
SMP3, nativeIO10, minimal2 and workflow12 also pass. Two compile-fail doctests
pass and five pre-existing examples remain ignored. These component results do
not replace the separate unfiltered-library result or close the full findings.
