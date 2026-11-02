# Classic GIC discovery and affinity routing

GICD_TYPER now covers the configured classic SPI range, including partial banks.
The count includes the 32 private INTIDs. For S implemented SPI slots, let
S' = min(S, 988). ITLinesNumber is ceil(S'/32), and its nominal maximum INTID is
32 * (ITLinesNumber + 1) - 1. INTIDs 1020-1023 remain reserved. Software discovers
which INTIDs within that ceiling are implemented by probing enable readback.

| Configured SPI slots | ITLinesNumber | Highest implemented SPI |
|---|---|---|
| 0 | 0 | None |
| 1 | 1 | 32 |
| 32 | 1 | 63 |
| 33 | 2 | 64 |
| 256 | 8 | 287 |
| 988 | 31 | 1019 |
| 992 historical storage slots | 31 | 1019 |

The existing historical 992-slot allocation remains representable; its last
four slots do not become interrupts. Storage/configuration and checkpoint layouts
are unchanged. Arbitrary invalid constructor configurations are not qualified.

In the GICv3/v4 classic profile, affinity routing is fixed on. CPUNumber therefore
reads zero and legacy ITARGETSR fields read zero and ignore writes. This does not
establish complete legacy GICv2 target-mask behavior or optional GICv4 facilities.

IROUTER reads and independent lower/upper word writes now preserve all four
affinity levels. Reserved fields read zero and ignore writes. The stored affinity
remains the existing compact Aff3:Aff2:Aff1:Aff0 representation; MMIO maps Aff3 to
bits[39:32], with IRM at bit31 and Aff2:Aff1:Aff0 in bits[23:0]. Under IRM=1 the
affinity fields are architecturally UNKNOWN; this model returns zero for them.
A nonimplemented affinity retains its programmed readback and receives no request,
which is one permitted constrained-unpredictable outcome. Pending retargeting
recomputes the existing per-PE request handles. The guest bridge's existing mutex
covers an entire 64-bit transaction, including its two internal word operations.

## Startup and restoration evidence

Six actual source-free file cases cover one, two and four PEs and both 64-bit and
split-word routing accesses. PE0 executes guest PSCI CPU_ON64 for each secondary;
the fixture does not call request_on or manually drain power requests. Return
codes, secondary context values, executed WFI instructions and coordinator online
state are checked. This starts secondary PEs from an initialized EL1 fixture;
it is not firmware or operating-system cold-boot qualification.

Each PE then executes guest discovery, calculates a distinct top-bank SPI from
ITLinesNumber, programs its route, enables and pends it, enables its CPU interface,
and waits with IRQ masked. The complete VM bundle is saved and loaded, then its
kernel and checkpoint files are removed before constructing a fresh VM. Repeating
restore retains each target-owned request Arc. Both VMs unmask IRQ and take a
zero-retirement entry on every PE. Guest handlers read IAR and full IROUTER,
withdraw the software-pending source with ICPENDR, issue EOI and return. Every PE
reaches its post-handler marker and WFI with its request deasserted. Full CPU
state, instruction counts, controller graph, coordinator and Retired clock agree
before entry, at entry and after continuation. There are 28 post-snapshot handler
executions across the source and restored VMs.

No serialized field, context tag, C ABI identifier or public layout changes.
Existing ambiguous-legacy-source rejection remains unchanged. Previously lost
MMIO programming intentions cannot be recovered from an old captured route;
restoration retains the actual represented routing state.

## Independent reference and gates

[qemu-gic.S](qemu-gic.S) runs under QEMU 11.1.2's four-PE GICv3 virt machine.
Its UART output records discovery, reset/enabled controls, legacy target readback,
full routing and independent upper/lower writes, and the highest implemented SPI.
[qemu-gic-rax-mirror.rs](qemu-gic-rax-mirror.rs) repeats the controller accesses
against the exact compiled RAX library. Nine selected observations match.
Only ITLinesNumber and CPUNumber are compared within TYPER; other capability
fields differ between the models and are excluded. This is an independent QEMU
register oracle, not physical GIC or Intel HVF execution.

[qualification.json](qualification.json) records actual reds, corrected fixture
iterations, complete owning-test results, compiler/source/executable identities,
commands, assumptions and omitted gates. Interrupted or failed iterations are not
passing gates. It includes the full unfiltered library suite, registered cluster
target, all other affected owning executables, all-target build/check/Clippy,
feature checks and doctests. A cfg-empty target supplies compilation evidence.

The primary is [Arm IHI0069H, ID020922](../../specifications/arm/gic-ihi0069.pdf),
sections 12.1.3 (widths), 12.9.22 (IROUTER), 12.9.30 (ITARGETSR), 12.9.38 (TYPER),
and 4.1.2 (interrupt lifecycle). Primary PDF and oracle-source checksums are retained.
Discovery and route-word lookup use O(1) time and additional space. A route write
retains the existing O(P * (32 + S)) controller recomputation for P PEs and S SPI
slots. No throughput benchmark is claimed.

The full A32-FP, C-STATE, C-SMP and C-HVF findings remain incomplete. Full backend,
private/in-flight and coordinated state, RISC-V cross-hart reservations and startup/controller/clock binding, remaining
native profiles, streaming FPSR reentry and physical Intel qualification remain open.
A separate strict two-case probe reproduces SC success after an observed peer
store, including a same-value write; this remains required C-SMP/C-STATE work.
Intel-labeled hosted runners are available; native Hypervisor.framework VM
creation and guest execution remain unverified. The protected primary executable and
guest processes remain outside the build roots. Historical ax.trace truncation
remains unexplained; guarding its current bytes does not establish preservation
of its original content. User files and other checkouts remain outside this group.
