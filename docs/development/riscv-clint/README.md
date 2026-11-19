# Generic RV64 CLINT and coordinated checkpoints

The generic software RV64 VMM binds every configured hart to one classic CLINT.
The controller supplies machine software interrupts, machine timer interrupts,
and a shared 10 MHz time source. GSC, standalone interpreter adapters and
user-mode harts retain their existing memory providers.

| Address | Register | Supported access |
|---|---|---|
| `0x02000000 + 4*h` | MSIP for hart h | naturally aligned 4-byte read/write; bit 0 |
| `0x02004000 + 8*h` | MTIMECMP for hart h | naturally aligned 4/8-byte read/write |
| `0x0200bff8` | shared MTIME | naturally aligned 4/8-byte read/write |

The aperture is `[0x02000000, 0x02010000)`. Unimplemented hart slots and reserved
registers read zero and ignore writes. Unsupported widths, misalignment and
cross-aperture accesses fault before changing controller state or shadow RAM.
LR/SC and AMO/CAS transactions overlapping the aperture are rejected. Loader
admission and stopped debugger RAM access exclude the aperture as well.

The primary register definitions are the retained RISC-V ACLINT 1.0-rc4 draft,
chapters "Backward Compatibility With SiFive CLINT", "MTIMER", and "MSWI".
This is an explicitly selected classic CLINT profile; it does not claim
supervisor ACLINT, PLIC, AIA, SBI, a DTB or Linux boot qualification. QEMU's
retained `riscv_aclint.c` supplies an independent implementation comparison;
its unsupported-slot behavior does not define every RAX fault policy.

MSIP resets to zero. RAX chooses `UINT64_MAX` for the architecturally unspecified
MTIMECMP reset value. MTIME resets to zero at controller construction. The
controller retains its VMM's `Arc<TimingContext>` before CPU creation, so entering
an unrelated ambient clock cannot change the source used by this controller.
MTIME is the owned counter plus a writable offset, modulo 2^64. Half-register
writes preserve the other half. MTIP is asserted when unsigned MTIME is greater
than or equal to that hart's comparator; changing time or a comparator can also
deassert it. Every entry/frontier poll reapplies MSIP/MTIP and the time CSR to the
core. A CPU write to `mip` cannot take ownership of a peripheral input.

At 10 MHz one tick is 100 ns. The selected Retired clock advances one 3 GHz unit
per retirement, hence 300 retired units per timer tick. Interrupt entry retires
zero instructions and does not advance this clock. Wall mode uses elapsed VM
time. These are platform clock policies, not a physical CPU cycle model.

## Checkpoint profile and publication

New CPU-private records use `RAXRV003`, followed by one profile byte (0 for the
legacy memory provider, 1 for CLINT), then the reservation/core/adapter payload.
Other profile values are rejected. `RAXRV001` and `RAXRV002` import explicitly as
legacy ordinary-RAM providers. Their former RAM contents are never inferred to
be software-interrupt registers. A standalone single-hart context import requires
the same current provider profile; complete VMM import coordinates profile changes
across all detached CPU replacements.

`RAXEXE09` carries the shared CLINT source registers, time offset and topology.
A materialized CLINT checkpoint requires matching private records for every
configured hart, coordinator state, complete clock state and every byte of the
legacy zero-based mapped RAM, including its 4 GiB padding. Missing/inconsistent
sections reject before publication. Base-only capture from an active CLINT VMM
rejects and directs callers to the complete bundle API. Explicit legacy base
restore selects the original ordinary-RAM profile.

```text
stopped CPU cohort
  -> exclude controller writers
  -> capture/publish CPU + coordinator + clock + complete physical RAM
  -> publish shared controller/profile
  -> release physical writer exclusion
  -> resume guest execution
```

Capture and restore hold the shared controller mutex across the coordinated
publication closure. Context capture uses an atomic profile mirror and does not
re-enter that mutex. Ordinary MMIO samples its owned clock before acquiring the
controller mutex. Complete VMM capture/restore require exclusive stopped-VM access;
independent raw memory aliases and external clock writers must be quiescent.
There are no guest/device callbacks under the controller lock. A rejected commit
retains the prior shared controller/profile.

## Verification and limits

The actual VMM guest in `tests/fixtures/riscv/vmm_clint.S` installs an M-mode trap
handler and requires both software and timer work from every hart before the BSP
can shut down successfully. Its LLVM-produced words are retained in
`tests/support/riscv_clint.rs`. The independent public `riscv_boot` consumer and
library exercise one, two and four harts. The additional
`vmm_clint_future_prefix.S` variant sets each comparator 64 ticks into the future;
the Retired VMM must advance at least 19200 retirement units before completion.
Both variants are independently assembled and their exact guest bytes run under
QEMU with `icount shift=10,align=off,sleep=off`. A separate two-hart `shift=0`
run reaches the bounded guest failure loop. Its retained register/memory diagnostic
observes the BSP's expired wait counter and later completed work on both harts;
this configuration does not qualify the witness's bounded scheduling assumption.
It is retained as a failed oracle run, not counted as a passing reference. The source-free file test captures with
both interrupt sources pending and global MIE masked, deletes the source image,
restores a new VMM, unmasks delivery and verifies new handler work on every hart.
The Retired source/restored pair compares all private contexts, coordinator and
clock state after continuation.

The negative matrix covers missing sections, a mismatched final hart profile,
reserved profile bits, legacy RAM imports, bounded wire decoding, controller
poison/rejected publication, atomic overlap and loader/debugger shadow-RAM
exclusion. See `qualification.json` for observed counts, failures and independent
oracle results. Register accesses and signal sampling take O(1) time and storage;
controller capture/restore takes O(N) time and storage for N harts. Whole-VM
physical capture additionally visits and compresses all mapped RAM.

## Supervisor interrupt delivery

The RV32/RV64 hart now samples all six represented interrupt causes before
interpreter fetch and before JIT region entry. The pending and enable bits
are intersected, delegation selects the destination, and a candidate
targeting M-mode takes priority over one targeting S-mode. Within each
target, the applicable order is MEI, MSI, MTI, SEI, SSI, STI. An eligible
interrupt changes privilege and trap state without retiring an instruction
or acknowledging its source.
[RISC-V Privileged Architecture 20250508, §§3.1.8–3.1.9 and 12.1.1–12.1.9](../../specifications/riscv/riscv/riscv-privileged.txt)

S-mode entry writes `sepc`, `scause` and `stval`, copies SIE to SPIE,
clears SIE and records the originating privilege in SPP. Direct `stvec`
uses BASE. Vectored `stvec` adds 4 bytes times the interrupt cause to BASE,
with address wrap at XLEN. `stvec`, `sscratch`, `scause` and `stval`
use the existing sparse CSR records in the public and private hart state.
An absent entry reads zero, so the saved CPU record layout and legacy
public-state comparison are preserved. Interrupt selection examines at
most six causes and requires constant extra space.

In the isolated baseline, a pending delegated SSI lost to an instruction
access fault. The owning regression uses the same PC and pending bit to
verify zero-retirement trap entry. A separate fixture verifies the
`MRET` to SSI handler to `SRET` sequence on one, two and four harts.
It also holds each handler with SSIP still pending, saves a file, removes
the boot image and resumes both the source and restored VM. The handler
checks its restored CSRs and clears SSIP before returning. Both VMs are
compared at the final coordinator, clock and private hart boundaries.
[Guest assembly](../../../tests/fixtures/riscv/vmm_supervisor_irq.S)

QEMU 11.1.2 completed the ordinary-run guest with one, two and four harts
using the same position-independent code. The detached file continuation
is qualified by the RAX VMM tests. Synchronous supervisor traps and PLIC
device delivery remain open.

The Apple Silicon integration projection over `c0121da24` passed 160 tests
across the ISA oracle, RISC-V boot and hart identity, and RISC-V lift and
AArch64 JIT targets. The x86-64 JIT and the Linux-only scalar and vector
differential targets registered zero tests on this host. The full library
run over `cdca6ca3b` with the same implementation and test files passed
13,096 tests with two ignored. `c0121da24` adds a disjoint Windows RPC change.

All original audit findings remain partially validated. This group does not
qualify other backend/controller profiles, full input replay, or physical Intel
Hypervisor.framework execution. The preceding group's independent CI failures
remain separately recorded in `../riscv-vmm-startup/qualification.json`.

## Interrupt input ownership

The RV32 and RV64 cores keep the external controller's SEIP line and the
M-mode software injection bit separately. Guest MIP and delegated SIP
reads, trap selection, and WFI use their logical OR. The MIP CSR's set and
clear instructions return the combined value to the destination register
and use the software bit as the write operand. Guest MIP writes preserve
MSIP, MTIP and MEIP because the platform owns those inputs.
[RISC-V Privileged Architecture 20250508, §3.1.9](../../specifications/riscv/riscv/riscv-privileged.txt)

Public register transfers carry the software injection so that exporting
and importing registers cannot latch a controller-owned signal. Private
`RAXRV004` records add one byte for the external line. Versions 1 through
3 retain their existing pending bits and start with the separate line
deasserted. The generic VMM had no producer for a separate controller
line in those versions. GSC validates that its unused external SEIP line
is low and keeps its existing record format.

The isolated baseline failed both source-ownership regressions. QEMU
11.1.2 verified the architectural effects using CLINT and PLIC inputs
on RV32 and RV64. The RAX tests exercise instruction execution, private
adapter restore, and legacy-record admission. Full UART-to-PLIC routing
is a separate platform change.

The integration run over `d5327b278` passed 176 tests across the ISA
oracle, retirement budgets, boot, hart identity, lift and Apple Silicon
JIT targets. The C API run over the same parent passed 246 tests. The
full library run over `4fb7c6a84` with the same implementation and test
files passed 13,100 tests with two ignored. The intervening Windows RPC
change touched disjoint files. The x86-64 host JIT and Linux-only RISC-V
differential targets registered zero tests on this host.

## UART interrupts through the virt PLIC

The generic RV64 emulator maps the shared PLIC at `0x0c00_0000` for
`0x0060_0000` bytes. Source zero is reserved and the 16550 drives level
source 10. Each configured hart has a machine and supervisor target, in
that order. The controller accepts aligned, little-endian 32-bit accesses.
The machine and supervisor external inputs are sampled before hart entry.
[QEMU virt board map](https://github.com/qemu/qemu/blob/v11.1.2/include/hw/riscv/virt.h)

The controller distinguishes pending, in-service and asserted input state.
Only an enabled pending source with priority above the target threshold
asserts a notification. A claim ignores the threshold and clears the
shared pending bit. Completion from an enabled target releases the
gateway, which immediately re-pends a level that remains asserted.
[RISC-V PLIC specification](https://docs.riscv.org/reference/plic/v1.0.0/index.html)

Host console input and destructive guest UART reads update the shared UART
output under the platform lock. The VMM publishes writes after dispatching
the ordered MMIO exit and before admitting the next hart. Checkpoints
capture the UART and PLIC together. They validate the saved UART level
against serial state and require every private hart to agree with the
shared platform profile before restore. Version 2 controller records
retain priorities, per-context enables and thresholds, level, pending
and claim state. Version 1 keeps the CLINT-only mapping, and the private
hart reader accepts saved versions 1 through 4.

The old CLI failed the same guest code on one, two and four harts. The
fixture checks M- and S-mode cause, resume PC and claim on every hart.
QEMU 11.1.2 completed 30 common-path runs across those topologies. The RAX
fixture additionally checks the gateway rule for a still-asserted level
and saves a file with a claim in service before removing the boot ELF.
The work covers the generic software board and its 16550 connection.
[Guest assembly](../../../tests/fixtures/riscv/vmm_plic_uart.S)

A separate CLI replay saved a CLINT-only file at retirement 87 after
writing guest RAM at the future PLIC address. Both the old and current
CLI resumed the file after the boot ELF was removed and verified the
saved value. A cold boot of the current profile intercepted that same
address as a PLIC register. The unfiltered library run passed 13,109
tests with two ignored. The isolated integration run passed 176 tests
and the C API run passed 246 tests on Apple Silicon. The shared
MMIO dispatch passed 135 Hypervisor.framework MMIO and ownership tests
on that host. Physical Intel execution remains unverified.

## Synchronous trap delegation in the core

RV32 and RV64 now honor the implemented `medeleg` bits when a
synchronous exception originates in U or S mode. Both synchronous and
interrupt entry share the supervisor trap frame. `stvec` vectored mode
uses its aligned base for an exception. Delegated entry records
`sepc`, `scause`, and `stval`, updates SIE, SPIE, and SPP, and preserves
the machine trap registers and machine status fields.
[RISC-V Privileged Architecture 20250508, §§3.1.8 and 12.1.1–12.1.9](../../specifications/riscv/riscv/riscv-privileged.txt)

The interpreter and native region use the same delivery path. The
existing ECALL exit remains available to embedders. If the embedder
calls `deliver_ecall_trap`, it uses the same architectural delegation.
The process adapter reports faults at the original guest PC even when
the embedder has restored machine exception delegation CSRs.
The changed path keeps the existing CPU record layout. The system VMM
selects how to dispatch those synchronous exits.

Three baseline regressions entered MTVEC with delegation enabled.
The revised integration tests verify RV32 and RV64 state across
illegal instructions, U-mode ECALL delivery, and a faulting native
load after a retired prefix. The native test requires one JIT entry
and zero interpreter fallbacks at O0 and O2. QEMU 11.1.2 independently
confirmed the machine-mode control, supervisor-mode illegal
instruction, and user ECALL paths on both XLENs.

The unfiltered library run passed 13,110 tests with two ignored. The
integration and C API suites passed 180 and 246 tests. The Linux
user-mode suite passed 43 tests with its optional live Docker oracle
ignored. Both RV64 fixture and corpus comparisons passed with and
without JIT enabled.

## Synchronous traps in the virt firmware profile

```sh
RAX_MACHINE=riscv-virt rax --arch riscv64 --backend emulator --memory 128M --kernel firmware.elf
```

In this profile each hart delivers `ECALL` and `EBREAK` (including
`C.EBREAK`) to its guest trap handler. A synchronous fault that the core
has already delivered resumes at the selected guest vector. Trap entry
retires zero instructions and returns control to the coordinator so a
peer hart can run. The ELF `tohost` symbol remains available for shutdown.

The default bare-metal profile keeps the existing host exits for `ECALL`,
`EBREAK` and other synchronous faults. Version 3 of the shared platform
record saves the firmware selection together with the CLINT and PLIC.
Restoring a full checkpoint recovers the saved selection across all harts,
regardless of the launch environment. Versions 1 and 2 and a missing
platform record retain legacy exit handling. Standalone, GSC and process
adapters keep their separate exit conventions.

| Assumption | Falsification probe | Result |
|---|---|---|
| The coordinator can continue a delivered fault without a host exit. | Run identical LLVM-linked ELFs on RAX and QEMU 11.1.2. Check M/S cause and the fault PC before UART output and shutdown. | The baseline stops before both markers. The revised CLI prints both expected markers and exits successfully. |
| The saved policy controls every hart after restore. | Save before any handler instruction retires on one, two and four harts. Delete the ELF, restore in a new process with `RAX_MACHINE` unset, and require every hart to return, execute its following instruction, and take a second exception. | Each hart retires exactly six instructions between the two exceptions. |
| The mode switch preserves compatibility. | Decode version 3, reject a failed restore, then restore a version 2 record and an absent record. Run the existing bare-metal boot guests. | The shared platform keeps its prior policy after failed publication, and legacy records select host exits. |

The profile affects guest exception and scheduling behavior. Native
hypervisor continuation and Intel hardware coverage remain outside this
component. [RISC-V Privileged Architecture 20250508, §§3.1.8 and 3.3.1](../../specifications/riscv/riscv/riscv-privileged.txt)

The unfiltered library run over `ea4dd6009` passed 13,116 tests with two
microkernel tests ignored. The owning integration targets passed 180
tests, including bare-metal boots and retirement budgets. The C API
passed 245 tests with `x86_64-suite,smir-jit`. The Linux-only RISC-V
differential targets and x86-64 JIT target registered zero tests on
Apple Silicon. The intervening Windows change touched disjoint files.

## MRET memory privilege

On RV32 and RV64, `MRET` clears `mstatus.MPRV` when it returns to U or
S mode. A return to M mode preserves `MPRV`. The change uses the existing
architectural and private checkpoint representation for `mstatus`.
[RISC-V Privileged Architecture 20250508, §§3.1.6.1 and 3.1.6.4](../../specifications/riscv/riscv/riscv-privileged.txt)

The direct regression executes a decoded `MRET` for each return mode on
both XLENs and checks the target, PC and interrupt-enable stack. The
independent RV64 witnesses set `MPRV`, execute `MRET`, then issue `ECALL`
to read `mstatus` in a validated machine trap frame. The baseline fails
the U and S returns and passes the M control. QEMU 11.1.2 and the revised
VMM pass all three identical LLVM-linked ELF witnesses.

The combined firmware and `MRET` source over `36f1a583a` passed 13,117
unfiltered library tests with two microkernel tests ignored, as well as
180 integration tests and 245 C API tests, on Apple Silicon.

## Privileged instruction admission

The RV32 and RV64 cores check the current mode and machine interception
bits before retirement or any destination register or CSR write.

| Operation | U mode | S mode | M mode |
|---|---|---|---|
| `satp` read/write, `SFENCE.VMA`, `SINVAL.VMA`, `HFENCE.GVMA`, `HINVAL.GVMA` | Illegal | Illegal if TVM is set | Admitted |
| `SFENCE.W.INVAL`, `SFENCE.INVAL.IR`, `HFENCE.VVMA`, `HINVAL.VVMA` | Illegal | Admitted | Admitted |
| `WFI` | Illegal | Illegal if TW is set | Admitted |

The table assumes the instruction's extensions are present.
`HINVAL.VVMA` and `HINVAL.GVMA` require both H and Svinval. For the
standard flat-memory core, `satp` is fixed at Bare with zero ASID and
PPN. Admitted fences need no translation-cache work. An admitted `WFI`
still completes as a hint, and locally enabled pending interrupts can
resume it while global delivery is masked. TVM and TW already travel in
the hart's `mstatus` checkpoint field. Xsoteria preserves the sparse
register at address `0x180` separately from the standard `satp` path.
[RISC-V Privileged Architecture 20250508, §§3.1.6.6, 3.3.3, 12.1.11, 12.2.1, 13 and 21.3](../../specifications/riscv/riscv/riscv-privileged.txt)

| Assumption | Falsification probe | Result |
|---|---|---|
| The flat board can enforce admission without translating addresses. | Run the same ELF encodings with QEMU 11.1.2 and the RAX virt firmware CLI. Verify the exact fault PC, illegal-instruction cause, trap value and register preservation. | QEMU passed 44 cases at each XLEN. The RV64 RAX baseline passed 26 of 44 and the revised CLI passed 44 of 44. |
| Hart policy is local and survives checkpoint restore. | Give alternating harts different TVM/TW values and require each hart to observe its own pair of trap outcomes. Capture before releasing the harts, remove the ELF and restore in a new process. | For one, two and four harts, QEMU passed and baseline RAX failed. Revised RAX passed on cold boots and after resuming files captured at 1,000, 2,000 and 4,000 retirements with the launch override unset. |
| Interception precedes effects even when a CSR access suppresses one half of the transaction or an interrupt could wake an admitted `WFI`. | Run RV32/RV64 CSR regressions including a write-only form and an unsupported mode value. Restore an S-mode hart with a locally enabled and globally masked interrupt. | The denied operations leave retirement and the destination unchanged. The saved software-interrupt bit remains pending across the illegal `WFI` trap. |
| `HINVAL` depends on both extensions. | Independently disable H and Svinval for each encoding and each XLEN. | QEMU passed eight illegal-encoding cases. The RAX decoder test also covers both extensions enabled and both absent. |

These checks take constant time per instruction and add no checkpoint
fields. Sv39 translation, VS/VU execution and the remaining native
backends are outside this component.

The unfiltered run over `48c397467` passed 13,125 library tests with two
ignored, 180 owning integration tests and 245 C API tests on Apple
Silicon. The Linux-only RISC-V differential targets and the x86-64 host
JIT target registered zero tests on this host.
