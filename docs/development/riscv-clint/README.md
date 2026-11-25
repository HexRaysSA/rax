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

Fresh default firmware harts clear `misa.H`. Version 3 of the firmware
profile provided M/S/U harts with Bare translation. Software uses `misa.H`
to discover the hypervisor register file and two-stage translation.
Complete checkpoint restore uses the hart configuration from the saved
CPU record.

An RV64 Bare-mode supervisor payload passed on two and four harts with the
unmodified OpenSBI v1.8.1 `FW_DYNAMIC` image. A guest reset stub supplied the
dynamic firmware information and device tree. The payload called SBI Hart State
Management to start each secondary twice, checked the hart ID and the distinct
opaque value delivered on each entry, and waited for `STOPPED` after each run.
QEMU 11.1.2 passed the same firmware, payload and supplied device tree with H
and PMP disabled. The RAX runs exercised the software coordinator and the
CLINT software-interrupt wakeup path. [SBI HSM v2.0](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/v2.0/src/ext-hsm.adoc)

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

## Instruction fetch across a memory boundary

The RV32 and RV64 interpreter and native-JIT entry point fetch instructions
in 16-bit parcels. If a parcel is inaccessible, the core reports its
address in `mtval` or `stval` and records the instruction start in `mepc`
or `sepc`. The second parcel address wraps at XLEN. Fetch takes constant
time with at most two backing reads and adds no checkpoint fields.
[RISC-V Privileged Architecture 20250508, §§3.1.16 and 12.1.9](../../specifications/riscv/riscv/riscv-privileged.txt)

| Assumption | Falsification probe | Result |
|---|---|---|
| A second-parcel fault leaves the faulting instruction unretired. | Start an RV64 `ADDI` at `0xffe` with memory ending at `0x1000`. Delegate the access fault to S mode and check the cause, `sepc`, `stval`, destination and retirement count. Run the interpreter and the JIT entry point. | The baseline reported `stval=0xffe`. Both entry points now report `stval=0x1000`, retain `sepc=0xffe` and leave the destination and retirement count at zero. |
| The configured address width governs the second fetch. | Fetch a 32-bit encoding at the last halfword on RV32 and RV64. Supply its high halfword at address zero and require exactly two parcel reads. | Both decode the complete `ADDI` encoding. |
| The full virt machine delivers the same trap as an independent system emulator. | Boot the same LLVM-linked RV64 ELF on RAX and QEMU 11.1.2. The guest checks `scause=1`, `sepc=0x107fffffe`, `stval=0x108000000` and an untouched `ra` before UART output and shutdown. | Both exited zero and each emitted one `RAX-FETCH-PARCEL-PASS` marker. |

The ELF was assembled with LLVM 23.0.0git using
`llvm-mc -triple=riscv64 -filetype=obj fetch-parcel.S -o fetch-parcel.o`
and linked with `ld.lld -m elf64lriscv --no-relax -Ttext=0x80000000
fetch-parcel.o -o fetch-parcel.elf`. The ELF SHA-256 is
`a487d7b53166f779fa45de23a3db0e22c49df88c0ceaf0af6d60d2ca88743c8b`.
RAX used `RAX_MACHINE=riscv-virt`, one vCPU and 128 MiB of configured
RAM plus the current 4 GiB padding. QEMU used `virt`,
`rv64,h=false,pmp=false` and 2,176 MiB from `0x80000000`. Both backings
end at `0x108000000` exclusive. The source, bytes and run logs are in
`/Users/int/dev/rax-audit-work/four-findings-riscv-fetch-parcel-2026-11-25/`.

The RISC-V library filter passed 374 tests. The boot, SMIR lift and
AArch64 JIT integration targets passed 12, 26 and 16 tests. Library Clippy
with warnings denied passed on Apple Silicon. The unfiltered library
run over `7b02b98d6` passed 13,414 tests with two ignored.

The Sv39 profile below applies the same parcel rule across virtual page
boundaries.

## Sv39 in the RV64 virt firmware profile

The RV64 `riscv-virt` firmware profile accepts Bare and Sv39 in `satp`.
It walks up to three 8-byte page-table entries per attempt and accepts
aligned 4 KiB, 2 MiB and 1 GiB mappings. The walk uses constant storage
and checks canonical virtual addresses, PTE encoding, effective privilege,
and access permissions. A/D updates use a RAM compare-and-exchange and
restart the walk if the PTE changes. Translated instruction parcels,
including diagnostic disassembly reads, use RAM. Disassembly leaves A/D
unchanged. Translated data accesses still route through the physical
memory map. LR/SC reservations use the translated physical address.
[RISC-V Privileged Architecture 20250508, §§3.1.6.4, 12.1.11, 12.3.2 and 12.4](../../specifications/riscv/riscv/riscv-privileged.txt)

The native JIT entry uses the interpreter for instructions with active
fetch or data translation. There is no translation cache to flush at
`SFENCE.VMA`. Hart record `RAXRV007` and shared virt platform record v4
identify Sv39 support. Restore validates the capability across the
platform and every hart before publishing replacement CPUs. Older virt
records retain Bare behavior. RV32, GSC and process memory bindings keep
their existing semantics.

| Assumption | Falsification probe | Result |
|---|---|---|
| Each hart uses its own `satp` and observes shared PTE updates. | Boot byte-identical two- and four-hart ELFs. Have every hart translate shared pages, participate in atomics, and fence after a remap. | QEMU 11.1.2 passed both. Baseline RAX stopped at `satp`. The revised RAX passed both. |
| A translated fetch can fault on the second parcel and retry at the first. | Use two distinct frames and install the second PTE from the fault handler. Check `scause=12`, `sepc=0x40000ffe`, `stval=0x40001000`, and the destination before and after retry. | QEMU and revised RAX passed. Baseline RAX stopped at `satp`. |
| The active translation mode follows effective access privilege. | Contrast M-mode fetch and MPRV data access, vary SUM and MXR, and check that failed accesses preserve the target. | QEMU and revised RAX passed. Baseline RAX stopped at `satp`. |
| Management and zero operations differ in permissions and dirty-bit behavior. | Run cache-block operations over read-only and unmapped pages. Check A/D bits, store-class faults and the original effective address. | The revised RAX passed. QEMU confirmed permission and A/D behavior but rounded the unaligned trap values to 64-byte block boundaries. RAX retained the original operands, `0x40001034` and `0x40000034`. [RISC-V Unprivileged Architecture, §19.4.2.2](../../specifications/riscv/riscv/riscv-unprivileged.txt) |
| The in-flight fetch fault survives a source-free checkpoint. | Stop at a UART scratch-register write inside the handler, then delete the ELF and restore with `RAX_MACHINE` unset. Also present a legacy hart record on an Sv39 platform. | The guest resumed from a file captured at 84 retirements and passed. The mismatched hart record was rejected. |

The guest sources, image hashes, commands and logs are under
`/Users/int/dev/rax-audit-work/four-findings-riscv-sv39-2026-11-25/`.
On Apple Silicon, the RISC-V library filter passed 378 tests. The boot,
SMIR lift and AArch64 JIT integration targets passed 12, 26 and 16
tests, respectively. Library Clippy passed with warnings denied. The
unfiltered library suite passed 13,418 tests with two ignored. The C API
library passed 266 tests with 21 ignored.

The checkpoint witness at 84 retirements uses an explicit execution yield.
The [exact-count checkpoint](#exact-retirement-checkpoints) below captures
inside the same handler without a forced yield. Sv48 and VS/VU translation
remain open.

The two-hart Debian Linux 6.12.117 boot with OpenSBI v1.8.1 reached
paged supervisor execution and reported `smp: Brought up 1 node, 2 CPUs`
on the optimized RAX CLI. The boot did not reach the PID 1 affinity test
within the 900 s host limit. The four-hart RAX run reached paged kernel
initialization and also timed out before PID 1 affinity. The same kernel,
firmware and initramfs passed the affinity test on all CPUs in the two- and four-hart QEMU
reference runs. Images, commands, logs and the RAX checkpoint with
active Sv39 are under
`/Users/int/dev/rax-audit-work/four-findings-riscv-linux-2026-11-25/`.

## Exact retirement checkpoints

The software coordinator can end a turn at an automatic checkpoint count.
When the triggering instruction exits for I/O, the coordinator services the
exit before capture. An automatic file records the completed retirement count
and the cursor for the next CPU. A failed write during a nonterminal turn
leaves the trigger due and can be retried at that boundary before another CPU
enters.

| Claim | Probe | Observed result |
|---|---|---|
| A trigger can capture inside a turn. | Request retirement 79 in the Sv39 split-fetch handler without a UART yield. Remove the ELF before restoring in a new process. | The baseline captured at 106. The revised CLI saved `instret=79`, `sepc=0x40000ffe`, and `stval=0x40001000`. Both revised processes emitted one pass marker and exited with status 0. |
| Explicit and periodic triggers share a schedule. | Interleave unsorted explicit counts with a periodic trigger and a final x86 ACPI power-off. Read the files and inspect the program counters and retirement counts. | The files record retirements 2, 5, 7 and 10. |
| A failed write preserves the next-CPU cursor. | Fail a two-CPU guest's capture at 2, remove the obstruction and retry. Restore from the file and compare the peer's RAM writes and final retirement count. | The retry captured at 2. The peer wrote first in both runs, and the live and restored VMs finished with identical memory and retirement counts. |
| MMIO completion remains the capture boundary for a non-stepping CPU. | Set an already-due capture count and issue an MMIO read-modify-write from either CPU. Also fail the completion callback. | The initial guard failed all three cases. With the software-only guard, successful completions saved the issuing CPU's registers and a failed completion produced no checkpoint. |

Commands, the input ELF, hashes and logs are under
`/Users/int/dev/rax-audit-work/four-findings-exact-checkpoint-2026-11-25/`.

## RV64 virt firmware power-off

The software RV64 virt firmware profile reserves the SiFive test device at
physical address `0x0010_0000` for 4096 B. Naturally aligned 16-bit and
32-bit accesses read as zero. A zero-code `0x5555` write to the base
register powers off the VM. Reset and nonzero termination status commands
raise a store access fault. Writes to other offsets have no device effect.
The device classifies access and publishes terminal state in O(1) time and
space.

The platform's version-5 checkpoint stores the terminal state for the
entire VM. Version-4 and earlier records retain their recorded capabilities,
including the original mapping at the finisher address. A version-5 terminal
restore stops before the coordinator enters any CPU. Generic RV64 machines
continue to use the original memory map.

| Claim | Probe | Observed result |
|---|---|---|
| Firmware sees a device at the virt test address. | Write a sentinel to a non-command offset, then read it back. | The old RAX read its RAM sentinel and timed out. QEMU 11.1.2 read zero and powered off. |
| OpenSBI system reset can request power-off. | Run the same two-hart device tree, OpenSBI v1.8.1 firmware, and supervisor payload in both engines. The payload makes an SBI SRST shutdown call. | The baseline RAX printed the pre-call marker, then timed out. Revised RAX and QEMU each printed it once, never returned to the caller, and exited with status 0. |
| A terminal file can restore without replaying the power-off instruction. | Request a checkpoint at the instruction that powers off, then delete the input ELF and restore with no machine override. | The producer emitted one UART byte before powering off at retirement 7. The restored process exited 0 without UART output. |
| A file from the prior Sv39 profile retains its state. | Restore the version-4 split instruction fetch file in a fresh version-5 process with no machine override. | The guest completed its fault-handler retry and emitted its pass marker once. |

QEMU's device and OpenSBI's system reset driver define the reference
register and firmware path. [QEMU 11.1.2 SiFive test device](https://raw.githubusercontent.com/qemu/qemu/v11.1.2/hw/misc/sifive_test.c)
[OpenSBI v1.8.1 system reset driver](https://raw.githubusercontent.com/riscv-software-src/opensbi/v1.8.1/lib/utils/reset/fdt_reset_syscon.c)

Commands, inputs, hashes, and logs are under
`/Users/int/dev/rax-audit-work/four-findings-riscv-linux-2026-11-25/`.

### Debian SMP boot and power-off

Debian Linux 6.12.117-1 ran under OpenSBI v1.8.1 with the same device
tree and initramfs in both engines at each hart count. PID 1 applied
`sched_setaffinity` for each CPU, checked it with `getcpu`, and requested
power-off. RAX used the public `Vmm::new_with_clock` entry point with
`RetiredWithIdle` and the guest options `quiet nowatchdog`.

| System | 2 harts | 4 harts |
|---|---|---|
| QEMU 11.1.2, virt | Observed CPUs 0 and 1, power-off, exit 0 | Observed CPUs 0 through 3, power-off, exit 0 |
| RAX RV64 virt, before the finisher | Observed CPUs 0 and 1, guest power-down log, host timeout | Observed CPUs 0 through 3, guest power-down log, host timeout |
| RAX RV64 virt, with the finisher | Observed CPUs 0 and 1, power-off, exit 0 | Observed CPUs 0 through 3, power-off, exit 0 |

The earlier RAX wall-clock control with the same guest options timed out
at two harts before any PID 1 affinity marker. This result qualifies the
retired-clock software profile. Default wall-clock and other backend
qualification remain open. The successful four-run comparison is in
`final-linux-comparison.json` beside the raw logs and runner source.
[Linux RISC-V boot requirements](https://docs.kernel.org/arch/riscv/boot.html)
