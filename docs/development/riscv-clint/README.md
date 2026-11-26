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

### Shared timer frontier in complete RV64 files

Complete RV64 capture samples the VM clock once while the shared platform
is stopped. It adds the saved MTIME offset modulo 2^64 and uses the result
for the TIME CSR in every public and private hart record. In that same
frontier, CLINT supplies MSIP and MTIP, and the saved PLIC, when present,
supplies MEIP and the separate external SEIP line. Software-injected SEIP
and the other guest-owned pending bits are carried through. This uses
the existing file layout and performs no guest entry or live hart updates.

The four-hart regression fixes the wall clock at 12,345,600 ns and
programs MTIME to 90,000 ticks. It sets hart 1's comparator to that same
tick, asserts hart 2's software interrupt and seeds hart 3's software
SEIP. The baseline file reported TIME = 0 in the first hart record. The
test checks the live source records for byte equality across capture and
admits the resulting file into a fresh VM with the source VM and kernel
removed. The restored public and private records agree before any hart
retires an instruction.

Restore first compares the saved public and private hart records. It then
rebuilds the cached TIME and hardware-owned pending inputs from the file's
clock, CLINT and PLIC while preparing detached harts. The transaction
publishes the rebuilt harts with those same shared devices. Files produced
before capture used a common clock sample can therefore resume with coherent
inputs. The saved record layout and software-owned pending bits are preserved.
Rebuilding takes one projection per hart and linear time in the total size
of the private records.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| A historical file can contain matching public and private hart records that precede the saved device state. | High | Save and reload a four-hart file with records from MTIME 99 and a shared platform at MTIME 100. Read each restored hart before entry. |
| CLINT and PLIC own their input levels independently of the software SEIP latch. | High | Move MSIP and MTIP between harts and reroute an asserted UART from supervisor to machine and supervisor targets. Compare the full restored private records with a coherent capture, including a hart with both software and hardware SEIP asserted. |

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

### One Sv39 walk for parcels on the same page

The architectural fetch resolves the first parcel's virtual page once. A
second parcel on the same 4 KiB page reuses its physical page and carries
out its own physical read. A parcel on another page walks that page and
reports its own virtual address on fault. The mapping is local to the
instruction fetch. For L levels traversed per parcel, a same-page 32-bit
fetch reduces page-table entry reads from 2L to L, excluding A/D retries.
It uses O(1) temporary space.
[RISC-V Privileged Architecture 20250508, §§12.3.2 and 12.4](../../specifications/riscv/riscv/riscv-privileged.txt)

| Assumption | Falsification probe | Result |
|---|---|---|
| Both parcels share a mapping and the following instruction walks afresh. | Execute a 32-bit instruction at an address aligned to 2 B, count PTE reads, then remap the page and repeat at the same PC. | The parent performed six PTE reads. The revised fetch used three on each execution and observed the new target after remapping. |
| A page boundary still gives the second parcel its own translation. | Execute across a page boundary with the second PTE missing, check the trap PC and address, install the second mapping and retry. In a separate fixture, capture at retirement 84 in the handler and remove its ELF before restoring. | QEMU and the revised CLI both passed. The saved retirement count was 84 and `sepc` was `0x40000ffe`. The capture process and the fresh restore each printed one pass marker and exited with status 0. |
| Paged fetch cost matters to the four-hart interpreter. | Profile the archived turn-batched Debian boot twice for 8 s. Time an identical Sv39 guest with 90,000,000 loop instructions on baseline and revised builds, with two interleaved runs per build. | The two host profiles counted 1,086 and 1,070 Sv39 walk samples out of 3,181 and 3,184 main-thread samples. The four-hart synthetic guest passed on both builds, with median elapsed time of 23.23 s on the baseline and 18.41 s on the revision, a 20.8% reduction for this workload. |

Each hart in the timing guest verifies its arithmetic result and publishes
a distinct bit. The boot hart prints the pass marker after all four bits
are set. QEMU 11.1.2 also passed the same guest. The timed builds used the
same optimized Cargo profile on Apple Silicon. This benchmark exercises
four harts in supervisor mode. Complete Debian wall-clock boot qualification
remains open.

The guest and executable hashes, raw sampling traces, commands and
per-run results are in
`/Users/int/dev/rax-audit-work/four-findings-rv64-retirement-poll-2026-11-26/`.

## Exact retirement checkpoints

The software coordinator can end a turn at an automatic checkpoint count.
When the triggering instruction exits for I/O, the coordinator services the
exit before capture. An automatic file records the completed retirement count
and the cursor for the next CPU. A failed write leaves the trigger due. The
VMM retries a due write before another software CPU enters, including when
the triggering instruction powered off the VM.

| Claim | Probe | Observed result |
|---|---|---|
| A trigger can capture inside a turn. | Request retirement 79 in the Sv39 split-fetch handler without a UART yield. Remove the ELF before restoring in a new process. | The baseline captured at 106. The revised CLI saved `instret=79`, `sepc=0x40000ffe`, and `stval=0x40001000`. Both revised processes emitted one pass marker and exited with status 0. |
| Explicit and periodic triggers share a schedule. | Interleave unsorted explicit counts with a periodic trigger and a final x86 ACPI power-off. Read the files and inspect the program counters and retirement counts. | The files record retirements 2, 5, 7 and 10. |
| A failed write preserves the next-CPU cursor. | Fail a two-CPU guest's capture at 2, remove the obstruction and retry. Restore from the file and compare the peer's RAM writes and final retirement count. | The retry captured at 2. The peer wrote first in both runs, and the live and restored VMs finished with identical memory and retirement counts. |
| A stopped VM can retry its due capture. | Block the automatic write after the x86 guest powers off at retirement 3. Remove the obstruction, retry and restore from the resulting file with the same trigger. | The baseline returned without writing. The retry now captures the stopped state at 3. Later live and restored runs skip the already-consumed trigger. |
| MMIO completion remains the capture boundary for a non-stepping CPU. | Set an already-due capture count and issue an MMIO read-modify-write from either CPU. Also fail the completion callback. | The initial guard failed all three cases. With the software-only guard, successful completions saved the issuing CPU's registers and a failed completion produced no checkpoint. |

Commands, the input ELF, hashes and logs are under
`/Users/int/dev/rax-audit-work/four-findings-exact-checkpoint-2026-11-25/`.
The terminal retry logs are under
`/Users/int/dev/rax-audit-work/four-findings-terminal-retry-2026-11-25/`.

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

### Wall-clock firmware waits

The RV64 Sv39 firmware profile parks a hart after `WFI` under the wall clock.
It retires the instruction once and keeps the post-`WFI` PC. A locally
enabled interrupt resumes the hart even with global interrupt delivery
masked. The CLINT continues to use elapsed VM time while a hart waits. Plain
`Retired` mode and the generic wall-clock profile treat `WFI` as a hint.
`RetiredWithIdle` still advances its clock to the next timer when every
online hart waits.

The per-hart wait uses the existing `RAXRV007` profile flag. Restore checks
it against the recorded firmware profile and the saved clock mode before
publishing the coordinated CPU and platform state. A waiting or waking
step uses constant space and checks a fixed number of interrupt inputs.

In the baseline four-hart Linux run, the boot hart progressed from
`jump_label_swap` to `blake2s_compress_generic` between captures requested
at 30 s and 95 s. The three secondary harts were in the OpenSBI HSM wait
loop at both captures and accounted for 101,547,000 of 134,695,176 retired
instructions (75.4%) between them. Both the two-hart run and the sampled
four-hart run timed out at 240 s before producing any PID 1 affinity
markers. A revised four-hart run captured at approximately 135 s recorded
all three secondary harts parked immediately after the OpenSBI `WFI`,
with about 1.17 million retirements per secondary. The revised wall-clock
two- and four-hart runs both reached the 420 s host limit before PID 1
reported affinity. The full wall-clock Linux boot remains unqualified.
An 8 s host profile of a separate revised four-hart run recorded 1,041 of
2,892 main-thread samples in the coordinator's vCPU clock polling call.
[OpenSBI v1.8.1 HSM wait](https://github.com/riscv-software-src/opensbi/blob/v1.8.1/lib/sbi/sbi_hsm.c#L148-L178)
[RISC-V Machine-Level ISA, Wait for Interrupt](https://docs.riscv.org/reference/isa/priv/machine.html)

A two-hart guest scheduled one CLINT timer per hart, 2,000,000 ticks
(200 ms) after the current time, and entered `WFI` with global interrupt
delivery masked. The baseline RAX reached the guest's failure path
before expiry. The revised RAX and QEMU 11.1.2 reached the pass marker
and powered off. An automatic RAX capture at retirement 28 recorded
both harts waiting at `0x80000038`, their post-`WFI` PC. Restoring that
file in a new process without the input ELF or a machine override
produced the same pass marker and exit status. The adapter regression
also exercises wake from a locally enabled machine software interrupt.
Commands, the guest assembly and raw results are under
`/Users/int/dev/rax-audit-work/four-findings-rv64-wall-clock-2026-11-26/`.

### RV64 retirement batches

The coordinator gives a generic RV64 hart a bounded retirement batch.
The executing hart samples CLINT and PLIC inputs at every instruction.
The coordinator refreshes the entire online cohort at entry and when the
batch ends. An I/O exit or a zero-retirement trap still yields immediately.
An automatic checkpoint or retirement-counter wrap limits the batch
before entry, so the subsequent turn or file observes the same cursor,
retirement count and peer interrupt state.

For a turn of Q instructions on H online harts, clock sampling requires
O(Q + H) work and O(1) additional space. Two tests check that a peer's
timer is pending at retirement 300 before that peer executes, and that a
turn crossing count wrap stops at the first checkpoint in the new epoch.
The batched CLI also captured two machine timer waits at retirement 28.
The live guest and a fresh restore with the ELF removed both woke the
two harts on their timers and powered off.

The same RV64 ELF ran a fixed loop of 90,000,000 instructions on the
boot hart while its peers waited under the wall clock. Optimized RAX
executables on macOS Arm64 and QEMU 11.1.2 produced the pass marker and
powered off. In alternating runs, four-hart host elapsed time went from
27.67 s to 13.05 s (median of two measurements per build). One two-hart
pair took 29.23 s and 13.59 s. The timings describe this guest and host.
The two- and four-hart Debian wall-clock probes reached their 650 s and
750 s host limits before the PID 1 affinity markers. Linux reported RCU
stalls and, on four harts, two blocked tasks. Checkpoint memory verified
against the stored RAM digest contained Linux online CPU masks `0x3` and
`0xf`. A frame-pointer walk using the exact kernel's symbol addresses found
`riscv_timer_interrupt` in every saved hart's stack across two two-hart
captures and one four-hart capture. Three snapshots are insufficient to
measure interrupt occupancy or establish the cause of the stalls.
[Linux RCU stall detector documentation](https://docs.kernel.org/RCU/stallwarn.html)
[Linux v6.12 RISC-V stack walker](https://github.com/torvalds/linux/blob/v6.12/arch/riscv/kernel/stacktrace.c)

The optimized CLIs from before and after retirement-turn batching restored
the same two-hart `RetiredWithIdle` bundle at retirement zero. Both runs
reached PID 1, ran on each hart and powered off at guest time 0.366651 s.
Host elapsed time was 543 s before batching and 527 s after batching, with
one diagnostic capture per run. The runs overlapped, so host load can
affect the elapsed-time comparison. The capture from the batched
run showed both harts executing kernel cryptographic self-tests.

A separate wall-clock diagnostic appended only
`initcall_blacklist=jent_mod_init` to the two-hart guest. It reached its
420 s host limit and reported an X.509 load timeout. QEMU booted that
diagnostic guest through PID 1 and powered off. The wall-clock Linux boot
remains unqualified.

#### Timer publication at the end of a retirement budget

The RV64 adapter samples its platform inputs before every instruction in a
retirement budget. It publishes the executing hart's time and pending inputs
again at the return boundary, after charging the final retirement to the
clock. A completed batch of Q ordinary instructions on that hart uses Q+1
samples, with constant extra space. The coordinator still publishes peer
inputs before selecting the next hart.

| Assumption | Impact | Falsification probe |
| --- | --- | --- |
| The retirement timebase advances 300 instructions per CLINT tick (3 GHz / 10 MHz). | High | Arm hart 1 for tick 1. Require MTIP clear after 299 retirements, then retire `WFI` and require MTIP set on return. The parent returned with MTIP clear. |
| Batching preserves per-instruction interrupt sampling. | High | Run through the same deadline without `WFI`. Require interrupt entry before the 301st instruction, with the original instruction address in MEPC and exactly 300 total retirements. |

The regression checks the machine timer cause and vector in both paths.
With `dd4eb7b2a`, the default four-hart Debian wall-clock boot reached the
950 s host limit without a PID 1 affinity marker. The saved RAM and matching
kernel BTF yielded the following task and RCU state.

| Host elapsed time at checkpoint decode | `event_mutex` | PID 1 | RCU ticks on CPUs 0 through 3 |
| ---: | --- | --- | --- |
| 69.260 s | PID 40 on CPU 1, no waiters | Running on CPU 3 | 3,270 / 3,138 / 3,238 / 2,784 |
| 309.203 s | PID 40 on CPU 0, PIDs 1 and 38 waiting | Blocked in `init_kprobe_trace` | 57,242 / 56,925 / 56,534 / 55,660 |

Both captures had the same RCU sequence and a zero leaf quiescent-state
pending mask. The later console reported blocked tasks and a separate RCU
stall. The samples establish that each hart handled timer ticks and that
the scheduler migrated the mutex owner between captures. The cause of the
wall-clock boot timeout remains open. The console, supervisor result, RAM
digests and decoded task records are in
`/Users/int/dev/rax-audit-work/four-findings-rv64-timer-frontier-2026-11-26/`.

#### Linux timer counters at the recorded checkpoints

The saved RAM SHA-256 values were verified before reading the Linux IRQ
and high-resolution timer counters. The saved kernel's BTF matched the
boot image. The IRQ descriptor matched hardware cause 5, Linux IRQ 10,
and `riscv_timer_interrupt`. Linux's CPU-to-hart map identified the
counter owner, including the two-hart run that booted on hart 1.
[Linux v6.12.117 timer driver](https://raw.githubusercontent.com/gregkh/linux/v6.12.117/drivers/clocksource/timer-riscv.c)

| Saved run | High-resolution timer events | Deadline retries | Timer hangs | Longest recorded hang |
| --- | ---: | ---: | ---: | ---: |
| Two harts, wall, later capture | 93,738 | 1,687 | 61 | 41.0 ms |
| Four harts, wall | 160,928 | 164,269 | 17,591 | 176.9 ms |
| Two harts, retired, batched | 103 | 0 | 0 | None recorded |
| Four harts, wall, batched, `highres=off` | 0 | 0 | 0 | None recorded |

Counts sum the per-CPU values at capture. Linux records a timer hang
after three failed attempts to program the next deadline during one
handler. Over 83.814 s between the two wall-clock captures of the same
two-hart run, Linux jiffies advanced at 250 Hz and timer IRQ 10 arrived
at 219 and 217 per second on CPUs 0 and 1. The interval is the difference
in saved MTIME ticks divided by the guest's 10 MHz timebase. The
four-hart snapshot establishes repeated deadline misses. The snapshots
do not measure the share of execution spent in interrupt handlers or
establish the cause of the boot timeout.
[Linux v6.12.117 high-resolution timer handler](https://raw.githubusercontent.com/gregkh/linux/v6.12.117/kernel/time/hrtimer.c)

The four-hart `highres=off` control adds one kernel argument. The DTB is
the only changed ELF load segment. QEMU 11.1.2 reached all four affinity
markers and powered off. The archived turn-batched RAX build
(`eea2e5e65`) reached the 950 s host limit before any affinity marker.
At the 300 s checkpoint, Linux's online mask was `0xf`. The verified RAM
counters recorded 47,405, 48,851, 47,660 and 46,676 timer IRQs for CPUs
0 through 3. All four saved stacks included `riscv_timer_interrupt`.
Linux logged RCU stalls even with its high-resolution timer disabled.
The cause of the wall-clock boot timeout remains open.

The fixture, output, hashes and exact commands are in
`/Users/int/dev/rax-audit-work/four-findings-rv64-turn-batching-2026-11-26/`.

#### Linux task state at the recorded checkpoints

The task and mutex walk matched the saved RAM hashes and the kernel's BTF.
For each online CPU the run queue's current task matched the hart's saved
thread pointer. The frame walk used the saved `thread_struct` for blocked
tasks and checked the task and per-CPU IRQ stack bounds for current tasks.
[Linux v6.12.117 RISC-V stack unwinder](https://raw.githubusercontent.com/gregkh/linux/v6.12.117/arch/riscv/kernel/stacktrace.c),
[IRQ stack switch](https://raw.githubusercontent.com/gregkh/linux/v6.12.117/arch/riscv/kernel/entry.S)

| Saved run | PID 1 | `event_mutex` | RCU quiescent state pending |
| --- | --- | --- | --- |
| Four harts, wall, `highres=off`, 300 s | Blocked in `init_kprobe_trace` | Held by PID 40 on CPU 3, with PIDs 38 and 1 waiting | CPU 3 |
| Four harts, wall, high-resolution timers enabled | Running in `dnotify_init` | Unowned | None |
| Two harts, wall, high-resolution timers enabled | Running in `jent_memaccess` | Unowned | CPU 0 |
| Two harts, retired clock | Runnable during `ftrace_free_init_mem` | Unowned | CPU 1 |

In the 300 s capture, the outer timer interrupt interrupted PID 40 in
`strlen` under `trace_event_update_all`. Its nested timer interrupt
interrupted the scheduler's load-balancing softirq. The task waiting
ahead of PID 1 was in `event_trace_init`. RCU's saved sequence matched
the three console stalls for the same grace period (`g=-1159`).
These observations locate PID 1's wait in this capture. The other wall
captures identify different work in progress, and the cause of the
wall-clock boot timeout remains open.
[Linux trace-event update](https://github.com/gregkh/linux/blob/v6.12.117/kernel/trace/trace_events.c#L2978-L3028),
[mutex owner and waiters](https://raw.githubusercontent.com/gregkh/linux/v6.12.117/kernel/locking/mutex.c),
[RCU leaf state](https://raw.githubusercontent.com/gregkh/linux/v6.12.117/kernel/rcu/tree.h)

The reader, hashes and decoded task, IRQ-stack, mutex and RCU records
are in `/Users/int/dev/rax-audit-work/four-findings-rv64-task-stacks-2026-11-26/`.

#### Periodic-tick control at four harts

This control adds `nohz=off` to the four-hart `highres=off` guest. The
DTB is the only changed ELF load segment. QEMU 11.1.2 reached the four
affinity markers and powered off in 1.45 s. The `eea2e5e65` turn-batched
RAX binary reached the 950 s host limit before any affinity marker.
The saved RAM and kernel BTF identify the same mutex owner and waiters
at both checkpoint requests. The scheduler moved the owner between harts.

| Request | `event_mutex` | CPU timer IRQ totals (CPU 0 through CPU 3) | RCU quiescent state pending |
| ---: | --- | --- | --- |
| 150 s | PID 44 on CPU 1, with PIDs 39 and 1 waiting | 11,599 / 10,893 / 11,383 / 10,694 | None |
| 320 s | PID 44 on CPU 2, with PIDs 39 and 1 waiting | 18,961 / 21,353 / 22,006 / 22,547 | None |

All four harts were online at both captures. The difference in saved
MTIME was 1,698,561,730 ticks at 10 MHz, or 169.856 s. Linux jiffies
advanced by 30,861 and the high-resolution timer event, retry and hang
counters were zero on all four harts. RCU sequence -1156 was waiting
for a new grace period in both captures. PID 44 was interrupted in
`trace_event_update_all` at offsets `0x216` and `0x144`, respectively.
The periodic-tick control reproduced the timeout with no pending RCU
quiescent state at either saved point. The boot timeout's cause remains
unresolved.

The supervisor waited 20 s for the second checkpoint, which completed
47.25 s after the request. The second analysis uses a separately hashed
copy of that completed file. The guest, console, saved checkpoints and
decoded records are in the task-state evidence directory above.

#### Trace-format traversal during the periodic-tick control

The two saved `pt_regs` records place PID 44 inside the trace-format parser
in `trace_event_update_all`. The disassembly identifies `s10` as the
current `ftrace_events` list node and `s1` as its successor. The reader
checks the instruction that resolves the list head against the matched
kernel symbol and checks both directions of every saved list link. Both
checkpoints contained the same 1,305 node addresses in the same order.
[Linux v6.12.117 trace-event traversal](https://github.com/gregkh/linux/blob/v6.12.117/kernel/trace/trace_events.c#L2978-L3028)

| Checkpoint request | Current event index (zero-based) | Next event index | Current evaluation-map index |
| ---: | ---: | ---: | ---: |
| 150 s | 792 | 793 | 276 |
| 320 s | 796 | 797 | 232 |

PID 44 advanced four event-list entries in the observed interval while
PID 1 remained blocked on `event_mutex`. This measures progress in the
captured interval. The traversal alone cannot establish what limited that
progress or whether the full guest would eventually finish. Exact list
order, register values, disassembly and the reader are in
`periodic-trace-cursor.json` and its neighboring evidence files.

#### Trace evaluation initcall control

Adding `initcall_blacklist=trace_eval_init` to the four-hart periodic-tick
guest changed only the DTB boot arguments. The other four ELF load segments
matched by SHA-256. This option disables the trace evaluation worker and
leaves tracefs initialization in place.
[Linux v6.12.117 trace initialization](https://github.com/gregkh/linux/blob/v6.12.117/kernel/trace/trace.c#L9342-L9374)

| RAX checkpoint request | PID 1's saved kernel path | `event_mutex` |
| ---: | --- | --- |
| 150 s | CPU 3, allocating a slab while creating tracefs directories | PID 1 held it with no waiters |
| Approximately 610 s | CPU 2, validating kernel BTF during XFRM initialization | Unowned |

The checkpoint stacks came from the matching Debian kernel symbols and
saved RAM. All four harts remained online. Each hart's RCU timer tick
count advanced, and the leaf quiescent-state pending mask was zero at both
saved points. A later console message reported an RCU stall on CPU 2.
The run reached the 950 s limit with zero affinity markers. With the same
firmware, kernel, initrd and DTB, QEMU 11.1.2 reached all four affinity
markers and powered off in 1.44 s. Disabling trace evaluation changed where
the guest spent time. The wall-clock boot timeout remains open.
[Linux v6.12.117 XFRM BTF registration](https://github.com/gregkh/linux/blob/v6.12.117/net/xfrm/xfrm_state_bpf.c#L116-L125)

The guest inputs, console, checkpoint hashes and decoded tasks are in the
task-state evidence directory under `trace-init-disabled*`.

## Issued UART writes in checkpoints

The VMM retains an issued UART MMIO write at the head of the originating
hart's event queue until device dispatch succeeds. Under the platform and
serial locks, the write updates the UART and publishes its PLIC input. A
successful acknowledgement removes that one queue entry. Additional writes
from the same instruction remain queued in their original order.

`RAXRV008` identifies a hart record whose first queued event is an issued
UART write. It carries the same reservation and event payload as earlier
records. A full restore checks that the issuing hart is online and that the
bundle carries the coordinator, clock and physical RAM. Earlier tags still
decode with their original queued-event semantics. The VMM dispatches the
saved write before selecting a new hart, subject to a connected debugger's
resume mask. The dispatch leaves the retirement count at the saved value.
Finding the issued write takes O(H) checks for H harts. The queue
acknowledgement takes O(1) time.

The regression saves a VM after `SB` to UART IER retires, with a byte in the
receive FIFO and the UART interrupt disabled. It destroys the source VM and
removes the kernel file. The restored VM applies the write. At two and four
harts, the next hart reads `IIR=0x04` before the issuing hart executes again.
[TI TL16C550D data sheet, Table 5](https://www.ti.com/lit/ds/symlink/tl16c550d.pdf)

| Assumption | Probe |
| --- | --- |
| Capture occurs after retirement and before device dispatch. | Check retirement 3 and a low UART output at capture and immediately after restore. |
| The write belongs to the already-issued turn. | Check UART output after resume, and at two and four harts check the issuing hart's PC and retirement count alongside the peer's IIR result. |

The fixture prepares the peers directly and uses the retirement clock.

```sh
cargo +stable test --locked --no-default-features --lib riscv_file_replays_issued_uart_write_before_the_next_hart
```
