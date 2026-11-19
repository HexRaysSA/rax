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
