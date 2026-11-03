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

All original audit findings remain partially validated. This group does not
qualify other backend/controller profiles, full input replay, or physical Intel
Hypervisor.framework execution. The preceding group's independent CI failures
remain separately recorded in `../riscv-vmm-startup/qualification.json`.
