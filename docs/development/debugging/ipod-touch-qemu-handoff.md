# RAX iPod Touch Boot Divergence Handoff

Date: 2026-06-14

## User Direction

Keep QEMU as the reference oracle. Avoid tunnel vision on a single RAX-side
hypothesis; every fix or trace should be compared to what QEMU actually does.

## Current Reference State

Reference checkout: `_ref/qemu-ipod-touch-1g`

Reference boot assets:

```sh
_ref/qemu-run/bootrom_s5l8900
_ref/qemu-run/iboot_204_n45ap.bin
_ref/qemu-run/nand
_ref/qemu-run/nor_n45ap.bin
```

Reference log: `/tmp/qemu-ipod-touch-vic-ref.log`

QEMU reaches the desired storage path:

```text
AppleS5L8900XADMFMC::start: Loading ADM/FMC firmware 'CalmADMFMCFirmware-17'
Unrecognized ADM command: 256
disk::attach(AppleS5L8900XADMFMC)
Registering: ../flash-controller0@A00000/AppleS5L8900XADMFMC/disk@FF
AppleNANDFTL::start: block device created, ready for work
IOGUIDPartitionScheme::start(unknown vendor unknown product Media) <1>
Registering: ../IOGUIDPartitionScheme/Untitled 1@1
BSD root: disk0s1, major 14, minor 1
```

The important QEMU VIC sequence at the first ADM firmware command is:

```text
qemu_vic op=ack value=0x80000025 raw=0x11002000 en=0x800c009f irq=0x0 addr=0x80000025 before_cur=33 before_high=32 before_prio=16 before_depth=0 after_cur=32 after_high=32 after_prio=15 after_depth=1 daisy=1
qemu_vic op=fin value=0x0 raw=0x20 en=0x183 irq=0x0 addr=0x80000025 before_cur=33 before_high=33 before_prio=33 before_depth=1 after_cur=33 after_high=33 after_prio=16 after_depth=0 daisy=0
qemu_vic op=fin value=0x0 raw=0x11002000 en=0x800c009f irq=0x0 addr=0x80000025 before_cur=32 before_high=33 before_prio=15 before_depth=1 after_cur=33 after_high=33 after_prio=16 after_depth=0 daisy=0
```

Interpretation: parent VIC0 acknowledges the daisy vector `0x80000025`,
then QEMU finishes/unmasks the child VIC1 service, then finishes/unmasks
the parent daisy service.

Relevant QEMU files:

```text
_ref/qemu-ipod-touch-1g/hw/intc/pl192.c
_ref/qemu-ipod-touch-1g/hw/arm/ipod_touch_adm.c
_ref/qemu-ipod-touch-1g/hw/arm/ipod_touch.c
_ref/qemu-ipod-touch-1g/include/hw/arm/ipod_touch.h
```

QEMU wiring:

```c
nms->vic1->daisy = nms->vic0;
#define S5L8900_ADM_IRQ 0x25
```

QEMU ADM behavior:

```c
ADM_CTRL read  -> 0x2
ADM_CTRL2 read -> 0x10
ADM_CTRL2 write 0x2 executes command and raises ADM IRQ
ADM_CTRL2 write without bit 1 lowers ADM IRQ
unknown command 0x100 still raises IRQ and prints "Unrecognized ADM command: 256"
```

## Current RAX Changes

Only product-code file intentionally touched for this work:

```text
src/backend/emulator/s5l8900.rs
```

Unrelated dirty files existed/appeared in the worktree; do not revert them
without user approval.

Current RAX changes are not yet an accepted fix. They are a partial ADM/VIC
behavioral experiment plus diagnostic tracing:

- Added `vic1_adm_daisy_latched` and `vic1_adm_daisy_in_service` to
  `BridgeInner`.
- `refresh_vic_daisy()` now keeps VIC0 daisy input asserted for a latched
  ADM completion and supplies VIC1 vector slot 5 (`0x80000025`) when VIC1
  itself is not asserting IRQ.
- VIC0 `VECTADDR` read marks the ADM daisy as in service when appropriate
  and calls `vic1.acknowledge_daisy_child()`.
- VIC0 `VECTADDR` write that finishes a daisy service calls
  `vic1.finish_daisy_child()` and clears the ADM latch/in-service flags.
- VIC1 `VECTADDR` write while ADM daisy is in service clears the ADM
  latch/in-service flags.
- `sync_irqs()` latches ADM on the rising raw edge of VIC1 line 5 and clears
  latch state when ADM deasserts.
- ADM completion clear (`ADM_CTRL2` write without bit 1) clears latch state
  and refreshes VIC daisy.
- Added diagnostic fields to `vic_trace`: `INTSELECT`, daisy input/address,
  `adm_irq`, `adm_latched`, `adm_in_service`.
- Added `RAX_S5L_VIC_TRACE_ADM`, but this needs tightening; it was too broad
  because `adm_irq` can remain true while unrelated soft IRQ traffic occurs.

Build status after these changes:

```text
cargo fmt -- src/backend/emulator/s5l8900.rs
cargo build --release
```

Both passed. The release build still emits the existing warning flood
(`rax` lib generated 341 warnings).

## RAX Runs And Observations

Main useful RAX log:

```text
/tmp/rax-ipod-after-adm-daisy-service.log
```

Command shape used:

```sh
timeout 900 env \
  RUST_LOG=rax::backend::emulator::s5l8900=info \
  RAX_MACHINE=s5l8900 \
  RAX_S5L_NAND=_ref/qemu-run/nand \
  RAX_S5L_LOGICAL0_PAGE=25856 \
  RAX_S5L_ADMFMC_TRACE=80 \
  RAX_S5L_ADM_DUMP=1 \
  RAX_S5L_ADM_PAGE_DUMP=96 \
  RAX_S5L_ADMIRQ_TRACE=160 \
  RAX_S5L_ADMIRQ_TRACE_START=752900000 \
  RAX_S5L_VIC_TRACE=160 \
  RAX_S5L_VIC_TRACE_START=752900000 \
  RAX_S5L_WMR_TRACE=120 \
  target/release/rax --arch armv7a --backend emulator --memory 128M \
    --kernel _ref/qemu-run/iboot_204_n45ap.bin \
  > /tmp/rax-ipod-after-adm-daisy-service.log 2>&1
```

This got RAX to the same ADMFMC firmware upload point as QEMU:

```text
AppleS5L8900XADMFMC::start: Loading ADM/FMC firmware 'CalmADMFMCFirmware-17'
kernel adm command dump cmd="0x100" ... pc="0xc049fc24" lr="0xc04a20c8"
adm completion raised cmd="0x100" ...
```

It also delivered the parent daisy vector:

```text
vic_trace ... VIC0 read offset="0xf00" result="0x80000025" ... after_cur=32 after_depth=1
vic_trace ... VIC1 ack_daisy ... before_raw="0x20" before_en="0x405a3" before_irq="0x20" ... after_cur=5 after_depth=1
```

But RAX diverged immediately after:

```text
vic_trace ... VIC1 write offset="0x14" value="0x20" ... after_en="0x40583" after_irq="0x0" after_cur=5 after_depth=1
panic(cpu 0 caller 0xC04A10A4): AppleS5L8900XADMFMC: ADM did not complete command (POST 0x50)
```

Compared to QEMU:

- QEMU: parent ack `0x80000025`, child `fin`, parent `fin`, then disk/FTL.
- RAX: parent ack `0x80000025`, child `INTENCLEAR 0x20`, no observed child
  `fin` before panic in that trace.
- RAX child VIC1 had `irq_status=0x20` because `INTENABLE` included bit 5.
- QEMU child VIC1 raw bit was also `0x20`, but `irq=0x0` in the printed child
  state. In the first command QEMU child `en=0x183`, so bit 5 was not enabled;
  later QEMU logs show child `en=0x405c3` but still `irq=0x0`, so inspect
  `INTSELECT` and write ordering before concluding.

Diagnostic reruns:

- `/tmp/rax-ipod-adm-focused-prepatch.log`: missed the ADM window because
  instruction count varied. It eventually reached the upload at a different
  count (`719955565`) than the prior run (`790974000`).
- `/tmp/rax-ipod-adm-triggered.log`: used continuous ADM IRQ state tracing and
  panicked earlier with a prefetch abort; not useful as a storage oracle.
- `/tmp/rax-ipod-adm-triggered-viconly.log`: attempted ADM-triggered VIC trace,
  but the trigger was too broad and flooded on repeated VIC0 soft interrupt
  writes while `adm_irq=true`. It did not produce the clean ADM `0x80000025`
  sequence before the run was stopped.

All active RAX boot processes were stopped after this handoff.

## Current Hypotheses

Keep validating against QEMU before patching.

Strongest current hypothesis:

RAX now gets the ADM completion into VIC0 as the correct daisy vector, but its
VIC1 child state around ADM differs from QEMU. In RAX, child line 5 becomes a
normal enabled IRQ (`irq_status=0x20`) and the driver writes `INTENCLEAR 0x20`;
the child priority stack remains masked (`depth=1`). QEMU sees the ADM raw bit
but prints child `irq=0x0`, and the service path produces child/parent `fin`
events and continues.

Possible root causes to test:

- RAX exposes ADM as a direct VIC1 IRQ when QEMU effectively treats it as a
  chained/daisy completion with no child `irq_status`.
- `INTSELECT` or enable ordering differs; QEMU may have ADM line routed/masked
  differently than RAX.
- RAX child priority stack needs to be unwound when the guest clears ADM
  `INTENCLEAR 0x20` while the ADM daisy service is in progress, but do not
  implement this until QEMU write-offset trace confirms the guest/QEMU path.

## Recommended Next Steps

1. Tighten RAX trace first.

   The current `RAX_S5L_VIC_TRACE_ADM` trigger should not trace merely because
   `adm_irq` is true. Prefer triggering only on:

   - VIC1 line 5 raw edge.
   - VIC0 daisy highest/current (`32`).
   - `vic1_adm_daisy_latched`.
   - `vic1_adm_daisy_in_service`.
   - MMIO access to VIC1 offsets `0x00`, `0x04`, `0x08`, `0x0c`, `0x10`,
     `0x14`, `0xf00` while VIC1 raw bit 5 is set.

2. Add QEMU write-offset trace behind `RAX_QEMU_TRACE_VIC`.

   Existing QEMU trace logs only `ack`/`fin`. Add env-gated logging in
   `_ref/qemu-ipod-touch-1g/hw/intc/pl192.c::pl192_write()` with controller
   name, offset, value, raw/en/intselect/irq/fiq/current/high/depth before and
   after. Keep this in `_ref/` only or behind the env flag.

3. Re-run QEMU reference with that trace and record exactly whether the guest
   writes VIC1 `INTENCLEAR 0x20`, VIC1 `VECTADDR`, or both after ADM command
   `0x100`.

4. Only after QEMU confirms write ordering, make the smallest RAX behavior fix.

   Candidate if QEMU and RAX guest writes differ only because RAX exposes child
   `irq_status=0x20`: adjust ADM/VIC1 exposure so ADM completion matches QEMU
   child state (`raw=0x20`, `irq=0x0`) while still raising parent daisy.

   Candidate if QEMU shows equivalent child clear/finish semantics: treat VIC1
   `INTENCLEAR 0x20` while `vic1_adm_daisy_in_service` as the child service
   finish/lower event, then let the parent finish path proceed normally.

5. Acceptance remains QEMU-derived:

```text
AppleNANDFTL::start: block device created, ready for work
IOGUIDPartitionScheme::start(unknown vendor unknown product Media)
Registering: ../IOGUIDPartitionScheme/Untitled 1@1
BSD root: disk0s1
```

Do not rely on these as final fixes:

```text
RAX_S5L_REWRITE_PMBR_AS_FDISK
RAX_S5L_GUID_PROBE_SCORE
forced IOBSD hacks
```

`RAX_S5L_LOGICAL0_PAGE=25856` is still part of the current RAX harness.
