# Booting the iPod Touch 1G (S5L8900) iBoot on RAX

RAX can boot Apple's first-stage bootloader **iBoot** for the first-generation
iPod Touch / iPhone (Samsung S5L8900, ARM1176JZF-S, ARMv6K) on its software
emulator backend.

## Run

```sh
RAX_MACHINE=s5l8900 rax \
    --arch armv7a --backend emulator \
    --kernel docs/hardware/apple/iPodTouch1/iboot_204_n45ap.bin
```

`--kernel` points at the iBoot binary; the `bootrom_s5l8900` and
`nor_n45ap.bin` images are discovered as siblings in the same directory. The
machine is selected by the `RAX_MACHINE=s5l8900` environment variable (the
`armv7a` arch otherwise selects the Samsung SMDK6410/Linux machine).

## What boots

iBoot runs from reset through its full early-boot sequence:

- CPU/MMU/exception-vector setup, stack init for every processor mode
- Clock/PLL controller, system timer, PL192 VIC pair, GPIO, chip-ID
- I2C transactions with the PCF50633 PMU (reads PMU registers, enables the
  debug UART path)
- UART configuration (Samsung s3c/exynos-compatible)
- **SPI bus + LCD panel detection** (panel ID read over SPI1) and LCD
  controller setup; framebuffer clear (320×480 at physical `0x0fe00000`)
- **PMU/RTC reads, full peripheral init**, and a long sequence of timed
  device-bring-up delays
- Environment-variable initialisation (`config_board=n45ap`,
  `boot-command=fsboot`, `auto-boot=true`,
  `boot-path=/System/Library/Caches/com.apple.kernelcaches/kernelcache.s5l8900xrb`,
  …)
- Entry into its **bootdelay / recovery console wait**, polling the UART for a
  keypress

### Autoboot path (RAX_S5L_TIMER_IRQ=1, work in progress)

iBoot is a cooperative-scheduler firmware whose autoboot runs as a task woken by
the system-tick **timer interrupt**. With the timer IRQ enabled the scheduler
now runs continuously and handles ticks correctly; iBoot reaches its cooperative
scheduler's idle/event loop (timer-callback processing around `0x18005490`)
without crashing. The autoboot task then waits on a timer-based deadline (the
original "auto-boot vs recovery" decision) — getting it to dispatch `fsboot`'s
NAND read is the next step.

**The heap-corruption panic is fixed.** It was caused by a missing
exception-return path in `exec_pop` (see fix #4 below): the timer IRQ handler's
return (`LDMIA sp!, {r0-r3,r12,pc}^`, `e8fd900f`) is decoded as a `POP`, and
`exec_pop` restored PC but **not** CPSR/mode from SPSR. So the handler "returned"
still in IRQ mode with the wrong stack; a later `POP {pc}` then read garbage,
PC fell to `0`, the CPU re-ran iBoot's reset/startup, which re-initialised the
heap (`heap_add_chunk(0x18026000, …)` a second time) over the live env entries —
and the subsequent `setenv("config_board")` walked that now-freed list and
`free()`'d freed memory → `heap error: free : looping forever`.

Four correctness fixes found along the way:

- **Interworking returns.** `POP {pc}` / `LDM {pc}` / `LDR pc` are interworking
  branches on ARMv5+: bit0 of the loaded value selects ARM/Thumb. The executor
  only *set* Thumb and never *cleared* it, so a Thumb→ARM return stayed in Thumb
  and decoded the ARM return as garbage. Fixed in `exec_pop`, `exec_ldm_stm`,
  `exec_ldr` (shared AArch32 core; all 44k+ ARM tests + the Linux boot pass).
- **Vector-ready IRQ gate.** iBoot runs from `0x18000000` and maps virtual `0`
  to its in-place vector table only after early init. An IRQ delivered before
  that maps to physical `0x18` (zeros) and the CPU walks off into low memory.
  The step loop now only delivers an IRQ once the vector at the active base
  reads back the real `LDR pc, [pc, #0x18]` (`0xe59ff018`), replacing a fragile
  fixed-instruction-count readiness heuristic.
- **Deterministic timer.** `RAX_S5L_DET_TIMER=<insns-per-µs>` drives the µs
  counter from the instruction count instead of the host clock, so boots are
  fully reproducible (essential for chasing the heap bug; the host-clock timer
  made every run diverge).
- **`exec_pop` exception return (the heap-corruption root cause).** A privileged
  `LDM sp!, {…, pc}^` (S-bit set, e.g. `e8fd900f`) is decoded as a `POP`. The
  ARM `^` form must restore CPSR from the current mode's SPSR; `exec_pop`
  previously only did PC interworking, so an IRQ handler returned in IRQ mode.
  Fixed in `exec_pop` (shared AArch32 core), mirroring `exec_ldm_stm`. All 2254
  lib + 44330 ARM tests still pass and the heap panic is gone.

`RAX_S5L_FORCE_FSBOOT=1` (direct call into `do_fsboot`, bypassing the scheduler)
is **incompatible** with `RAX_S5L_TIMER_IRQ`: fsboot then runs in the main
context, so the timer IRQ's task context-switch has no valid current task to
save/restore and derails into the reset handler. Use one or the other.

Enable the scheduler path with `RAX_S5L_TIMER_IRQ=1 RAX_S5L_DET_TIMER=32
RAX_S5L_IRQ_READY=0`. It is off by default because the heap panic is not yet
resolved.

### Where it currently stops (default, no timer IRQ)

iBoot reaches its console input-wait and does **not** auto-boot to `fsboot`
(it never touches the NAND/ADM MMIO). The timer has been verified to advance
correctly from iBoot's view (a 64-bit µs clock read via an atomic
read-high/read-low/re-read sequence), so this is an **unconditional wait for
serial/USB input** (the interactive recovery/DFU console), not a stuck timed
delay. iBoot's serial *output* is gated off by `debug-uarts`/`debug-enabled`
(a production image), so it runs silently.

This iBoot image, loaded directly (bypassing the bootrom→LLB→iBoot chain),
drops to its console rather than auto-booting. Driving it further needs either
the USB DFU path or resolving the auto-boot/recovery decision, plus the flash
+ crypto stack below.

## Implementation

- `src/backend/emulator/s5l8900.rs` — the S5L8900 vCPU: memory bridge (v6 MMU +
  device routing), per-instruction step loop, IRQ delivery, host-clock µs timer.
- `src/devices/s5l8900.rs` — device models: clock, timer (µs counter + system
  -tick IRQ), PL192 VIC, SYSIC, GPIO, chip-ID, I2C + PCF50633 PMU, SPI
  controller, LCD panel, LCD controller, **NAND controller + ECC**, the
  **ADM (Apple Data Mover) NAND DMA** (serviced in the vCPU step, reads the
  `nand/` page dumps), and the **8900 AES crypto engine** (`S5lAes`, MMIO
  `0x38C00000`).
- `src/devices/crypto.rs` — self-contained AES (key schedule + CBC decrypt) and
  SHA-1, verified against NIST/FIPS-197 vectors; used by the AES engine to
  decrypt 8900/IMG2-wrapped boot images.
- `src/arch/arm.rs` (`load_s5l8900_firmware`) — firmware load layout (iBoot at
  `0x18000000`, bootrom at `0x20000000`, NOR at `0x24000000`) and the
  bootrom-call / 8900-engine patches the QEMU reference uses.

### Key fix: the timer

The S5L8900 timer is a free-running microsecond counter that firmware reads
with a "read counter, read again, retry if it changed" atomic sequence — which
assumes the timer is *slower* than the CPU. A naive per-instruction tick makes
consecutive reads always differ and hangs the guest. The timer is therefore
driven from a host monotonic clock (updated every 256 instructions, so it is
stable across the few-instruction read) with a configurable speedup
(`RAX_S5L_TIMER_SPEEDUP`, default 256) so multi-second firmware delays elapse
quickly.

### Debug aids (environment-gated)

- `RAX_S5L_TRACE=1` — log every executed instruction (pc/raw).
- `RAX_TRACE_PC=<hex,hex>` — dump registers when PC hits the listed addresses.
- `RAX_S5L_DERAIL=1` — dump recent PC history when execution falls into zeros.
- `RAX_S5L_DEVLOG=1` — log all device-register reads (with `RAX_S5L_OPENBUS_LOG`
  raising the budget).
- `RAX_S5L_STACKDUMP=1` — dump iBoot return addresses found on the stack.
- `RAX_S5L_FBDUMP=<path>` — dump the LCD framebuffer (BGRA).
- `RAX_S5L_MEMDUMP=<hexaddr>:<hexlen>:<path>` — dump an arbitrary phys region.
- `RAX_S5L_INPUT=<str>` — inject serial input into the UART once iBoot reaches
  its console wait.
- `RAX_S5L_TIMER_SPEEDUP=<n>` — guest-time speedup factor (host-clock timer).
- `RAX_S5L_DET_TIMER=<n>` — deterministic timer: derive µs from `insns / n`
  (default `n=32`) instead of the host clock, for reproducible boots.
- `RAX_S5L_WATCH=<hexaddr>:<hexlen>` — log every guest write into the range
  (catch heap/free-list corruption).
- `RAX_S5L_TRACE_BUDGET=<n>` / `RAX_S5L_TRACE_START=<insns>` — cap the number of
  `RAX_TRACE_PC` dumps and only start logging after a given instruction count
  (so a trace can target a late code path like the autoboot task).

## The heap-corruption blocker (root-cause analysis)

With the timer IRQ enabled the autoboot task reaches `fsboot`, which then panics
in `setenv("config_board", ...)`:

```
panic (heap_panic): heap error: free : looping forever
```

Traced deterministically (`RAX_S5L_DET_TIMER=32 RAX_S5L_IRQ_READY=0
RAX_S5L_TIMER_IRQ=1`; panic at a fixed ~12.79M instructions):

- The panic is iBoot's `free()` (`0x180077fc`) **heap-consistency check** at
  `0x18007840` (calls `heap_panic` at `0x18004b00`). It is *not* a loop counter
  despite the "looping forever" text.
- `setenv` walks the env list (head `0x180211a0`) via the unlink-and-free helper
  at `0x18007280`, and in one call frees **two adjacent `config_board` chunks**:
  `0x18026008` then `0x18026068`.
- These overlap the heap's **main free chunk at `0x18026000`** (size field
  `[0x1802600c] = 0x1abfe`, i.e. ~0xd5ff0 bytes spanning to `0x180fbff8`). The
  size field at `0x1802600c` is the main chunk's `+12` slot but `free()` reads it
  as chunk `0x18026008`'s `+4` slot (they alias 8 bytes apart). So node2
  (`0x18026070`) was allocated from the free pool **without the main free chunk
  being split** — the allocation and the free chunk overlap. `free()` then finds
  `prev(0x18026008) + size(0xd5ff0) = 0x180fbff8 ≠ 0x18026068` and panics.
- The mis-split is produced by the malloc split routine at `0x18007574`
  (conflicting size writes: `[0x1802606c] = 0x1abf2` then `0x2`, `[0x1802600c] =
  0xc`). It happens **before** ~12.7M instructions, so it is set up earlier and
  only surfaces when `setenv` frees the overlapping chunk.
- Crucially, the **default boot (no timer IRQ) never corrupts the heap** — so the
  bad allocation comes from the **scheduler / timer-event path** (task, timer and
  event structures allocated on the same heap) that only runs once the timer IRQ
  drives the cooperative scheduler. An IRQ-during-allocator guard
  (`0x18007000..0x18008000`) does *not* prevent it, so it is not a simple
  register clobber from an IRQ taken mid-malloc — it is a wrong value computed in
  the scheduler-context allocation path.

Verified *not* the cause: double-free of the same pointer (only two frees
occur), free-list bin-head corruption (bins stay clean), the LSL shift-carry used
by the coalesce flag tests (correct for n=30/31 — see `shift_c` in
`src/arm/execution.rs`).

**Next step:** pin the exact mis-emulated instruction by reference-diffing the
allocator/scheduler path against the QEMU port (`s5l8900-qemu.diff`)
instruction-by-instruction — the random AArch32 differential tests (44k passing)
don't cover whatever specific case this path exercises.

## Not yet modelled (remaining work to boot iOS)

The autoboot path (`RAX_S5L_TIMER_IRQ=1`) now reaches `fsboot` in the autoboot
task, in this order of remaining work:

1. **Fix the heap free-list corruption** that panics the autoboot task. It is a
   silent data corruption (no fault/undefined-instruction) in the
   scheduler/fsboot path reached only once the timer-IRQ-driven task runs —
   likely a subtly mis-emulated instruction or a scheduler context save/restore
   issue. This is the immediate blocker.
2. NAND read through to the kernelcache (the controller + ECC + ADM are
   implemented; once `fsboot` runs it should exercise them against the 521 MB
   `nand/` page dump).
3. **Done:** the **8900 AES engine** (`S5lAes`, MMIO `0x38C00000`) does real
   AES-128/192/256-CBC decryption with the UID / Custom / GID key selectors, and
   a **SHA-1** primitive is available for image verification. Both live in
   `src/devices/crypto.rs` and are verified against NIST/FIPS-197 vectors plus an
   MMIO register-protocol test. The GID key (needed for real LLB/iBoot/kernel
   images and absent from the QEMU reference) is supplied via `RAX_S5L_GID_KEY`
   (hex). Once `fsboot` runs, iBoot drives this engine to decrypt the
   kernelcache.
4. iBoot loading and jumping to the kernelcache, then **XNU kernel bring-up**
   (more devices the kernel drives directly).
5. USB OTG (Synopsys) is only needed for the DFU/restore path, not for booting
   an installed OS.
