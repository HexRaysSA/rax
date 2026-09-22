# S5L8900 iBoot Boot — Handover

**Goal:** boot Apple's iBoot for the 1st‑gen iPod Touch (Samsung S5L8900,
ARM1176JZF‑S / ARMv6K) on RAX's software emulator, all the way to loading +
jumping to the XNU kernelcache. This is the `RAX_MACHINE=s5l8900` machine.

```sh
RAX_MACHINE=s5l8900 RAX_S5L_DET_TIMER=1 \
  target/release/rax --arch armv7a --backend emulator \
  --kernel docs/hardware/apple/iPodTouch1/iboot_204_n45ap.bin
```
`--kernel` is iBoot; `bootrom_s5l8900` and `nor_n45ap.bin` are loaded as siblings.
The 521 MB NAND dump is in `docs/hardware/apple/iPodTouch1/nand/bankN/<page>.page`.

---

## ⭐ THE SINGLE MOST IMPORTANT FACT

**This boot is known‑achievable, and there is a complete working reference.**
The user pointed us to **devos50's QEMU iPod Touch port**:
- Blog: `devos50.github.io/blog/2022/ipod-touch-qemu/index.html` (+ `-pt2`)
  (both are checked out locally under `/Users/int/dev/rax/devos50.github.io/`).
- **The full QEMU source is `docs/hardware/apple/iPodTouch1/s5l8900-qemu.diff`.**

devos50 boots **this exact NAND dump** to the XNU kernel + Springboard. His console
log shows `VFL_Open [OK]`, `FTL_Open [OK]`, `HFSInitPartition`, `Reading 8900
header`, `Will decrypt 8900 image`, `Loading kernel cache at 0xb000000`.

**Implication:** the dump is sufficient, the FTL mounts, and the GID decryption is
handled (devos50 HOOKS the in‑ROM 8900 decrypt routine — it lives in the missing
fused bootrom at 0x22000000 — and decrypts in emulator logic with the known
S5L8900 GID key). Any remaining failure in RAX is a **device‑emulation gap vs
devos50**, NOT a data problem. **When stuck, diff RAX's device behavior against the
matching device in `s5l8900-qemu.diff`.** Earlier in the session I wrongly concluded
"impossible / missing metadata / missing key" — that was a dead end; ignore it.

---

## Current status

| Goal item | State |
|---|---|
| 1. fsboot runs (autoboot/recovery decision) | ✅ DONE — `do_fsboot` (0x18004300) and the fsboot dispatch (0x18004e8c) are reached in the default boot. |
| 2. NAND + ECC + (ADM) DMA reads OS images | ✅ Core DONE — iBoot reads NAND pages via PL080 DMA, byte‑perfect (verified). FTL not yet fully mounted. |
| 3. 8900 AES decrypt + SHA1 | ⏳ Implemented + unit‑tested, **not yet invoked in the live boot** (boot hasn't reached the kernelcache read). |
| 4. Load + jump to kernelcache, XNU bring‑up | ❌ Not reached yet. |

Regression baseline (keep green): `cargo test --release --lib` → **2254 pass**,
`cargo test --release --test arm` → **44330 pass**. All changes are confined to the
`s5l8900` backend; the Linux ARMv6 path is untouched.

---

## Fixes landed this session (all in `src/backend/emulator/s5l8900.rs` unless noted)

Each was found by tracing the live boot to its exact block, then matching the QEMU
reference. The repeating pattern: **iBoot initializes a device, then polls/blocks on
a completion bit or IRQ; wire that device's completion and the boot advances.**

1. **System‑tick IRQ on by default.** The timer IRQ drives iBoot's cooperative
   scheduler (wakes `task_sleep`). It self‑gates on the timer's `started` flag (set
   when iBoot arms TIMER_4 @0x3e2000a4), so it's safe on by default. `timer_irq =
   !RAX_S5L_NO_TIMER_IRQ`, interval 50000 insns. → got past the multitouch sleep.
2. **PL080 DMA controller (DMAC0 @0x38200000)** — new `S5lDmac` in
   `src/devices/s5l8900.rs`. Channel‑enable (Config bit0) triggers a synchronous
   transfer run by `BridgeInner::dma_run` (drains the NAND FIFO 0x38a00080 word‑wise
   into RAM, honours increment flags), sets terminal‑count + clears active, wired to
   VIC0 line 0x10. iBoot reads 2 KB pages (+64 B spare) this way.
3. **NAND_ECC IRQ** — `S5lNandEcc` already raised `irq` on START(0xC) but wasn't
   wired. NAND_ECC_IRQ=0x2B → VIC1 line 11. Added `vic1.set_line(NAND_ECC_VIC1_LINE,
   …)` in `sync_irqs`. → unblocked the post‑NAND‑read ECC poll → **fsboot runs**.
4. **ADM completion IRQ** — `service_adm` now sets `adm_irq` after a command and
   clears it on ack (CTRL2 bit1 clear); wired to VIC1 line 5 (ADM_IRQ=0x25).
   Correct per devos50, but NOTE: **iBoot does not drive the ADM in the current
   phase** (0 writes to 0x388xxxxx) — it reads NAND via direct FMC registers +
   PL080. So this is correct‑to‑have but isn't the current gate.
5. **USB OTG + USB PHY stub** — new `S5lUsb` in `src/devices/s5l8900.rs`, routed at
   0x38400000 (OTG) and 0x3c400000 (PHY). Registers are read‑back; **GRSTCTL (0x10)
   always reads `1<<31` (AHBIDLE set, all reset bits clear)** so the DWC soft‑reset
   poll completes; GNPTXFSTS (0x1C) returns 0xFFFFFFFF. → **unblocked USB init**
   (the boot was parked polling GRSTCTL bit31 at 0x1800c3be). devos50's blog notes
   USB OTG is "not essential to boot," so a minimal stub is enough.

---

## Where the boot is RIGHT NOW (the active frontier)

After the USB stub (fix #5), the USB‑init poll at **0x1800c3be** is no longer hit at
steady state — the boot advanced past it. **But it parks again at a new location
that has NOT yet been identified.** The next agent must find the new park point.

The boot sequence observed (with `RAX_S5L_DET_TIMER=1`):
fsboot decision → ~82 single‑page direct‑FMC + PL080 NAND reads (page 0,
DeviceInfo/BBT page 524160 across all 8 banks, then VFL‑scan blocks 34/40‑60 which
are erased — **this is normal**, devos50's FTL mounts despite these being erased) →
USB controller init (now passes) → **parks (new, unidentified)**.

> Important correction to earlier notes: the park is NOT because blocks 34‑60 are
> erased. devos50 reads the identical erased blocks and still mounts the FTL. The
> gate is always a device/IRQ/poll gap, found by tracing.

---

## The proven debugging methodology (use this)

1. **Find the park.** Run the boot; it settles into the scheduler idle (PCs in
   0x18018xxx = 64‑bit divide inside `get_time`, 0x18005xxx = scheduler, 0x18003xxx
   = timer). The parked task yielded from somewhere. Catch its yield point via a
   heartbeat whose `lr` is OUTSIDE the idle regions (that's how 0x1800c3c3 → the USB
   poll at 0x1800c3be was found). Or trace candidate poll PCs.
2. **Identify what it polls.** Disassemble the poll loop; read its literal pool to
   get the polled register address (Python: read u32 at `vaddr-0x18000000` from the
   iBoot binary). Map the address to a device via the base list below.
3. **Match the QEMU reference.** Find that device in `s5l8900-qemu.diff`, see what
   value/bit/IRQ it must produce, and replicate it minimally in RAX.
4. **Verify no regression** (`--lib` + `--test arm`) and that the default boot still
   reaches fsboot.

### Disassembler
```sh
target/release/examples/disasm docs/hardware/apple/iPodTouch1/iboot_204_n45ap.bin \
  0x18000000 <vaddr> <num_insns> thumb   # or 'arm'
```
iBoot is mostly **Thumb**. Watch for data/literal pools being mis‑decoded as code
(runs of 0x0000 / 0x3e20xxxx are usually register‑address tables).

---

## Device MMIO base addresses (S5L8900) — and what's implemented

Implemented & routed in `BridgeInner::dev_read`/`dev_write`:
CLOCK0 0x38100000 · CLOCK1 0x3C500000 · VIC0 0x38E00000 · VIC1 0x38E01000 ·
SYSIC 0x39A00000 · TIMER1 0x3E200000 · GPIO 0x3E400000 · CHIPID 0x3E500000 ·
UART0‑4 0x3CC00000/04000/08000/0C000/10000 · I2C0 0x3C600000 · I2C1 0x3C900000
(PMU) · SPI0 0x3C300000 · SPI1 0x3CE00000 · SPI2 0x3D200000 · LCD 0x38900000 ·
NAND/FMC 0x38A00000 · NAND_ECC 0x38F00000 · ADM 0x38800000 · DMAC0 0x38200000 ·
**USB_OTG 0x38400000** · **USB_PHY 0x3C400000** · AES 0x38C00000 · 8900 0x3F000000.

IRQ map (global → VIC): TIMER1=0x7, SPI0/1/2=0x9/0xA/0xB, LCD=0xD, DMAC0=0x10,
DMAC1=0x11, I2C0=0x15, I2C1=0x16, **ADM=0x25 (VIC1 line 5)**, **NAND_ECC=0x2B
(VIC1 line 11)**, GPIO groups G0=0x21…G6=0x00. VIC0 = lines 0‑31, VIC1 = 32‑63
(local line = global‑32), VIC1 daisy‑chains into VIC0.

Likely next devices to need attention (USB just done; watch for these in polls):
the rest of the **DWC USB OTG** register set (if iBoot does more USB), I2C/PMU
completion, GPIO‑group interrupts via SYSIC, or another DMAC/FMC completion.

---

## Key iBoot addresses (Thumb)

- `get_time` raw 64‑bit µs read: **0x18002ba8** (reads TICKSHIGH 0x3e200080 /
  TICKSLOW 0x3e200084).
- `get_time` wrapper (calls 64‑bit divide @0x18018xxx): **0x18005800**.
- "elapsed ≥ duration" predicate: **0x1800582c**; busy‑wait delay: **0x1800585c**.
- do_fsboot: **0x18004300**; fsboot dispatch (string‑match boot‑command=="fsboot"):
  **0x18004e8c**.
- enter/exit critical (IRQ nesting counter [task+24]): **0x18004ba0 / 0x18004bc4**.
- Timer IRQ source handler: **0x18002b48** (bumps tick, dispatches event channels
  4/5/6 via 0x18002af8).
- USB‑init poll that fix #5 cleared: **0x1800c3be** (polls GRSTCTL 0x38400010 bit31).
- FTL/VFL message strings (PC‑rel ADR refs, no abs pointers): VFL_Init 0x1801ebae,
  VFL_Open 0x1801ec3e, FTL_Open 0x1801ec7a. "debug-enabled" 0x1801c7e4.

## NAND geometry (from devos50's log, matches our constants)
8 banks · 4096 blocks/bank · **128 pages/block** · 524288 pages/bank · 2048 B/page ·
64 B spare · chip ID 0xA514D3AD. Page 524160 = block 4095 page 0 = the DeviceInfo/
BBT page ("DEVICEINFOBBT"). Kernelcache is an HFS+ file at
`/System/Library/Caches/com.apple.kernelcaches/kernelcache.s5l8900xrb`, loaded to
0x0b000000 and decrypted (3319392 bytes in devos50's run).

---

## Open problem: no console output (high‑value to solve)

devos50 has full iBoot console logs; **RAX does not** — iBoot only *initialises*
UART0 (writes ULCON/UCON=0x405/UFCON/baud, never UTXH 0x3cc00020). iBoot's debug
print is gated off (`debug-enabled`/`debug-uarts` in the NOR's binary syscfg).
Getting the console would make every remaining step trivial (you'd see exactly which
`[FTL:…]` step fails). Two avenues, neither finished:
- Patch the NOR syscfg to enable debug (binary kvstore format; `debug-enabled` entry
  at NOR file offset 0x10c0c, value field ~+0x20).
- Hook iBoot's `dprintf` at the emulator (its gate is likely *after* formatting, so
  capturing the r0 format‑string pointer at entry yields output even with debug off).
  `dprintf`/`putchar` not yet located — the UART literal at 0x1801f0d8 is in a device
  data table, not putchar's pool.

---

## Debug aids (env‑gated / RUST_LOG‑gated, zero cost when off)

- `RAX_S5L_DET_TIMER=1` — deterministic time (1 insn = 1 µs); use for reproducible,
  fast boots. `RAX_S5L_TIMER_MUL=N` multiplies µs (does NOT speed compute‑bound
  loops — the per‑page scan cost is `get_time` divide, insn‑bound).
- `RUST_LOG=rax::devices::s5l8900=debug,rax::backend::emulator::s5l8900=debug` —
  enables `dma_run`, `adm_cmd`, `nand page hit/MISS`, openbus/dev logs.
- `RAX_S5L_DMADUMP=/path` — append every DMA transfer (header + bytes) to a file
  (used to byte‑verify NAND reads vs the dump).
- `RAX_S5L_WLOG=1` — log all writes to UART0‑4 and ADM ranges.
- `RAX_TRACE_PC=0xAAA,0xBBB` + `RAX_S5L_TRACE_START=<insns>` + `RAX_S5L_TRACE_BUDGET=N`
  — log registers when PC hits the listed addresses (after START insns).
- `RAX_S5L_TRACE=1` (+ START/BUDGET) — consecutive instruction trace (pc/raw/lr/cpsr).
- Other: `RAX_S5L_WATCH=addr:len` (write watchpoint), `RAX_S5L_NO_TIMER_IRQ`,
  `RAX_S5L_GID_KEY=hex` (GID key for real image decrypt; not needed until item 3).

Heartbeat log: `RUST_LOG=…s5l8900=debug` prints `heartbeat insns=… pc=… lr=… cpsr=…`
every ~2 s — the cheapest way to see roughly where the boot is.

---

## Recommended next steps

1. **Find the new park point** (post‑USB). Run with det_timer + debug log; catch the
   parked task's yield `lr` (heartbeat `lr` outside 0x18018/0x18005/0x18003), or
   trace candidate poll PCs. Disassemble, read its literal pool, identify the polled
   device, and match `s5l8900-qemu.diff`.
2. **Strongly consider getting the console first** (see above) — it converts blind
   tracing into reading devos50‑style `[FTL:…]` progress directly.
3. Keep applying the wire‑the‑completion pattern toward: FTL mount (VFL_Open/
   FTL_Open) → HFS+ mount → read kernelcache → **8900 AES decrypt (item 3)** → jump
   (item 4) → XNU bring‑up (many more device drivers; the big multi‑session phase).
4. For item 3 end‑to‑end you'll need the in‑ROM decrypt hook (devos50 intercepts the
   jump to the missing bootrom decrypt routine and decrypts in emulator logic) plus
   the S5L8900 GID key. RAX already has a correct AES/SHA1 engine
   (`src/devices/crypto.rs`, `S5lAes`); wire it to whichever path iBoot actually
   uses.

## Key files
- `src/backend/emulator/s5l8900.rs` — vCPU, device routing, IRQ wiring, `dma_run`,
  `service_adm`, `step`.
- `src/devices/s5l8900.rs` — device models: `S5lTimer`, `S5lDmac`, `S5lUsb`,
  `S5lNand`, `S5lNandEcc`, `S5lAes`, `S5lSpi`, `S5lLcd`, `Pl192`, etc.
- `src/devices/crypto.rs` — AES‑128/192/256 + SHA‑1 (unit‑tested vs NIST/FIPS).
- `src/arch/arm.rs` — `load_s5l8900_firmware` (iBoot@0x18000000, bootrom@0x20000000,
  NOR@0x24000000).
- `docs/hardware/apple/iPodTouch1/s5l8900-qemu.diff` — **the reference port** (diff
  against it for every device).
- Memory: `~/.claude/projects/-Users-int-dev-rax/memory/s5l8900-ipod-touch-machine.md`
  (long history; the top "CORRECTION (2026‑06‑12, late)" section is the current truth;
  disregard the older "impossible/data‑insufficient" notes below it).
