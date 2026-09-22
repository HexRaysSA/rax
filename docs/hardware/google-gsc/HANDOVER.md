# Google Security Chip (GSC) firmware on RAX — Handover

Status as of this handover: **Ti50 boots through init, ticks live, and processes
real host TPM 2.0 commands end-to-end.** Earlier milestones still hold (RISC-V +
Xsoteria core, reset-source reporting, console, GLOBALSEC windows, cryptolib
discovery, AP SPI host status/fast-read, flash read/program/erase, AP RO → `OK`).
Three things changed this session and are the headline result:

1. **Time advances.** The `0x400C0000` 64-bit free-running counter
   (`+0x14`/`+0x1C`) is now driven from retired instructions, so the firmware's
   `[ N.NNN]` log timestamps progress instead of being frozen at `[ 0.000]`.
   This alone unblocked the software alarm poll in `has_pending_interrupts`
   (`sub_9F9D8`): the scheduler now wakes and the firmware prints
   `service_pending_interrupts took … ms`. A 64-bit alarm compare
   (`+0x2C`/`+0x34`) plus `mip.MTIP` is also modeled for the machine-timer ISR.
2. **AP power / PLT_RST_L.** `RAX_GSC_AP_ON=1` deasserts `PLT_RST_L` (GPIO bank0
   `0x40520000` **bit 11**, found by runtime bisection) so the firmware reports
   `PLT_RST_L DEASSERTED` and treats the AP host as powered on. Without this the
   TPM task drops every command `"while AP off"`.
3. **TPM 2.0 command processing (the goal).** `RAX_GSC_TPM_CMD=<hexbytes>`
   injects one or more host TPM commands. In the default `yield` mode the
   emulator plants the command into the firmware TPM task's own globals at its
   command-wait `ecall` (`0xd3cca`), so the command runs through the real
   `ExecuteCommand` path (`sub_E06BE`/`sub_E07A0`) **in proper scheduler
   context**, and the response is captured at the send boundary (`sub_D4B80`).
   Verified end-to-end with `RAX_GSC_AP_ON=1`:
   - `TPM2_Startup(CLEAR)` → `80 01 0000000A 00000000` (TPM_RC_SUCCESS)
   - `TPM2_GetRandom(8)` → 8-byte success response (now non-zero entropy, see §4k)
   - a malformed `TPM2_SelfTest` → `rc=0x000001C4` = TPM_RC_VALUE on parameter 1
     (the firmware correctly validates and rejects the bad parameter).

Follow-up session added the three realism pieces that were previously TODO:

4. **Real entropy (§4k).** The TPM RNG (`sub_D5558` CryptRandomGenerate,
   `sub_D5606` nonces) delegates to a kernel crypto service over `ecall` that
   writes zeros in this board model. Those two functions are now hooked to fill
   their output buffer with a PRNG, so `TPM2_GetRandom`, nonces, and generated
   keys are non-zero (e.g. GetRandom(16) → `…0010 839ea371f91958029a9181409a37b3b9`).
5. **Runtime PLT_RST eventing (§4l).** `RAX_GSC_PLT_RST_EVENT=1` boots with the
   AP held in reset, then at runtime deasserts `PLT_RST_L` and warm-resets so the
   firmware re-boots AP-on — mirroring real `Rebooting GSC for AP RO due to
   state`. After it, TPM commands process (vs. dropped "while AP off").
6. **Wired transport (§4m).** `RAX_GSC_TPM_WIRED=1` stages the TPM frame in the
   **real GscFifo dual-port RAM window `0x40621000`** instead of scratch RAM, so
   the firmware reads the command from and writes the response to the actual
   host-interface MMIO. The firmware's SPS receive-ISR (FIFO→`0x220C0` copy +
   task wake) and the response-send both live behind RO kernel drivers (1004),
   so the *wake* step is still bridged at the task yield; everything else is the
   firmware's real path.

These are still host *command injection/bridging* at the interrupt-wake boundary
(the SPS/GPIO interrupt routing is in the RO image), not a fully autonomous SPI
bus. This document captures the state needed to resume without re-deriving it.

---

## 1. What this is

Goal: run Google Security Chip firmware inside RAX's software RISC-V emulator.

Two target images (NOT in the repo — proprietary):
| file | chip | size | arch | notes |
|---|---|---|---|---|
| `/Users/int/Downloads/fw.bin` | Dauntless / "nugget" | 0x3f800 (260 KB) | RV32IMC + Xsoteria | single RW slot; `nugget_v0.0.ab14367875 … 2025-10-31` |
| `/Users/int/Downloads/ti50.bin.prod` | Ti50 (production) | 0x100000 (1 MB) | RV32IMC + Xsoteria | A/B dual-bank flash; **Tock OS / libtock-rs**, `prepvt-15974.B`, `2026-01-30` |

GSC = the RISC-V generation (Dauntless/Ti50, "Soteria" SoC), successor to the
ARM Cortex-M3 Cr50/Haven. The reference Python emulator `gscemu-main` (at
`/Users/int/Downloads/gscemu-main`) emulates the *older* Cr50 on Unicorn — its
peripheral **behaviour** and register **semantics** transfer, but the Ti50
register **offsets are rearranged**. The IDA RISC-V procmod
(`/Users/int/hexrays/ida/module/riscv`) decodes the Xsoteria extension.

---

## 2. How to run / reproduce

```bash
cd /Users/int/dev/rax
cargo build

# ti50.bin.prod (flash image base defaults to 0x80000)
RAX_MACHINE=gsc target/debug/rax --arch riscv64 --backend emulator \
    --kernel /Users/int/Downloads/ti50.bin.prod --memory 256M

# ti50.bin.prod high-water mark with narrow AP RO data/digest stubs.
# /tmp/rax-ap-fmap11-gbb-gvd.bin is the current synthetic AP flash probe image.
RAX_MACHINE=gsc RAX_GSC_AP_RO_INFO_STUB=1 RAX_GSC_AP_RO_CRYPTO_STUB=1 \
    RAX_GSC_AP_FLASH=/tmp/rax-ap-fmap11-gbb-gvd.bin \
    target/debug/rax --arch riscv64 --backend emulator \
    --kernel /Users/int/Downloads/ti50.bin.prod --memory 256M

# *** TPM 2.0 command processing *** (the headline result).
# AP_ON deasserts PLT_RST_L so the firmware accepts host commands; TPM_CMD
# injects them (comma-separated). Prints a valid TPM response per command.
# Below: TPM2_Startup(CLEAR) then TPM2_GetRandom(8). Expect
#   TPM resp #1 ... rc=0x00000000 (SUCCESS) bytes=80010000000a00000000
#   TPM resp #2 ... rc=0x00000000 (SUCCESS) bytes=8001000000140000000000080000000000000000
RAX_MACHINE=gsc RAX_GSC_AP_ON=1 RAX_GSC_AP_RO_INFO_STUB=1 \
    RAX_GSC_AP_RO_CRYPTO_STUB=1 RAX_GSC_AP_FLASH=/tmp/rax-ap-fmap11-gbb-gvd.bin \
    RAX_GSC_TPM_CMD="80010000000c000001440000,80010000000c0000017b0008" \
    target/debug/rax --arch riscv64 --backend emulator \
    --kernel /Users/int/Downloads/ti50.bin.prod --memory 256M

# Everything: runtime AP power-on (PLT_RST event + warm reset) + wired GscFifo
# transport + real entropy. Boots AP-off, reboots AP-on, then runs the commands
# through the 0x40621000 FIFO window; GetRandom returns non-zero bytes.
RAX_MACHINE=gsc RAX_GSC_PLT_RST_EVENT=1 RAX_GSC_TPM_WIRED=1 \
    RAX_GSC_AP_RO_INFO_STUB=1 RAX_GSC_AP_RO_CRYPTO_STUB=1 \
    RAX_GSC_AP_FLASH=/tmp/rax-ap-fmap11-gbb-gvd.bin \
    RAX_GSC_TPM_CMD="80010000000c000001440000,80010000000c0000017b0010" \
    target/debug/rax --arch riscv64 --backend emulator \
    --kernel /Users/int/Downloads/ti50.bin.prod --memory 256M

# Broader standalone fallback: forces the kernel AP RO verifier return.
RAX_MACHINE=gsc RAX_GSC_AP_RO_STUB=1 target/debug/rax --arch riscv64 \
    --backend emulator --kernel /Users/int/Downloads/ti50.bin.prod --memory 256M

# Optional: back external AP SPI fast-read (opcode 0x0b) with an AP flash image.
# Missing bytes still read as erased flash (0xff).
RAX_MACHINE=gsc RAX_GSC_AP_FLASH=/path/to/ap_flash.bin target/debug/rax \
    --arch riscv64 --backend emulator \
    --kernel /Users/int/Downloads/ti50.bin.prod --memory 256M

# fw.bin (loads at 0xa0000 — must override the flash image base)
RAX_MACHINE=gsc RAX_GSC_FLASH_BASE=a0000 target/debug/rax --arch riscv64 \
    --backend emulator --kernel /Users/int/Downloads/fw.bin --memory 256M
```

`--arch riscv64` is mandatory (raw image can't be auto-detected). `--memory`
must be ≥128 MiB (validator) and large enough to cover the flash image; 256M is
fine. The machine internally runs **RV32** (`RiscVConfig::rv32(Isa::ti50())`).

If a regression sends the firmware back into a reboot loop, the loop guard stops
after 32 warm resets with `gsc: firmware reboot loop (N resets)`.

### Expected console output (ti50, narrow AP RO path)
```
[ 0.000] Starting D2C1 RO 0.0.62 RW 0.24.250
[ 0.000] ti50_common_prepvt-15974.B:v0.0.711-3fd7dded libtock-rs:v0.0.925-1213708 ...
[ 0.000] Strap config: LLLL => TPM Bus: SPI; FormFactor: Tablet
[ 0.000] Reset Type: Cold
[ 0.000] Reset cause: POR 0x00000001     <- RSTSRC model working
[ 0.000] USB: Off
[ 0.000] CCD_MODE:      asserted
[ 0.000] USB: On
[ 0.000] RBOX: WP true
[ 0.000] RBOX: assert EC_RST_L
[ 0.000] cryptolib v1 at 0x800
[ 0.000]
[ 0.000] RBOX: assert EC_RST_L
[ 0.000] AP WP SR OK!
[ 0.000] locating gvd to verify
[ 0.000] gscvd @00001000 consistent
[ 0.000] gscvd OK
[ 0.000] validating 1 ranges in AP flash
[ 0.000] caching gvd info
[ 0.000] AP RO: OK
[ 0.000] AP RO verifications took 0 ms.
[ 0.000] TPM SPI initialized
[ 0.000] 0 files found across 0 pages.
[ 0.000] 2048 bytes of data.
[ 0.000] 0 invalid and 10 free pages.
[ 0.000] 0 erases since boot.
[ 0.000] Partition |   File ID   | Bank | Page | Size
[ 0.000] 0 bytes free in active pages.
[ 0.000] Filesystem init took 0 ms.
[ 0.000] PLT_RST_L ASSERTED
[ 0.000] TPM SPI disabled (CS=true)
```
After this, a breakpoint at `RAX_GSC_BREAK=a2d3c` confirms scheduler idle:
`ra=0xa2d3c sp=0x13cb0 ...`, with stack strings such as
`"Abort sleep: plt_rst_l , ccd_mode_l , usb active"` and
`"service_pending_interrupts took "`.
The log is the **acroterm** tokenized format; `$` are arg placeholders. Decoding
it fully needs `acroterm.json` (referenced in the image header: a build path
`…/nugget/acroterm.json`), which we don't have.

---

## 3. What's implemented (rax source)

All on branch `gsc`. Not committed (commit when ready).

| file | what |
|---|---|
| `src/riscv/mod.rs` | `Isa.xsoteria` flag; `Isa::ti50()` profile (RV32 IMC+Zicsr+Zbb+Xsoteria) |
| `src/riscv/decode.rs` | `decode_xsoteria_custom0/1` (opcodes 0x0b/0x2b), 8 new `Op` variants |
| `src/riscv/cpu.rs` | xsoteria execute arms; `grev32`/`fls32` helpers; permissive vendor/PMP **CSR scratch** (`ext_csr`, gated on `isa.xsoteria` so RV64GC stays strict); `RiscVCpu::reset()`; `disasm_pc()` |
| `src/riscv/disasm.rs` | mnemonics + operand classes for the 8 ops |
| `src/backend/emulator/gsc.rs` | **the GSC machine** — `GscVcpu` + `GscBridge` (everything below), core-local IRQ model, UART RX wake, the `0x400C0000` free-running timer + MTIP alarm compare (`time_cell`, `timer_compare`), the `RAX_GSC_AP_ON` PLT_RST_L deassert, and the TPM command injection (`yield`/`call` modes: `plant_tpm_command`/`capture_tpm_response`/`begin_tpm_call`) |
| `src/backend/emulator/mod.rs` | `create_vcpu`: `ArchKind::Riscv64` + `RAX_MACHINE=gsc` → `GscVcpu` |
| `src/arch/riscv.rs` | `load_gsc` (SignedHeader loader, single- & multi-slot), `select_gsc_entry`, `rd_u32`, `env_hex` |
| `src/smir/lift/riscv.rs` | `xsoteria: false` in `decoder_isa` (oracle path doesn't lift it) |

Focused verification for this state:
- `cargo test gsc --lib`
- `cargo test ap_ro_crypto_stub --lib`
- `cargo test machine_interrupt_ --lib`
- `cargo test system_ecall_ebreak_fence --lib`
- `cargo build`
- bounded Ti50 run with
  `RAX_GSC_AP_RO_INFO_STUB=1 RAX_GSC_AP_RO_CRYPTO_STUB=1
  RAX_GSC_AP_FLASH=/tmp/rax-ap-fmap11-gbb-gvd.bin
  RAX_GSC_BREAK=a2d3c RAX_GSC_BREAK_STOP=1`, reaching scheduler idle

Relevant tests cover xsoteria decode/execute, CSR scratch, warm reset, loader
single/multi-slot, synthetic RV32+pcnt+UART console, PMU RSTSRC, chip ID,
GLOBALSEC windows, synthetic cryptolib, USB status, flash DOUT lanes, INFO flash
separation, RBOX, GSC FIFO, AP SPI status, AP RO cached INFO behavior, and the
AP RO crypto digest hooks.

### `GscBridge` models (in `src/backend/emulator/gsc.rs`)
- **Console UART** at `0x404d0000`: RDATA `+0x00`, WDATA `+0x04` → stdout +
  capture, STATE `+0x14`. TX is ready when bit0 is clear; RX data is available
  when bit7 is clear. `RAX_GSC_UART_RX` seeds an initial RX byte queue. The
  queue is hidden until the firmware reaches WFI; after that, source 0 in the
  core-local interrupt controller asserts MEIP and STATE reports RX available.
  Runtime proof: the external vector `0x9552c` fires with
  `mcause=0x8000000b`, `mip=0x800`, but the Tock UART RX client descriptor at
  `0x1eac0+4` is zero, so the handler skips the RDATA path and no shell input
  is consumed.
- **Core-local interrupt controller** at `0xe000e000`: firmware writes
  `+0x2c`, loops on `+0xd8`, and reads claim/source at `+0xd0`. Current model
  returns `0x80000000` for no pending interrupt and source `0` for armed UART RX.
  The RISC-V core now honors `mie/mip/mstatus.MIE`, vectored `mtvec`, and takes
  machine external/software/timer interrupts before fetching the next
  instruction.
- **PMU reset block**: RSTSRC `+0x00` (cold=POR / warm=SOFTWARE|EXIT), CLRRST
  `+0x04` (write-1-clear), GLOBAL_RESET `+0x08` (key `0x07041776` → warm reset).
- **Persistent register store**: all MMIO writes read back and **survive a warm
  reset** (PMU boot-counter/init-flags stay sticky).
- **Flash controller** `0x40110000`: PE_CONTROL0/1 `+0x04/+0x08`,
  READ_TRANS `+0x0c`, TRANS `+0x10`, STATUS0/1 `+0x18/+0x1c`, DOUT0
  `+0x60/+0x64`, DOUT1 `+0x6c/+0x70`, WR_DATA `+0x78/+0x7c`, PE_EN `+0x8c`
  magic `0xB11924E1`, ERROR `+0x9c`. READ fills DOUT; PROGRAM/ERASE update the
  XIP image or the separate INFO-bank store. INFO defaults to blank
  `0xffffffff`, which is required for tickv/filesystem init to classify pages
  correctly.
- **GPIO/sleep block**: `0x4003046c..0x40030488` are modeled as GPIO
  configuration / interrupt-state words. `0x40030484` and `0x40030488` are
  write-one-clear. GPIO input bank sample words at `0x40520000`,
  `0x40520034`, `0x40520068`, and `0x4052009c` default low and can be
  overridden through the ready/store path without relying on the spin-breaker.
- **RBOX** at `0x40090000`: static dump proves the control/status handshakes at
  `+0x44/+0x48/+0x54`; the W1C interrupt/status groups
  `+0x04/+0x0c/+0x10`, `+0x18/+0x20/+0x24`, `+0x2c/+0x34/+0x38`, init-ready
  `+0x58`, and command/status `+0xa0/+0xa4` are runtime/undecompiled-gap
  evidence. This model removes the old RBOX init failure.
- **AP SPI host** at `0x40600000`: control `+0x00`, transaction/start/busy
  `+0x04`, transfer config `+0x08`, W1C/status groups `+0x14/+0x1c/+0x20`,
  byte-addressed TX/RX window `+0x1000`. Ti50 uses this to read external AP
  flash status registers and AP flash bytes. Status opcodes `0x05/0x35/0x15`
  return SR1=`0x02`, SR2=`0x00`, SR3=`0x00`; opcode `0x0b` fast-read is backed
  by `RAX_GSC_AP_FLASH` and defaults to erased `0xff` bytes when no image is
  supplied. The RX payload base is `+0x1000 + align4(tx_len) + tx_len`, so
  status payloads land at `+0x1005` and fast-read payloads at `+0x100d`.
  `RAX_GSC_AP_RO_INFO_STUB=1` only synthesizes the cached AP RO INFO record;
  `RAX_GSC_AP_RO_CRYPTO_STUB=1` only fills the missing digest results. The
  broader `RAX_GSC_AP_RO_STUB=1` still forces the final verifier return.
- **GSC FIFO / TPM-SPI FIFO** at `0x40620000`: control `+0x10` clears reset-busy
  bits `0x9` on read, W1C IRQ/status group `+0x590/+0x598/+0x59c`, status
  `+0x5a0`. This removes the old `TPM SPI couldn't reset fifo` line.
- **Generic spin-breaker**: an unmodeled register polled `SPIN_THRESHOLD` (4096)
  times with no intervening write returns all-ones / zeros (alternating) to
  break "wait for status bit" loops.
- **Built-in ready map** + warm-reset + reboot-loop guard.

---

## 4. Reverse-engineering reference

### 4a. Xsoteria custom RISC-V extension (SOLVED, implemented, tested)
RV32-only, 2 custom opcodes. Verified byte-exact against the ti50-sdk LLVM-15
soteria patch (`github.com/naverwhale/whaleos-chromiumos-overlay …
ti50-sdk/files/llvm15-23112022-soteria.patch`).

| mnemonic | opcode | f3 / f7 | semantics |
|---|---|---|---|
| `grevi` | 0x0b | 000/0x00 | GREV32(rs1, imm5) — generalized bit-reverse |
| `bitci` | 0x0b | 001/0x00 | `rs1 & ~(1<<imm5)` |
| `bitsi` | 0x0b | 001/0x20 | `rs1 | (1<<imm5)` |
| `fls`   | 0x0b | 010/0x00, rs2=0 | `32 - clz` (1-based MSB index; fls(0)=0) |
| `clz`   | 0x0b | 010/0x20, rs2=0 | count-leading-zeros (reuses Zbb `Clz`) |
| `pcnt`  | 0x0b | 011/0x00, rs2=0 | popcount |
| `grev`  | 0x2b | 000/0x00 | GREV32(rs1, rs2&31) |
| `bitc`  | 0x2b | 001/0x00 | `rs1 & ~(1<<(rs2&31))` |
| `bits`  | 0x2b | 001/0x20 | `rs1 | (1<<(rs2&31))` |

Fields: `funct7=w[31:25]`, `imm5/rs2=w[24:20]`, `rs1=w[19:15]`, `funct3=w[14:12]`,
`rd=w[11:7]`. `grev32` = standard 5-stage butterfly (ctrl masked to 5 bits;
`grev(x,24)`=rev8). Custom CSRs: `0x7c0-0x7cf` = `mgpscratch0..15`, `0x7d0` =
`mnmivec` (NMI/fault vector). The image also has CFI CSRs `0x800-0x80f`, `mx0`
`0xbc0`, etc. — all handled as permissive store-only scratch when
`isa.xsoteria`.

### 4b. Image load / memory map
- **fw.bin**: `VA = file + 0xa0000`. SignedHeader at file 0; magic `0xFFFFFFFD`;
  `ro_base@0x32c=0xa0000`; entry `@0x404=0xa043c`; `mtvec@0x408=0xa05b1`. Single
  self-contained slot (`image_size@0x328 == file size`).
- **ti50.bin.prod**: `VA = file + 0x80000`. Whole 1 MB XIP-mapped at 0x80000.
  4 slots (RO_A@0x0, RW_A@0x15000, RO_B@0x80000, RW_B@0x95000). Run **RW_A**:
  entry `0x956b2` (file 0x156b2), mtvec `0x95582`. The loader (`select_gsc_entry`)
  picks the first RW-sized slot (image_size ≥ 0x30000).
- SRAM at `~0x10000` (sp/gp/.bss live there). MMIO aperture `0x40000000+`,
  intercepted by the bridge.
- Code is **plaintext RV32IMC** — no decryption. RSA-2048 sig/key in the header
  are verification-only and skipped.

### 4c. MMIO peripheral map (Ti50) — runtime + cross-referenced from gscemu
| base | peripheral | key registers / notes |
|---|---|---|
| `0x40000000` | **PMU** (128 KB) | RSTSRC+0x00, CLRRST+0x04, GLOBAL_RESET+0x08 (key 0x07041776), EXITPD/scratch +0x4c, scratch +0xa0/+0xb0, boot/RO-update status @0x1FFE4. `0x4001ffe0`/`0x4001fff8` chip-ID claims are absent from `ti50.bin.prod`. |
| `0x40030000` | GPIO/pad + interrupt/event bits | sleep setup uses +0x46c/+0x470, GPIO config +0x46c..+0x480, pending-clear +0x484/+0x488. The older +0x490 status claim has no static evidence in this dump. |
| `0x40040000` | unresolved (pinmux/GPIO/strap?) | runtime-only |
| `0x400a0000` | RTC / wakeup sequencer | runtime trace touches this page heavily; Cr50 `hw_regdefs.h` names the same base as `GC_RTC0_BASE_ADDR` with CTRL/PINMUX/PULSE_STRETCH/SW_TRIM registers. Ti50 uses more offsets than the old Cr50 RTC core definition. |
| `0x400b0000` | XO crystal oscillator | runtime/cross-ref only in this image; no literal xref in `ti50.bin.prod.c`. |
| `0x40090000` | **RBOX** | interrupt groups +0x04/+0x0c/+0x10, +0x18/+0x20/+0x24, +0x2c/+0x34/+0x38; controls +0x44/+0x48, status +0x54, init-ready +0x58 |
| `0x400c0000` | TIMER / 64-bit counter | enable +0x00, config +0x04/+0x10, counter low/high +0x14/+0x1c, period/reload +0x38, status/busy +0x78. Not console/UART and not DCRYPTO. |
| `0x400d0000` | clock generator | runtime/cross-ref only; busy +0x00 bit1 and dividers +0x04/+0x10/+0x20/+0x30 are not statically present in this dump. |
| `0x400e0000` | programmable engine + line IRQ | control/start +0xd4, mode +0xd8, data +0xdc, status +0x154, config table +0x108..+0x124; IRQ line mask bit20 at `0xe000e00c`. Not a USB wrapper. |
| `0x40100000` | GLOBALSEC (was Cr50 0x40090000) | REGION/ALERT; ALERT sub-window +0x4000 |
| `0x40110000` | **FLASH controller** | see 4f |
| `0x40200000` / `0x40204000` | 256-bit crypto verify engine | control/clear +0x34, command +0x38 (`0x080002a3`), result words at `0x40204040..5c`, operands at `0x40204060/80/a0/c0/e0`. Likely the live Ti50 DCRYPTO-like verify block. |
| `0x40250000` | DRBG/CSRNG/keymgr | arm +0x00, status +0x10, start +0x14, command +0x1c, seed/perso/output register files +0x24/+0x44/+0xc8/+0xe8, handoff magic words +0x64/+0x84 (`0xc7d40497`). |
| `0x40410000` | TRNG | Cr50/gscemu cross-ref only for this image; no Ti50 static xref. DRBG seed paths wipe/use the `0x40250000` register files. |
| `0x40450000` | FUSE / OTP | read-only word array; default 0x55555555; load-bearing config fuses |
| `0x404d0000` | **console UART** | RDATA +0x00, WDATA +0x04, STATE +0x14 (bit0 clear = TX ready, bit7 clear = RX available) |
| `0x40520000` | GPIO input-bank samples | banks at +0x00/+0x34/+0x68/+0x9c; `sub_A2F30` samples `plt_rst_l` / `ccd_mode_l` through this block |
| `0x40600000` | **AP SPI host / AP flash SPI** | control +0x00, XACT +0x04, XFER_CFG +0x08, W1C/status +0x14/+0x1c/+0x20, byte data window +0x1000. Ti50 moved this here; Cr50 `gscemu-main` uses different bases. |
| `0x40620000` | **GSC FIFO / TPM-SPI FIFO** | control +0x10 reset/mode, W1C IRQ group +0x590/+0x598/+0x59c, status +0x5a0 |
| `0x40630000` | I2C candidate | runtime/cross-ref only; absent from `ti50.bin.prod.c`. Do not treat it as established Ti50 MMIO without a live trace or IDA xref. |
| `0xe000e000` | core-local IRQ/vector block | `+0x0c` line mask writes, `+0x2c` init/config, `+0xd0` interrupt claim/source, `+0xd8` pending/epoch poll, `+0xe0` RW handoff vector |

### 4d. Reset-source register (SOLVED, working)
PMU base `0x40000000`. Classifier (fw.bin) at VA `0xabdb0`: reads `*0x40000000`,
saves it, writes 1 to `0x40000004` (CLRRST), then tests bits.

`RSTSRC` bits: POR=0x1, EXIT=0x2, WDOG=0x4, LOCKUP=0x8, SYSRESET=0x10,
SOFTWARE=0x20. The firmware's normal pattern: **cold boot = POR → one-time
setup → GLOBAL_RESET (software reset) → warm boot proceeds**. Model:
- cold = `0x01` (POR), warm = `0x22` (SOFTWARE|EXIT — satisfies both fw.bin's
  `0x20` check and ti50 RO's bit1 check).
- CLRRST (`+0x04` write) clears the reported bits.
- Persistent PMU scratch (`+0x4c` bits30/31 init-flags, `+0xb0` boot counter,
  `+0xa0`) must survive the warm reset — the `store` does (it's not cleared by
  `cpu.reset()`).

GLOBAL_RESET sites: fw.bin `0xabf04` (with `wfi` deep-sleep) and `0xabf9e`
(graceful); ti50 RW_A `0xa31aa` (panic-reboot).

### 4e. Console UART and interrupts (SOLVED enough for boot/wake)
`0x404d0000`. Discovered by an ASCII-write sniffer (16,170 printable byte writes
to `0x404d0004` decoded into the boot log). RDATA `+0x00`, WDATA `+0x04`,
STATE `+0x14`. IDA helpers: `sub_928D0` treats TX as ready when bit0 is clear;
`sub_92930` treats RX as ready when bit7 is clear. `RAX_GSC_UART_RX` seeds a
raw byte queue for RX experiments. Note: the statically-guessed `0x40620000`
block is not the live console UART — runtime evidence wins.

Interrupt path: the kernel has `mie=0x888` at idle and uses vectored
`mtvec=0x95501`. The external vector is `0x9552c`; it enters the Tock interrupt
dispatcher at `0xa32b2`, which reads `0xe000e0d8` and claims a source from
`0xe000e0d0`. Source 0 maps to device base `0x404d0000`. The dispatcher also
touches UART-like interrupt/status offsets `+0x3c`, `+0x40`, and `+0x44` before
checking the client descriptor. In the current boot, the RX client pointer is
zero, so source 0 wakes the kernel but does not reach UART RDATA.

### 4f. Flash controller
`0x40110000`. Verified from IDA and live trace:

| register | offset | function |
|---|---:|---|
| PE_CONTROL0/1 | `+0x04/+0x08` | command/opcode issue lanes; firmware polls until the lane reads zero |
| READ_TRANS | `+0x0c` | packed read transaction; `sub_9F74C` writes `((desc[4]+off)&0xffff) | info_bit16` |
| TRANS | `+0x10` | packed program/erase transaction; encoder at `0x9f9ac` gives `byte = ((TRANS>>7)&0xffff)*4`, plus info bit3 / high bit23 |
| STATUS0/1 | `+0x18/+0x1c` | lane completion/status; zero is success |
| DOUT0 | `+0x60/+0x64` | 64-bit read result for PE_CONTROL0 |
| DOUT1 | `+0x6c/+0x70` | 64-bit read result for PE_CONTROL1 |
| WR_DATA | `+0x78/+0x7c` | 64-bit program payload |
| PE_EN | `+0x8c` | write `0xB11924E1` before issuing a command |
| ERROR | `+0x9c` | error code; zero is success |

Opcodes present in `ti50.bin.prod`: READ `0x16021765` and Ti50 PROGRAM
`0xe89d48b7`. Cr50 PROGRAM `0x27182818`, ERASE `0x31415927`, and BULK
`0x1D1E2BAD` are family/reference constants absent from this image; erase is
encoded through `TRANS=sub_9F9AC(desc,cmd=3)`. Current model:
- PE_CONTROL0 targets slot 0, PE_CONTROL1 targets slot 1 (`0x80000` stride).
- Reads fill the appropriate DOUT lane.
- XIP flash reads/program/erase hit guest memory at `RAX_GSC_FLASH_BASE`
  (`0x80000` for ti50, `0xa0000` for fw.bin).
- INFO flash is separate from XIP and defaults blank (`0xffffffff`). This fixed
  tickv/filesystem page classification; previously INFO reads aliased XIP code.

### 4g. AP SPI host and AP RO status
`0x40600000` is the Ti50 AP SPI host used for external AP flash traffic, not
the console UART. Runtime/IDA proof:
- Init at `0xb7048..0xb7062` writes control `+0x04=0`, clears W1C/status
  groups `+0x14/+0x20/+0x1c`, reads `+0x20` expecting zero, then writes
  `+0x00=0x05001000`.
- TX helper `0xa4b66`/`0xa4c40` copies bytes into the `+0x1000` data window,
  writes transfer config `+0x08`, and starts the transaction with `+0x04 bit0`.
- RX helper `0xa4a62` polls `+0x04 bit0` clear, computes the RX offset from
  `+0x08`, and copies response bytes back out of the same `+0x1000` window.

Status opcodes `0x05`, `0x35`, and `0x15` are AP flash status-register reads.
The current model returns SR1=`0x02`, SR2=`0x00`, SR3=`0x00`, and the cached
policy words synthesized by `RAX_GSC_AP_RO_INFO_STUB=1` use the firmware
encoding `[expected, ~expected, mask, ~mask]`:
- SR1 expected `0x02`, mask `0xff` => word `0x00fffd02`.
- SR2/SR3 expected `0x00`, mask `0xff` => word `0x00ffff00`.

This is enough for the boot to print `AP WP SR OK!`. The early kernel AP RO
path then reads AP flash through opcode `0x0b` fast-read:
the helper sends `[0x0b, addr[23:16], addr[15:8], addr[7:0], dummy]`, uses
transfer config `0x00181380`, and receives payload bytes at window offset
`+0x100d`. Status reads use transfer config `0x00000380` and receive payload at
`+0x1005`; in both cases the payload starts at `align4(tx_len) + tx_len` inside
the `+0x1000` data window.

`RAX_GSC_AP_FLASH=/path/to/ap_flash.bin` supplies bytes for those reads; missing
or absent data is erased flash (`0xff`). The current narrow successful path uses
`/tmp/rax-ap-fmap11-gbb-gvd.bin`: FMAP v1.1 at AP flash offset 0, `GBB` at
`0x100`, `RO_GSCVD` at `0x1000`, a SHA256 range digest over AP flash
`[0,0x1000)`, and an appended GVD cache object at `gvd_offset + gvd_size`
(`0x13b0` in that probe). With `RAX_GSC_AP_RO_INFO_STUB=1` and
`RAX_GSC_AP_RO_CRYPTO_STUB=1`, this path prints `gscvd @00001000 consistent`,
`gscvd OK`, `validating 1 ranges in AP flash`, `caching gvd info`, and
`AP RO: OK`, then reaches idle. The crypto stub is intentionally narrow:
- PC `0xb2904`: copy the expected production root-key digest into the root-key
  digest compare buffer.
- PC `0xb1efe`: copy the expected GVD range digest into the computed digest
  buffer immediately before the range digest compare.

It does not force the verifier return at `0xb7462`. With blank AP flash the
verifier still returns `a0=0x0e` and prints `AP RO: NOT OK`. The broader
`RAX_GSC_AP_RO_STUB=1` still exists as a standalone bring-up fallback; that flag
does force the verifier return with zero before firmware copies it into the AP
RO status path.

GSCVD format is documented in ChromiumOS vboot:
- `host/lib/include/gsc_ro.h` defines `MAX_RANGES=32`, magic `0x65666135`
  (little-endian `5afe`), rollback counter `1`, and `struct
  gsc_verification_data` fields: size/version, board ID, FMAP location,
  hash algorithm, signature header, root-key header, `ranges_digest`,
  `range_count`, then range pairs.
- `futility/gscvd.c` validates size/magic/range count and checks that the
  signature and root-key bodies live inside the blob.
- `futility/cmd_gscvd.c` creates the blob in the AP firmware `RO_GSCVD` FMAP
  area, hashes configured AP RO ranges, signs the GVD with the platform key,
  and appends the keyblock/root-key material. It also verifies that RO ranges
  fit inside `WP_RO` or `SI_ALL`, do not overlap `RO_GSCVD`, and do not overlap
  each other.

Source links:
- https://chromium.googlesource.com/chromiumos/platform/vboot_reference/+/refs/heads/main/host/lib/include/gsc_ro.h
- https://chromium.googlesource.com/chromiumos/platform/vboot_reference/+/refs/heads/main/futility/gscvd.c
- https://chromium.googlesource.com/chromiumos/platform/vboot_reference/+/refs/heads/main/futility/cmd_gscvd.c

### 4h. Boot flow & current stop point
- **ti50.bin.prod**: boots RW_A, initializes USB/RBOX/cryptolib/TPM SPI, scans
  the blank persistent storage pages, prints `PLT_RST_L ASSERTED` and
  `TPM SPI disabled (CS=true)`, then reaches Tock idle at `0xa2d3c`. This is not
  the old abort/reboot path. `RAX_GSC_BREAK=a2d3c` shows the idle stack contains
  sleep/wake diagnostic strings such as `plt_rst_l`, `ccd_mode_l`, and
  `usb active`.
- **fw.bin**: still expected to use the same reset-source/console/flash
  machinery, but the latest session focused on Ti50. Re-verify before claiming
  fw.bin parity.
- With `RAX_GSC_AP_RO_INFO_STUB=1`, `RAX_GSC_AP_RO_CRYPTO_STUB=1`, and the
  synthetic AP flash at `/tmp/rax-ap-fmap11-gbb-gvd.bin`, boot prints
  `AP WP SR OK!`, `gscvd @00001000 consistent`, `caching gvd info`,
  `AP RO: OK`, then reaches idle. Without AP flash/GVD/provisioned policy data,
  the non-fatal AP RO line remains `AP RO: NOT OK`. RBOX init and TPM FIFO reset
  warnings have been eliminated by explicit RBOX/FIFO status models. The AP-RO
  status line was traced through the debug writer: hit `0x9f070` on the 657th
  UART write to get stack
  `0xb5924 -> 0xa7a58 -> 0xbeb28 -> 0xa7b96 -> 0x9f070`; the state already
  pointed at the `AP RO: OK`/`NOT OK` token cluster (`0xc06b3`).

### 4i. Timer / scheduler tick (SOLVED)
`0x400C0000` is the platform machine timer: 64-bit free-running up-counter at
`+0x14`(lo)/`+0x1C`(hi), prescale `+0x10` (init = 261), 64-bit alarm compare at
`+0x2C`(lo)/`+0x34`(hi) (init disarmed = all-ones), busy/ready `+0x78`. `sub_8072E`
= `get_now()` returns the raw `PAIR64(+0x1C,+0x14)` (it only `>>8`s when prescale
== 0). Firmware deep-sleep tick rate is 256000/sec (`sub_904EA`). rax drives the
counter from retired instructions (`RAX_GSC_TIMER_DIV`, default 24). The idle
loop `sub_A2D28` WFIs only when `sub_9F9D8` (`has_pending_interrupts`) returns 0;
that gate scans deferred-call slots at `0x16FB0`, driver flags
`0x1EC4A/0x1EB2A/0x1EB8A/0x1EBEA/0x1E8F1`, the armed+expired alarm
(`0x154D4` + `sub_9F27E` comparing now vs target `0x154C0/0x154C4`), service flags
at `0x1ECB0`, and finally `mip.MEIP` (bit 11). Because rax models WFI as a busy
re-check and time now advances, the software alarm poll fires and the scheduler
makes progress (`service_pending_interrupts took … ms`). MTIP (`mip` bit 7,
vector `0x9551c`) is also asserted when the counter reaches the compare, but this
image never arms that compare in the idle path, so it stays latent.

### 4j. TPM 2.0 host command path (SOLVED end-to-end)
The TPM command-processor task is `sub_D3904`. Its loop reads the pending flag
`0x220BC`, RX/TX buffer pointer `0x220C0`, length `0x220C4`, and capacity
descriptor `0x220C8` (low 24 bits = buffer size), dispatches standard commands
through `sub_E06BE → sub_E07A0` (= ms-tpm-20-ref `ExecuteCommand`; table-driven
dispatch via `sub_DE100`/`sub_E0B72`), then sends the response via `sub_D4B80`.
When no command is pending it yields at the `ecall` at **`0xd3cca`** (the next
insn `0xd3cce` loops back to re-read `0x220BC`).

**The AP-power gate.** Before dispatch the task checks `sub_D51F6` →
`sub_D46DE(1002, 31)` (a Tock syscall to the AP-power driver 1002). If the AP is
off it logs `"Received TPM command … while AP off. Drop"` (string @`0xe78e6`) and
drops the command. AP-on requires `PLT_RST_L` deasserted = GPIO bank0
`0x40520000` **bit 11** high (`RAX_GSC_AP_ON=1`). `plt_rst_l` was located by
runtime bisection of `sub_A2F30` pin samples (the pin bit comes from an RO helper
at `0x1950c`, so it is not in the RW decompile); bank0 bit 0 and bank1 bit 11 are
strap pins (driving them changes the `Strap config` line), bit 11 is plt_rst.

**Injection (rax `yield` mode).** At the `0xd3cca` yield, rax writes the command
to scratch RAM (`0x300000`), points `0x220C0` at it, sets `0x220C4`/`0x220C8`,
sets `0x220BC=1`, and skips the `ecall` (pc → `0xd3cce`). The task then runs the
real `ExecuteCommand` in its own context (all upcalls registered), and rax reads
the response back at the `sub_D4B80` entry (buffer = `0x220C0`, length = `a1`).
The out-of-context `call` mode (synthetic call straight to `sub_E06BE`) runs the
TPM stack deeply (it printed `TPM_Manufacture started`, key-ladder, AP RO latch)
but derails on a null upcall, so `yield` is the default.

### 4k. TPM entropy / RNG (SOLVED)
The TPM RNG reads **no MMIO** in the generate path (confirmed by full-session
crypto trace). The chain is `TPM2_GetRandom → sub_D5558` (`0xD5558`,
CryptRandomGenerate; `ctx a0`, `dest a1`, `count a2`; returns count) `→ sub_D4D48`
(`0xD4D48`) which `allow`s the output buffer then issues a Tock `command` syscall
to **kernel crypto service #1003, command 56** (`sub_D498C`/`sub_D49AA`). The
kernel service writes **zeros** into the allowed buffer while returning success,
so RNG/nonces/keys all come back zero. The hardware keymgr DRBG at `0x40250000`
(`sub_805C0`/`sub_80504`) is a *separate* block with **no RW callers** — modeling
it does nothing for the TPM RNG. rax hooks `sub_D5558` and `sub_D5606` (`0xD5606`,
nonces; `count a0`, `dest a1`) by guest PC: fill `[dest..dest+count]` with a
SplitMix64 PRNG, set `a0 = count`, return to `ra`. (`sub_80434`/`0x40250010`
status is also modeled as done=1 + non-zero output for the keymgr DRBG, and the
second timer instance at `0x40631000` — same layout as `0x400C0000`, polled as
the TPM command-timeout clock — is driven from instret.)

### 4l. Runtime PLT_RST eventing (SOLVED)
The firmware caches AP-power state in **kernel driver 1002** (`sub_D51F6 →
sub_D46DE(1002,31)`), updated only by its GPIO-pin handler — reached through the
RO interrupt-routing layer, so it cannot be triggered out of context (the
external dispatcher *does* run: source 19 = `0xE000E00C` bit19, armed by
`sub_B2EDC` in the plt_rst path, claims/acks correctly, but its pin-callback
wiring is RO). Instead `RAX_GSC_PLT_RST_EVENT=1` deasserts the plt_rst level then
requests a **warm reset**, so the firmware reboots and reads AP-on from boot —
which is what real silicon does on an AP power-state change (`Rebooting GSC for
AP RO due to state`). Result: first boot `POR` + `PLT_RST_L ASSERTED`; after the
event, `SW` reset + `PLT_RST_L DEASSERTED`, and TPM commands then process.

### 4m. Wired GscFifo transport (host interface)
The TPM host interface (GscFifo / TPM-SPI, driver 1004) has its receive-ISR
(copies a host frame into `0x220C0` and sets the `0x220BC` pending flag — only
ever written `=0` in the RW dump) and its response-send (`sub_D4B80 =
sub_D46DE(1004, 2)`) **both in the RO kernel**, and the FIFO interrupt source is
not in the RW `0xE000E00C` enables. So a fully autonomous SPI bus is not
reproducible without the RO image. `RAX_GSC_TPM_WIRED=1` does the achievable
thing: it backs the GscFifo dual-port command/response RAM at **`0x40621000`**
(`GSC_FIFO_RAM_BASE`, 2 KiB, byte-accurate) and points the firmware's command
buffer (`0x220C0`) there, so the firmware reads the command from and writes the
response to the real FIFO MMIO window. Only the receive-*wake* is bridged at the
task yield (`0xd3cca`); the parse/dispatch/response all run the firmware's code.

---

## 5. Debug tooling (env knobs)
| env | meaning | default |
|---|---|---|
| `RAX_MACHINE=gsc` | select the GSC machine | — |
| `RAX_GSC_TRACE` | `mmio` = first-touch + PMU + `CONSOLE?` ASCII-write candidates; `insn` = every instruction (`pc: disasm`) | off |
| `RAX_GSC_UART` | console UART base (hex) | `404d0000` |
| `RAX_GSC_UART_STATE` | base UART STATE bits; RX-empty bit is dynamic | `30` |
| `RAX_GSC_UART_RX` | initial UART RX bytes, as a raw env string | empty |
| `RAX_GSC_OPENBUS` | unmodeled MMIO read value | `0` |
| `RAX_GSC_READY` | fixed status regs `addr=val,addr=val` (hex) | — |
| `RAX_GSC_RSTSRC_COLD` / `_WARM` | reset-source values | `01` / `22` |
| `RAX_GSC_FLASH_BASE` | flash image guest base | `80000` |
| `RAX_GSC_AP_FLASH` | external AP SPI flash image for opcode `0x0b` fast-read | blank/erased |
| `RAX_GSC_AP_RO_INFO_STUB` | synthesize only the cached AP RO INFO record (`0x303`) | off |
| `RAX_GSC_AP_RO_CRYPTO_STUB` | synthesize AP RO digest results at `0xb2904` and `0xb1efe` without forcing verifier success | off |
| `RAX_GSC_AP_RO_STUB` | broad standalone fallback: cached AP RO state plus forced kernel verifier success | off |
| `RAX_GSC_ENTRY` | override boot entry PC | auto |
| `RAX_GSC_AP_ON` | deassert `PLT_RST_L` (GPIO bank0 `0x40520000` bit 11) → AP host powered on from boot; required for the firmware to process TPM commands instead of dropping them "while AP off" | off |
| `RAX_GSC_PLT_RST_EVENT` | boot AP-off, then deassert `PLT_RST_L` at runtime and warm-reset so the GSC re-boots AP-on (models the host powering on mid-run) | off |
| `RAX_GSC_TPM_CMD` | inject one or more host TPM commands (hex bytes; `,`/`;`-separated) once the firmware reaches the TPM command-wait point; prints each response | — |
| `RAX_GSC_TPM_WIRED` | stage the TPM frame in the real GscFifo dual-port RAM `0x40621000` (the firmware reads cmd / writes response there) instead of scratch RAM | off |
| `RAX_GSC_NO_ENTROPY` | disable the RNG hooks (`sub_D5558`/`sub_D5606`); randomness reverts to the all-zero kernel-service output | off (hooks on) |
| `RAX_GSC_CRYPTO_TRACE` | log accesses to the crypto/DRBG windows (and all MMIO during a TPM command) | off |
| `RAX_GSC_TPM_MODE` | `yield` (default) plants the command in the firmware task's own scheduler context via its command-wait `ecall` (`0xd3cca`) → real `ExecuteCommand`; `call` does an out-of-context synthetic call to `sub_E06BE` (runs the TPM stack deeply but derails on unregistered upcalls — diagnostic only) | `yield` |
| `RAX_GSC_TPM_TRACE` | bounded per-instruction trace of the in-flight TPM command processing | off |
| `RAX_GSC_TIMER_DIV` | retired-instructions-per-timer-tick divisor for the `0x400C0000` free-running counter (affects the `[ N.NNN]` timestamp scale) | `24` |
| `RAX_GSC_GPIO_TRACE` | log every GPIO pin sample (`sub_A2F30` @`0xa2f38`: bank base + bit index) — used to find plt_rst/ccd bits | off |
| `RAX_GSC_BREAK` | breakpoint PC: on first hit, dump regs + stack call-chain + ASCII strings pointed to by regs/stack | — |
| `RAX_GSC_BREAK_HIT` | 1-based breakpoint hit to dump, parsed as hex like other knobs | `1` |

The `RAX_GSC_BREAK` dump is the workhorse for diagnosing panics: it prints
ra/sp/a0-a5/s0-s4, a heuristic call-stack (stack words in 0x80000-0x180000), and
any image strings the registers/stack point at.

Disassembly: `python3` + `capstone` (`CS_ARCH_RISCV, CS_MODE_RISCV32 |
CS_MODE_RISCVC`); `VA→file = VA - load_base`. **Caveat: RVC misalignment** — if
you start at a non-instruction boundary you get garbage (e.g. `c.flw`/`c.jr ra`
that make no sense); re-anchor on a known-good address.

---

## 6. Next steps after boot-to-idle

Boot-to-idle, a live scheduler tick, host TPM 2.0 command processing, real RNG
entropy, runtime AP-power eventing, and a GscFifo-backed transport all work now
(see §4i–§4m). The three previous TODOs (wired transport, entropy, PLT_RST
eventing) are done; their residual limitation is the same one throughout: the
SPS/GPIO **interrupt routing and the receive/send kernel drivers (1003/1004) are
in the RO image**, so the host-frame *delivery wake* is bridged rather than
driven by a fully autonomous bus. Closing that needs the RO bank decompiled (or
its interrupt source-number table) — the single highest-leverage remaining input,
alongside `acroterm.json` for log detokenization. Remaining realism work:

1. **Replace AP RO provisioning/crypto stubs with real inputs.** The live
   kernel verifier path is now mapped: `RO_GSCVD`, `locating gvd to verify`,
   `gscvd @ consistent`, root-key digest compare at `0xb2904`, range digest
   compare at `0xb1efe`, `caching gvd info`, and `validating  ranges in AP
   flash`. AP SPI opcode `0x0b` fast-read is implemented and can be backed by
   `RAX_GSC_AP_FLASH`. The remaining realism gap is a production-accepted AP
   firmware image/GVD/trusted key chain and real crypto hardware results instead
   of `RAX_GSC_AP_RO_INFO_STUB`/`RAX_GSC_AP_RO_CRYPTO_STUB`. The broader
   `RAX_GSC_AP_RO_STUB=1` is only a fallback for bring-up.
2. **Get the acroterm.json dictionary** (or a symbol table). It is still the
   fastest way to turn tokenized logs and panic paths into named firmware
   diagnostics.
4. **Finish crypto/keyladder behavior only when a live path needs it.** The newly
   found `/Users/int/Downloads/ot_dsim-master` repo is the bignum/OTBN simulator
   used by `gscemu-main/src/haven/components/crypto.py`; it documents 256-bit
   WDRs, DMEM/IMEM, CSRs `0x7c0/0x7d0/0xfc0`, WSRs `0`/`1`, and instruction
   semantics. It does not by itself identify Ti50 MMIO offsets. Cr50's crypto
   register model is
   CONTROL `+0x04`, INT_ENABLE `+0x14`, INT_STATE `+0x18`, HOST_CMD `+0x20`,
   RAND_STALL_CTL `+0x30`, WIPE_SECRETS `+0x50`, DMEM `+0x4000`, IMEM
   `+0x8000` at Cr50 base `0x40420000`; that base is Cr50-only here. The Ti50
   production image does expose a different 256-bit verify engine at
   `0x40200000`/`0x40204000` and a DRBG/CSRNG/keymgr block at `0x40250000`.
   The current boot-to-idle path does not need a full OTBN interpreter; the
   `DCRYPTO FAULT` string shows up in the idle breakpoint stack as a
   string-table pointer, not as a printed fault.
5. **Replace generic spin-breaker behavior with real peripherals where needed.**
   Current boot succeeds with a permissive store/open-bus model for many pads,
   FIFOs, and status bits. For interactive behavior, pinmux/GPIO/event-router,
   USB, TPM SPI, and timers should get concrete state machines.
6. **Provisioned data.** Synthetic fuse/device identity is now sufficient for
   version strings, but silicon-provisioned fuses, real AP RO state, endorsement
   material, and NVRAM data are still synthetic/default.

---

## 7. Key code anchors

### rax
- `create_vcpu` gate: `src/backend/emulator/mod.rs` (`ArchKind::Riscv64` arm)
- machine: `src/backend/emulator/gsc.rs` (`GscBridge::read`/`write`, `GscVcpu::run`/`take_reset`)
- loader: `src/arch/riscv.rs` (`load_gsc`, `select_gsc_entry`, header consts `HDR_*`)
- xsoteria decode/exec: `src/riscv/decode.rs` (`decode_xsoteria_custom0/1`), `src/riscv/cpu.rs` (`grev32`/`fls32`, execute arms, `ext_csr`)

### firmware VAs (fw.bin / ti50, see which)
- fw.bin reset-source classifier: `0xabdb0` (reads PMU+0x00); reboot routines
  `0xabf04` (wfi deep-sleep), `0xabf9e` (graceful); panic/trap-save `0xa06d8`;
  reset logger `0xa9e96`; flash op `0xaa75e`.
- ti50 RW_A `_start` `0x956b2`; mtvec `0x95582`; Tock idle/WFI path `0xa2d28`
  with WFI at `0xa2d3c`; fatal abort/reboot path still exists at `0xa3fe0` →
  `0xa31aa` but is not the current high-water mark; flash read helper `0x9f74c`;
  command issue/poll/status helpers `0x9f7d0`/`0x9f800`/`0x9f822`; flash address
  encoder `0x9f9ac`; flash driver init `0x92b32`+.

### scratch (agent disassembler scripts, may be cleaned up)
`/private/tmp/claude-501/-Users-int-dev-rax/<session>/scratchpad/` —
`mmio_trace.py`, `pmuwalk.py`, `xref.py`, `win.py`, etc., and `soteria.patch`.

---

## 8. Open questions / unknowns
- `acroterm.json` location (have a copy? it's the key to fast progress).
- Which exact GPIO/event-router/USB/TPM-SPI inputs should be toggled to move
  past idle into an interactive or host-driven workflow.
- Full Ti50 crypto/keyladder behavior. The main Ti50 verify and DRBG/CSRNG
  bases are now identified (`0x40200000`/`0x40204000`, `0x40250000`), but their
  exact arithmetic/keyladder semantics should be implemented only when a live
  path requires more than the current boot model.
- Exact identities for heavily touched but still generic-modeled pages:
  `0x40040000` and the UART-like
  `0x404e0000`/`0x404f0000`/`0x40500000` instances. `0x400a0000` is now best
  identified as RTC/wakeup-sequencer territory from runtime trace plus the
  Cr50 `GC_RTC0_BASE_ADDR` cross-reference.
- Production fuse/provisioning values for AP RO/RBOX/TPM identity.

---

## 9. MMIO verification pass vs `ti50.bin.prod.c` (2026-06-26)

An exhaustive multi-agent sweep verified every MMIO claim in this handover and in
`mmio.md` against the Ti50 production pseudocode dump, with adversarial re-checks.
Full per-register evidence is in `mmio.md` ("Static verification pass") and
`mmio_verification_2026-06-26.md`. Headline results that change §4c/§4f/§6:

- **§4c `0x400e0000` is NOT a "USB event/reset wrapper".** It is a programmable
  engine + line-IRQ: control `+0xD4`, mode `+0xD8`(0x21F), data `+0xDC`, status
  `+0x154` (polled), config table `+0x108..+0x124`; IRQ = bit20 of `0xE000E00C`
  (`sub_A2B50`, `sub_120A32`).
- **§4c `0x40250000` is a DRBG/CSRNG/keymgr block, not "flash protection."**
  control `0x40250000`(arm 0x7), command `0x4025001C`(0/4/3/1), start
  `0x40250014`, 256-bit seed/perso/output files `0x40250024/0x40250044/0x402500E8`.
- **NEW: `0x40200000`/`0x40204000` is a 256-bit crypto verify engine** — the most
  likely live Ti50 relocation of the Cr50 "DCRYPTO" left open in §6.3.
  `sub_80608` loads 5 operands (`0x40204060/80/A0/C0/E0`), commands `0x080002A3`
  at `0x40200038`, reads digest `0x40204040`, XOR-compares to expected hash.
- **`0x400c0000` is a TIMER/64-bit counter block, not console/UART** (`sub_8072E`
  reads `__PAIR64__(0x400C001C,0x400C0014)`; `+0x38` reload, `+0x78` busy).
- **§4c bases ABSENT from this image** (cross-ref/runtime only, zero literal):
  `0x40040000`, `0x400b0000` (XO), `0x400d0000`, `0x40410000` (TRNG),
  `0x40420000` (Cr50 DCRYPTO), `0x40630000` (I2C — live base is `0x40620000`).
- **§4f flash opcodes:** only READ `0x16021765` and Ti50 PROGRAM `0xe89d48b7`
  are present in this image; Cr50 PROGRAM `0x27182818`, ERASE `0x31415927`, and
  BULK `0x1D1E2BAD` are **absent** (erase = `TRANS=sub_9F9AC(desc,cmd=3)`).
- **RBOX `0x40090000`:** only controls `+0x44`/`+0x48`, status `+0x54` are
  verifiable; the interrupt-group/descriptor rows and `sub_B6948`/`sub_99A40`
  do not exist in this dump (undecompiled gap). Treat as runtime-only.
- **Chip ID `0x4001ffe0`/`0x4001fff8` and value `0x8485694d`** appear nowhere in
  this image; `0x4001FFE4` is the boot/RO-update status word.
- **Caution — not registers:** `0x40000001..0x4000000D`, `0x40000110/11A/120`
  are TPM 2.0 permanent-handle constants, not PMU MMIO.
