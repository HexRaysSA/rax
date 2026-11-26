[← rax README](../../README.md)

# Xtensa LX7 and ESP32-S3 machine: plan (2026-11)

Plan for adding an Xtensa LX7 interpreter and an Espressif ESP32-S3 machine to rax, with
Espressif's QEMU fork as the differential oracle. Branch: `feat/xtensa-esp32s3`, from `master`
`36f1a583a`.

The end goal is to run unmodified `esp-hal` firmware, and the Bitaxe miner firmware
`esp-miner-rs` in particular, with its board around it (I2C power and fan chips, the ASIC chain on
UART1, the displays), apart from WiFi.

Since 2026-11-20 rax holds only the Xtensa LX7 core (`src/isa/xtensa/`, with the ESP32-S3 core
configuration). The ESP32-S3 SoC (machine, devices, runner) is the `esp32s3-emu` crate of
bitaxe-emu-rs, next to the board models, and uses rax as a library (decision D1). The SoC parts of
this plan (§3.2, §4.3-§4.7, §5.3-§5.4) stay here as their design record.

Every claim below is labelled with the classes of the
[documentation policy](../documentation-policy.md), or names its source.

## 0. Status (2026-11-20)

What exists on the branch, by claim class:

| Part | Where | Claim |
|---|---|---|
| Opcode recognition generated from the core tables (753 opcodes, 4 formats), with the AR operands of each opcode for window checks | `tools/xtensa/gen_opcodes.py`, `src/isa/xtensa/generated/` | **Inventory-checked**: same mnemonic as GNU objdump 2.46 for all 143,422 distinct words of an ESP32-S3 application image, 415 mnemonics; 4,343 of them kept in `src/isa/xtensa/testdata/` and checked by `decode_matches_objdump` |
| Interpreter: base ISA, windowed registers (overflow/underflow vectors, ENTRY/RETW/MOVSP/ROTW/RFWO/RFWU), loops, MUL16/32, DIV32, MAC16, booleans, S32C1I, XEA2 exceptions and the six interrupt levels plus NMI, CCOUNT/CCOMPARE, region protection registers, single-precision FPU (QEMU's reduced model of the division and square-root steps) | `src/isa/xtensa/` | **Implemented**; **Unit-tested** (windowed call, overflow, FPU and coprocessor exception, MAC16, S32C1I, loops, interrupt levels) |
| PIE (`ee.*`), `recip0.s`, `rsqrt0.s`, `sqrt0.s`, debug instructions | — | **Unsupported**: IllegalInstruction, counted in the execution profile |
| ESP32-S3 SoC: machine, devices, `esp32s3-run` | bitaxe-emu-rs, crate `esp32s3-emu` | Moved out of rax; its status table and assumptions (A3, A4, A6, A7, A9-A12) are in that crate's README. It uses only the public `rax::isa::xtensa` API |
| Speed | — | About 60-80 MIPS on the host this was written on (decode cache by address, fetch page cache) |
| Differential testing against QEMU (P3, P5) | — | **Unknown**: not done yet; the core is validated by the decode inventory, the unit tests and the full boot |
| Registration in the rax CLI (`ArchKind`, backend, snapshot) | — | Not done: the core is used as a library (`rax::isa::xtensa`) |

## 1. Acceptance criteria

| # | Milestone | Evidence that closes it |
|---|---|---|
| M1 | Xtensa decode of the ESP32-S3 core | Generated opcode tables; inventory test against GNU `objdump` for every opcode of the core; nonzero case count |
| M2 | Base ISA and the options the ESP32-S3 has (§3.1) execute | Unit tests per family; recorded QEMU differential cases replayed with no differences for the cases executed |
| M3 | `esp-hal` examples boot on the `esp32s3` machine | Boot-demonstrated: UART0 hello world, embassy timer example, defmt over RTT |
| M4 | Machine-level lockstep with QEMU | First-divergence tool reports no divergence over N instructions of the M3 images, under `-icount` |
| M5 | `esp-miner-rs` runs with an emulated Bitaxe board | Boot-demonstrated: power task, ASIC enumeration, valid nonces on the emulated chain, display frames |
| M6 | Networking | The web interface is reachable from the host; a stratum session runs against a local test pool |
| M7 | Later | Full flash boot (ROM, 2nd-stage bootloader, app), OTA, APP_CPU, PIE `ee.*`, Xtensa GDB server, optional SMIR lifter |

## 2. Sources and oracles

| Source | Use | License / redistribution |
|---|---|---|
| Espressif QEMU fork, `upstream/qemu-espressif` branch `esp-develop` (base QEMU 9.2.2), commit `7ca512d1f1` | ISA and device behaviour oracle, run as an external program | GPL-2.0: behaviour only, no code copied into rax |
| `target/xtensa/core-esp32s3/` (`core-isa.h`, `xtensa-modules.inc.c`, `gdb-config.inc.c`) | Machine-readable core configuration: options, vectors, interrupts, register files, every opcode's encoding | Tensilica MIT-style notice (header of each file): may be parsed by a generator, with a `THIRD_PARTY_NOTICES.md` entry |
| GNU binutils of the esp toolchain (`xtensa-esp32s3-elf-as/objdump` 2.46, crosstool-NG esp-16.1.0) | Encoding and disassembly oracle; assembler for test cases | Tool only. Checked on this host: assembles and decodes base, MAC16, FP and `ee.*` instructions |
| Xtensa ISA Reference Manual (Cadence), ESP32-S3 Technical Reference Manual and datasheet (Espressif) | Architectural and peripheral specification | Reference documents: link plus retrieval record under `docs/specifications/xtensa/` and `docs/hardware/espressif/`, per AGENTS.md §15 |
| ESP32-S3 ROM image `pc-bios/esp32s3_rev0_rom.bin` (393,216 B) | ROM code the firmware calls (§4.6) | **Unknown** redistribution terms: never committed; supplied by path at run time |
| Real ESP32-S3 boards (Bitaxe) | Strongest oracle for cases where QEMU has no model or disagrees with the TRM | n/a |

QEMU is the strongest *available* emulator oracle, not an independent architectural truth
(AGENTS.md §11.3). Its known gaps for this target:

- **Opcodes:** `recip0.s`, `rsqrt0.s`, `lddr32.p` and `sddr32.p` have no translator. They raise IllegalInstruction (`target/xtensa/translate.c:905-921`).
- **SIMD state:** the PIE state (`env->ext`, `cpu_esp32s3.h`) is neither reset nor migrated. Its QR registers read as zeros through the gdbstub. `ee.get_gpio_in` loops back `gpio_out`.
- **Missing devices:** no I2C (compiled but not instantiated), no LCD_CAM, no SAR ADC, no IO_MUX, no WiFi. USB-Serial-JTAG is a stub. Everything from 0x60000000 to 0x600D0FFF that isn't modelled reads 0 (`hw/xtensa/esp32s3.c:569-599`).
- **SRAM layout:** IRAM and DRAM are separate RAM regions with no I-bus/D-bus aliasing (`hw/xtensa/esp32s3.c:485-487, 739-741`).
- **Cores and timing:** APP_CPU comes out of reset with PRO_CPU, because `SYSTEM_CORE_1_CONTROL_0` isn't modelled. CCOUNT runs at a fixed 40 MHz of QEMU virtual time.
- **No ROM in `-kernel` mode:** loading an ELF puts a trampoline at 0x40000400 and loads no ROM (`hw/xtensa/esp32s3.c:1013-1051`). A firmware that calls ROM functions can only run in QEMU through a full flash boot.

## 3. Target facts

### 3.1 ESP32-S3 core (from `target/xtensa/core-esp32s3/core-isa.h`)

- **Identity and byte order:** LX7.0.12 "LX7_ESP32_S3_MP", little-endian.
- **Registers and windowing:** windowed registers with 64 physical AR registers.
- **Instruction formats:** 16-bit density instructions (x16a, x16b), 24-bit (x24) and 32-bit (format_32). Each format has a single slot, so there's no FLIX bundling. The length comes from the low nibble of byte 0: 0-7 give 3 B, 8-D give 2 B, E-F give 4 B.
- **Options:**
  - Loops, NSA, MIN/MAX, SEXT, CLAMPS.
  - MUL16, MUL32, MUL32_HIGH, DIV32.
  - MAC16.
  - Booleans, with BR 16 × 1 bit.
  - S32C1I, with ATOMCTL reset value 0x28.
  - THREADPTR, PRID, RER/WER, MISC0-3.
  - Unaligned accesses are handled in hardware, with no exception.
- **FPU:** single precision only, including DIV, RECIP, SQRT and RSQRT. It's the "DFPU single-only" variant.
- **Exceptions and interrupts:**
  - XEA2, with 32 interrupts: 26 external, 6 levels plus NMI at level 7. EXCM_LEVEL = 3, DEBUGLEVEL = 6.
  - Three CCOMPARE timers on interrupts 6, 15 and 16.
  - VECBASE is relocatable, reset value 0x40000000. Static reset vector: 0x40000400.
- **Memory protection:** region protection (8 × 512 MB with attributes). There's no MMU, no MPU and no core cache.
- **Opcodes:** 753, of which 217 are `ee.*` (PIE SIMD) and 38 are `rur/wur` of TIE user registers. TIE state: QR 8 × 128-bit, ACCX 40-bit, QACC_H/L 160-bit, SAR_BYTE, FFT_BIT_WIDTH, UA_STATE.

### 3.2 What the target firmware uses

Profiled from the `esp-miner-rs` image for the Bitaxe GammaHex (`objdump -d`, 598,750 decoded
instructions, 2026-11-19):

- **Most frequent:** `l32r`, `movi.n`, `add.n`, `l32i.n`, `j`, `s32i.n`, `callx8`, `entry`/`retw.n`, branches, `memw`, `extui`.
- **Integer multiply and divide:** `mull`, `muluh`, `mulsh`, `quou`, `remu`, `quos`, `rems`.
- **Windowed ABI:** `call4/8/12`, `callx4/8/12`, `entry`, `retw`, `rfwo`/`rfwu`.
- **Single-precision FP:** loads and stores, arithmetic, `madd.s`, `msub.s`, `maddn.s`, `divn.s`, conversions, ordered and unordered compares, conditional moves.
- **Atomics:** `s32c1i`, `wsr.scompare1`, `l32ai`, `s32ri`.
- **Other:** `loop`, `nsau`, `clamps`, `sext`, `min/max/minu/maxu`, `mul16s/u`, `any4/all4`, `ldinc`, `rsil`, `waiti`, `rfe`, `rfi`, `rsync`, `isync`.
- **No `ee.*` in real code.** objdump reports 102 distinct `ee.*` mnemonics, but each hit sampled is padding or literal data after a non-returning call (for example 0x42197a68 in `bitcoin_hashes::sha256::Hash::from_engine`). The image's 6,449 `.byte` and 1,031 `ill` entries come from the same misdecoding. So the static mnemonic set (426 distinct) overstates what executes. An execution profile from rax itself (§5.5) replaces it.
- **ROM functions reached through `l32r` literals:** 201. Most belong to the WiFi blobs and are unreachable without WiFi. The rest:
  - libgcc soft-float and 64-bit integer routines (`__adddf3`, `__divdf3`, `__fixdfsi`, `__divdi3`, …);
  - `memcpy`/`memset`/`memcmp`/`memmove`/`bzero`/`strncmp`/`strncpy`, `crc32_le`, `esp_rom_md5_*`;
  - `esp_rom_spiflash_{read,write,erase_sector,erase_block,unlock}`;
  - `ets_delay_us`, `ets_update_cpu_frequency`, `Cache_*`, `rom_config_{data,instruction}_cache_mode`;
  - `rom_i2c_writeReg`, `esp_rom_regi2c_read`, `intr_matrix_set`, `rtc_get_reset_reason`, `software_reset`.

### 3.3 rax facts (from `master` `36f1a583a`)

- **SMIR is optional.** Hexagon, Cortex-M, S5L8900 and GSC CPUs run without it (`src/isa/hexagon` has no SMIR reference; RISC-V's JIT is opt-in, `src/isa/riscv/cpu.rs:244-245`). A new ISA may stay interpreter-only, stating why per AGENTS.md §6.
- **Microcontroller template:** GSC (`src/machine/gsc/`, RISC-V core) and S5L8900 (`src/machine/s5l8900/`, ARMv6). In both, a machine-owned vCPU wraps the ISA core and implements its memory trait as a SoC bridge. The bridge does physical-address dispatch to device models, keeps instruction-count time and has a private checkpoint context, and the machine is selected with `RAX_MACHINE`. S5L8900 also loads a separate boot ROM and translates addresses before dispatch.
- **Oracle precedent:** the Cortex-M differential suite. It runs system-mode QEMU on one firmware image holding all cases, collects results over semihosting, records them in `tests/generated/cortex_m/thumb_oracle.json` and replays them in library tests (`tools/cortex-m-diff/`, `src/backend/emulator/cortex_m_oracle_tests.rs`). Machine-level lockstep against QEMU doesn't exist yet.
- **Generated decoder precedent:** Hexagon. `tools/hexagon/gen_iset.py` builds `src/isa/hexagon/generated/opcodes.rs` from QEMU inputs, and the `THIRD_PARTY_NOTICES.md` entry records the provenance.
- **GDB server:** x86-64 only (`src/debug/gdb/`).
- **Networking:** the e1000 model queues frames; there's no host network backend (no TAP, no user-mode NAT).
- **`b00tkitism/master`:** its tree is identical to `master` commit `0485fb7d0` (2026-06-14) under an unrelated history. Its S5L8900 machine is an earlier, monolithic stage of `master`'s. It has no Xtensa or ESP32 content.

## 4. Design

### 4.1 ISA core: `src/isa/xtensa/`

- **Shape:** a self-contained interpreter in the RISC-V layout. Its `Memory` trait has `read`/`write`/`fetch` plus atomic compare-and-swap for S32C1I. The core config struct (`XtensaConfig`) carries the options, vectors, interrupt levels and types, CCOMPARE count and register-file sizes, so the ESP32 (LX6) and ESP32-S2 cores can follow with a new config.
- **CPU state:**
  - physical AR file (64);
  - WINDOWBASE and WINDOWSTART;
  - PC, PS (INTLEVEL, EXCM, UM, RING, OWB, CALLINC, WOE), SAR, LBEG/LEND/LCOUNT;
  - BR, MR and ACCLO/ACCHI, FR and FCR/FSR, SCOMPARE1, ATOMCTL, THREADPTR;
  - the EPC/EPS/EXCSAVE and DEPC sets, EXCCAUSE/EXCVADDR, VECBASE;
  - INTERRUPT/INTENABLE, CCOUNT/CCOMPARE0-2, CPENABLE, MISC0-3, the region-protection attributes;
  - TIE state (later).
- **Exits:** Continue, Exception (cause), Waiti, Break and Simcall. The machine owns the vectors' targets, as with RISC-V `deliver_trap`.
- **Interrupts:** `set_interrupt_level(line, bool)`, with edge and level semantics per interrupt type. The pending check before fetch takes the highest level above `max(PS.INTLEVEL, EXCM ? EXCM_LEVEL : 0)`.
- **Windowed ABI:** a CALLn, ENTRY or RETW that needs a spill or reload raises the window overflow or underflow exception to the vector of its size (OF4/UF4/OF8/UF8/OF12/UF12), with the exact WINDOWSTART/WINDOWBASE and PS.OWB/CALLINC rules of the ISA manual. QEMU's `win_helper.c` serves as behaviour oracle only.
- **Loops:** a fetch at LEND with LCOUNT ≠ 0 decrements LCOUNT and branches to LBEG, unless PS.EXCM is set.
- **FP:** IEEE-754 single precision with the FCR rounding modes and FSR flags. Host `f32` operations are acceptable only where they give the specified rounding and NaN results. The `use_first_nan = 0` behaviour of the DFPU-single variant must match QEMU (`overlay_tool.h:541`).
- **Files:** the AGENTS.md §9.2 limits apply (1,500-line soft cap, 2,000 hard). Expected split: `decode/`, `cpu/{state,exceptions,interrupts,windows,loops,timers}.rs`, `execute/{alu,mem,branch,call,mac16,bool,fp,system,atomic}.rs`, `disasm.rs`, `config.rs`, `generated/`.

### 4.2 Decode: generated recognition, handwritten semantics

- **Generator:** `tools/xtensa/gen_isa` reads `core-esp32s3/xtensa-modules.inc.c` (MIT tables) and emits `src/isa/xtensa/generated/opcodes.rs`. Following Hexagon's `opcodes.rs`, that file holds:
  - the `Opcode` enum (753) and the names;
  - per format and slot, `(mask, value)` patterns;
  - operand field extractors, with their decode transforms (signed and scaled immediates, `b4const`, `ai4const`, PC-relative targets).
- **Two ways to build it:**
  - **(a)** Compile the tables with QEMU's `xtensa-isa.c` as a build-time tool, which never ships, and enumerate the encodings through the libisa API. That's Hexagon's `gen_semantics.c` approach.
  - **(b)** Parse the `Slot_*_decode` if-chains and the `Field_*` functions directly.
  - **(a) is preferred:** it relies on the same engine that defines the tables. The output is data, with a notice.
- **Inventory test:** for each opcode, assemble canonical operand sets with GNU `as`, decode them in rax and compare opcode and operands with `objdump`. Also sweep the whole 16-bit space and sampled 24- and 32-bit spaces against `objdump`. Results go to `tests/generated/xtensa/decode_*.json`, with a `manifest.toml` entry.
- **Semantics** are handwritten per family. Recognition and semantics stay separate change surfaces (AGENTS.md §8.10 precedent). An opcode without semantics raises IllegalInstruction and counts in the execution profile (§5.5).

### 4.3 Machine: `src/machine/esp32s3/` and `src/devices/esp32s3/`

**Shape:** the GSC/S5L8900 pattern.
- `Esp32s3Vcpu` wraps the Xtensa core and an `Esp32s3Bridge` that implements `xtensa::Memory`.
- The bridge does physical-address dispatch to RAM regions and device models, with instruction-count time and a private checkpoint context.
- Selection: `--arch xtensa` (a new `ArchKind`) with `RAX_MACHINE=esp32s3`, following the existing convention. Whether to add a CLI flag is decision D2.

**Memory map** (TRM, cross-checked with QEMU `hw/xtensa/esp32s3.c:91-105`):

| Region | Address | Size |
|---|---|---|
| Internal ROM (I-bus) | 0x40000000 | 384 KB |
| ROM (D-bus view) | 0x3FF00000 | 128 KB, = ROM + 0x40000 |
| Internal SRAM, I-bus view | 0x40370000 | 512 KB |
| Internal SRAM, D-bus view | 0x3FC80000 | 1,472 KB (0x170000) |
| RTC slow memory | 0x50000000 | 8 KB |
| RTC fast memory | 0x600FE000 | 8 KB |
| External flash/PSRAM via cache MMU, D-bus | 0x3C000000 | 32 MB |
| External flash/PSRAM via cache MMU, I-bus | 0x42000000 | 32 MB |
| Peripherals | 0x60000000–0x600D0FFF | — |

The internal SRAM gets one physical store with both views, per the TRM. That deviates from QEMU (assumption A3).

**Cache MMU:**
- 512 entries × 64 KB pages, as one table shared by the I and D windows, at 0x600C5000.
- Entry format: bits [13:0] page number, bit 14 invalid, bit 15 PSRAM.
- Flash is a backing image, with read-only fetch through the window.
- Unlike QEMU, flash writes through SPI1 are seen by the next fetch of a mapped page (QEMU only refreshes on remap; `hw/misc/esp32s3_cache.c:106-114`). Writes are rare enough to invalidate per page.

**Time:**
- Instruction-count based and deterministic (the GSC/S5L precedent): CCOUNT advances by one per instruction, at the rate the firmware set the CPU to (240 MHz after `esp-hal` init).
- SYSTIMER runs at 16 MHz and TIMG at its APB or XTAL source, both derived from the same count.
- WAITI fast-forwards to the next timer event (the S5L "idle" precedent).
- A host-clock mode is optional, for interactive use.

**Interrupt matrix:** 99 sources. The map registers at 0x600C2000 + 4·source select the CPU interrupt, where reset value 6 means disconnected. Each line is the OR of the levels mapped to it. FROM_CPU_INTR0-3 are sources 79-82.

### 4.4 Peripherals, in order of need

| Peripheral | Needed by | QEMU oracle | Notes |
|---|---|---|---|
| SYSTEM/clock, RTC_CNTL, APB_CTRL, analog `regi2c` (0x6000E000) | every `esp-hal` init | partial (clk, rtc_cntl; regi2c returns BBPLL done) | Reset cause, clock config, CPU frequency; PLL lock status |
| Interrupt matrix, SYSTIMER, TIMG0/1 (with watchdogs) | `esp-rtos`, embassy time | full | Watchdog resets wired, unlike QEMU (`esp32s3.c:846-873`) |
| UART0/1/2 | console, ASIC chain | full | FIFO, baud changes (the ASIC chain switches to 1 Mbaud, then higher) |
| USB-Serial-JTAG | `esp-println` default console | stub only | Functional model, TRM-based |
| EFUSE | MAC address, ADC calibration, chip revision | full (file-backed) | eFuse image file |
| Cache/EXTMEM, SPI1 flash controller, flash chip | code and rodata in flash, `esp-storage` (NVS, OTA) | full | Flash command set used by `esp_rom_spiflash_*` |
| GPIO, IO_MUX | buttons, enables, resets | strap only, none | TRM-based |
| I2C0/1 | board power and fan chips, OLED | none | TRM-based; device trait for slaves (§4.5) |
| GDMA, LCD_CAM | colour LCD boards | GDMA full, LCD_CAM none | LCD_CAM i80 mode, TRM-based |
| SAR ADC (APB_SARADC/RTC) | core voltage read-back | none | TRM-based, eFuse calibration |
| RNG | `esp-hal` RNG | host random | Deterministic seed for tests |
| OpenCores Ethernet MAC, 0x600CD000 | networking (§4.7) | full | QEMU routes its IRQ to source 0 |
| SHA/AES/RSA/HMAC/DS, PMS, TWAI, SDMMC, LEDC, RMT, … | not needed by the target | various | Unmapped-access reporting, so a missing model is visible instead of silently reading 0 |

An unmodelled peripheral access is logged with PC, address, width and value, and counted (the
S5L open-bus precedent), so missing models show up in the execution profile.

### 4.5 Board models (Bitaxe)

These are generic SoC extension points that the ESP32-S3 machine exposes:
- an `I2cSlave` trait on the I2C controllers;
- byte-stream endpoints on the UARTs;
- GPIO pin observers and drivers;
- an LCD_CAM i80 sink.

The board devices sit on top of them:
- TPS546 (PMBus), EMC2101/EMC2103/EMC2302, TMP1075, INA260, DS4432;
- SSD1306 (I2C OLED) and ST7789 (i80 LCD, framebuffer dumped to PNG);
- the BM13xx ASIC chain on UART1. The chain model answers chip-address enumeration and register reads and writes, takes jobs, and returns real nonces: it searches the job's nonce space with SHA-256d up to a configurable share difficulty. So the share path of the firmware gets exercised. It reuses the `bm13xx-protocol` crate for frames.

Where these board models live is decision D1.

### 4.6 ROM

Two modes:
- **Real ROM image:** `RAX_ESP32S3_ROM=<path>`, loaded at 0x40000000 with its D-bus view. Every ROM function works, provided the peripherals it touches are modelled (SPI1 for flash, `regi2c` for analog). This mode is required for the full flash boot.
- **HLE table:** native implementations at the ROM addresses of the functions listed in §3.2, when no image is given:
  - libgcc arithmetic on host integers and IEEE f64;
  - libc routines and `crc32_le`/MD5;
  - flash routines on the backing image;
  - `ets_delay_us` advancing time;
  - cache routines updating the MMU.

  Any other ROM address faults with its name, from the ROM ELF symbol list where available. The HLE table removes the ROM licensing question for CI, and the real-ROM mode is its oracle.

### 4.7 Networking

WiFi isn't emulated: the radio and PHY are closed blobs, and QEMU doesn't emulate them either.
- **Device:** model the OpenCores Ethernet MAC at QEMU's address and IRQ, with QEMU's model as oracle.
- **Host side:** add a host network backend to rax. Linux TAP, or a user-mode NAT built on `smoltcp` that needs no privileges (decision D5).
- **Firmware side:** `esp-miner-rs` gets an `emulator` build feature that replaces `esp-radio` with an `embassy-net` driver for that MAC. ESP-IDF's Apache-2.0 `esp_eth_mac_openeth` serves as the reference for its behaviour.

## 5. Oracle and test strategy

### 5.1 Encoding

GNU binutils of the esp toolchain, recorded per §4.2. These are inventory checks, not semantics
(policy claim class).

### 5.2 ISA execution (Cortex-M precedent)

- **Harness:** `tools/xtensa-diff/` builds one bare-metal oracle image with the esp toolchain. It loads each case's input state (AR window state, SAR, LBEG/LEND/LCOUNT, BR, FR/FCR/FSR, ACC/MR, PS subset), executes the case instruction from IRAM and dumps the output state.
- **Running it:** QEMU runs it with `qemu-system-xtensa -M esp32s3 -nographic -kernel oracle.elf -serial stdio` (no ROM needed: the image doesn't call it), and the results come back over UART0.
- **Recording and replay:** results are recorded in `tests/generated/xtensa/isa_oracle.json`, with provenance in `manifest.toml`, and replayed by library tests against the rax core.
- **Families:**
  - ALU and shifts, including SAR forms;
  - loads and stores at all widths, alignments and `addmi` forms;
  - branches and jumps, placed at controlled PCs so that PC-relative results compare;
  - CALLn/ENTRY/RETW, including forced window overflow and underflow;
  - loops at the LEND boundary;
  - MUL/DIV, including divide-by-zero (IntegerDivideByZero exception);
  - MAC16 and booleans;
  - FP, with every rounding mode and NaN/Inf/denormal operands;
  - S32C1I with ATOMCTL;
  - exceptions (illegal, alignment where enabled, privileged), recording cause, EPC and EXCVADDR.
- **Evidence:** the AGENTS.md §11.3 requirements apply: nonzero counts, QEMU found, cases run, skips understood, no masked fields.
- **Gaps:** the four QEMU-unimplemented opcodes, and later the PIE `ee.*` state, are checked on real hardware. The same image runs on a Bitaxe through probe-rs, with results read from RAM.

### 5.3 Machine lockstep (new in rax)

- **Tool:** `tools/xtensa-lockstep/` runs one image in QEMU (`-accel tcg,one-insn-per-tb=on -icount shift=0 -d cpu,nochain`) and in rax with an equivalent per-instruction trace. It reports the first divergence: instruction index, PC, and the differing registers.
- **What it covers:** the ROM-free images of M3 (built with HLE disabled where they call the ROM), then the full flash boot under both emulators once M7's boot path exists.
- **Trace content:** QEMU's `-d cpu` dump has PC, every sysreg, A0-15, AR0-63 and FR, but no TIE state (`target/xtensa/translate.c:1211`).
- **Time:** both sides run deterministic instruction-count time. QEMU's fixed 40 MHz CCOUNT has to be accounted for on the rax side, or CCOUNT reads masked in the comparison and stated.

### 5.4 Peripherals

- **Where QEMU has a model** (UART, SYSTIMER, TIMG, interrupt matrix, cache MMU, SPI1, GDMA, EFUSE, OpenCores MAC): register-level tests in rax, plus lockstep runs of driver-heavy `esp-hal` examples.
- **Where it doesn't** (I2C, LCD_CAM, ADC, IO_MUX, USB-Serial-JTAG): the TRM, plus captures from real boards. The workspace already holds logic-analyzer captures of Bitaxe I2C and UART traffic, and the `bitaxe-raw` USB bridge firmware runs on real ESP32-S3 boards.

### 5.5 Execution profile

A per-run report:
- opcodes executed, with counts;
- unimplemented opcodes hit;
- unmodelled MMIO accesses, by address;
- ROM functions called, in HLE mode.

It replaces static mnemonic counts (§3.2) as the measure of what a firmware needs.

## 6. Phases

Sizes are rough, calibrated on `src/isa/riscv` (22,735 lines), `src/machine/gsc` (5,426),
`src/machine/s5l8900` + devices (13,434) and their tests.

| Phase | Deliverable | Closes | Oracle | Size |
|---|---|---|---|---|
| P0 | Tooling: reproducible build of `qemu-system-xtensa` from `upstream/qemu-espressif` (nix shell: glib, pixman, libgcrypt, slirp, meson, ninja; `--target-list=xtensa-softmmu --enable-gcrypt --enable-slirp`); ROM acquisition notes; esp toolchain for test images; spec retrieval records | — | — | scripts, docs |
| P1 | `ArchKind::Xtensa` registration (§7), `XtensaConfig` for the ESP32-S3, generator and generated tables, decoder, disassembler, decode inventory | M1 | binutils | 3-5k Rust + generated + 1k tools |
| P2 | Core semantics: base ISA, windows, loops, MUL/DIV, MAC16, booleans, S32C1I/ATOMCTL, special registers, XEA2 exceptions and interrupts, CCOUNT/CCOMPARE, WAITI, region protection, single-precision FP | M2 (unit) | ISA manual | 8-12k |
| P3 | `tools/xtensa-diff` oracle image, recorded corpus, replay tests | M2 | QEMU, real hardware for the gaps | 2-3k + corpus |
| P4 | `esp32s3` machine: memory map with SRAM aliases, ROM modes, ELF boot (sections into SRAM, flash-resident segments into the backing image plus MMU entries, as the 2nd-stage bootloader leaves them), cache MMU, SPI1 + flash, interrupt matrix, SYSTEM/RTC/APB/regi2c, SYSTIMER, TIMG, UART, USB-Serial-JTAG, EFUSE, RNG, RTT reader (defmt up-buffer at the `_SEGGER_RTT` symbol), MMIO report | M3 | QEMU devices, TRM | 6-9k |
| P5 | Lockstep tool, run on the M3 images | M4 | QEMU | 1-2k |
| P6 | GPIO/IO_MUX, I2C, ADC, GDMA + LCD_CAM; board extension points; Bitaxe board models including the BM13xx chain | M5 | TRM, real-board captures | 5-8k |
| P7 | OpenCores MAC, host network backend, firmware `emulator` feature | M6 | QEMU MAC | 2-4k + firmware |
| P8 | Full flash boot, OTA, APP_CPU, PIE `ee.*` (QEMU's `translate_tie_esp32s3.c` as behaviour oracle), Xtensa GDB server (registers from `gdb-config.inc.c`), optional SMIR lifter | M7 | QEMU, real hardware | open |

P1-P3 can proceed in parallel with P0. P4 needs P2. P6 needs P4, and P7 needs P4 too.

## 7. Change-surface map (registration points)

| Plane | Status | Where |
|---|---|---|
| ISA module | affected | `src/isa/mod.rs`, new `src/isa/xtensa/` |
| Architecture kind and CLI | affected | `src/config/kinds.rs` `ArchKind`; `src/config/runtime.rs` (ELF e_machine 94 → Xtensa, default backend, emulator-only validation, memory checks) |
| Backend | affected | `src/backend/emulator/mod.rs` `create_vcpu`; `checkpoint_machine.rs` `MachineFamily` + `RAX_MACHINE` |
| Machine | outside rax | the `esp32s3-emu` crate of bitaxe-emu-rs; a later `from_arch_kind` registration would wrap it |
| VM runtime | affected | `src/vm/runtime.rs` `null_boot_info` and serial choice; `src/vm/vcpu/state.rs` `CpuState` (serde: compatibility surface) and `pc()` |
| Snapshot | affected | `src/vm/snapshot/backend_context.rs`: next free context number (13) |
| Devices | outside rax | the `esp32s3-emu` crate of bitaxe-emu-rs |
| SMIR lift/IR/interpreter/optimizer/lowering/JIT | unaffected | interpreter-only first. A Xtensa block never reaches SMIR, so lowering can't admit it (AGENTS.md §6) |
| Static oracle, C ABI | deferred | `src/oracle/mod.rs` `OracleIsa`; `capi` `rax_arch` (next value 7). Optional, after M2 |
| GDB | deferred | `src/debug/gdb/` is x86-64 only; P8 |
| Tests/CI | affected | `[[test]]` entries; `tests/suites/{isa,differential,machine}/xtensa*`; `tests/generated/xtensa/` + manifest; CI shard |
| Docs/notices | affected | `docs/specifications/xtensa/`, `docs/hardware/espressif/esp32s3/`, `docs/architecture/{machines,devices}.md`, `THIRD_PARTY_NOTICES.md` and its `capi/` copy, `tools/licensing/check.py` |

## 8. Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | Rust/LLVM code for `xtensa-esp32s3-none-elf` emits no `ee.*` | §3.2 sampling: the `ee.*` hits are data | PIE deferred to P8 | `esp-dsp`-style intrinsics or ROM code using PIE | Execution profile of M3/M5 runs reports zero `ee.*` executed | retained |
| A2 | QEMU's base Xtensa semantics are reliable for the options listed in §3.1 | Upstream QEMU Xtensa target, long maintained | P3 corpus as truth | FP NaN propagation, window exceptions, loop + EXCM interaction | Sample of corpus cases on a real Bitaxe; any disagreement goes to a documented deviation list (Cortex-M precedent) | retained |
| A5 | The Tensilica tables may be redistributed in generated form | MIT-style header in `xtensa-modules.inc.c` and `core-isa.h` | P1 generator output checked in | A file in the core directory without that notice | `tools/licensing/check.py` and a manual header check of every input file | retained |
| A8 | Board models can live outside the rax tree, using rax as a library | rax is a library crate with public APIs | D1 option | Private types needed for extension | Build a crate against the branch | held: the SoC and board crates of bitaxe-emu-rs build against the public `rax::isa::xtensa` API |

## 9. Decisions for the maintainer

- **D1 — where the Bitaxe board models live.**
  - (a) In the rax fork as an `esp32s3-bitaxe` machine variant: simpler, but it keeps the fork diverged from HexRaysSA.
  - (b) In a separate crate in this workspace that uses rax as a library: keeps the rax branch upstreamable.
  - Recommended: (b), if A8 holds.
  - Decided (2026-11-20): (b), extended to the SoC: the machine and devices left rax too, for the crate `esp32s3-emu` of bitaxe-emu-rs.
- **D2 — machine selection.**
  - (a) `RAX_MACHINE=esp32s3`, the current convention for the ARM and RISC-V SoCs.
  - (b) A new CLI flag, which touches a public interface.
  - Recommended: (a).
- **D3 — ROM.** Both modes as in §4.6, or the real-ROM mode only, which is less work but needs the ROM file on every CI runner.
- **D4 — upstream target.** Whether the branch aims at a HexRaysSA pull request (all AGENTS.md provenance and test rules from the first commit), or stays a fork feature.
- **D5 — host networking.**
  - (a) TAP: simple, but needs privileges.
  - (b) User-mode NAT with `smoltcp`: no privileges, more code.

## 10. Out-of-scope findings

| Impact | Finding | Evidence | Blocks |
|---|---|---|---|
| Medium | QEMU `esp32s3-intmatrix-test` labels `SHA_SOURCE 81`, but the enum value is 78 | QEMU tests/qtest; `include/hw/xtensa/esp32s3_intc.h` | no |
| Low | QEMU's gdbstub for Xtensa has no target XML. Plugins' `reg=` logging gets no registers on Xtensa | `gdbstub/gdbstub.c:496-519` | no: the lockstep uses `-d cpu` |
