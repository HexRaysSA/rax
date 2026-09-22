# Ti50 GSC MMIO — static verification vs ti50.bin.prod.c (2026-06-26)

Durable record of the exhaustive multi-agent MMIO verification pass. Companion to mmio.md / HANDOVER.md.

---

## Static verification pass vs `ti50.bin.prod.c` (2026-06-26)

An exhaustive agent sweep cross-checked every MMIO claim above against the Ti50 production pseudocode dump (`ti50.bin.prod.c`). Findings were adversarially re-verified. Provenance legend: absolute `MEMORY[]`, decimal-encoded absolute, or base+offset (peripheral base is a RAM pointer; only the offset is provable). Each row cites the bank-A function(s) that prove it.

### Block-identity corrections (high impact)

- **`0x400C0000` is a TIMER / 64-bit counter block, not Console/UART.** `sub_8072E` reads `__PAIR64__(0x400C001C, 0x400C0014)` and divides by 256 when prescale `0x400C0010==0`; `0x400C0038`=period/reload, `0x400C0078`=busy/ready, `0x400C0000`=enable.
- **`0x40250000` is a DRBG/CSRNG/keymgr block, not "Flash/protection".** control `0x40250000`(arm 0x7), command `0x4025001C`(0=instantiate/4=reseed-fuses/3=reseed-flash/1=generate), start `0x40250014`, 256-bit seed/perso/output files at `0x40250024/0x40250044/0x402500E8`. Handoff magic at `0x40250064`/`0x40250084` is **`0xC7D40497`** (−942406505); the old `0xC7D1BD97` was wrong.
- **`0x40200000`/`0x40204000` is a 256-bit crypto verify engine (likely the unresolved Ti50 DCRYPTO).** `sub_80608` loads 5 operands (`0x40204060/80/A0/C0/E0`), commands `0x080002A3` at `0x40200038`, reads digest `0x40204040`, XOR-compares to expected hash.
- **`0x400E0000` is a programmable engine + line-IRQ, not a "USB event/reset wrapper".** control `+0xD4`, mode `+0xD8`(0x21F), data `+0xDC`, status `+0x154`(polled), config table `+0x108..+0x124`; its IRQ line is bit20 of `0xE000E00C`.
- **RBOX `0x40090000`:** base is a RAM pointer; only controls `+0x44`/`+0x48` and status `+0x54` (via `sub_A4774`/`sub_A4712`) are verifiable. The interrupt-group/descriptor rows and the function `sub_B6948` **do not exist in this dump** (those VAs are in an undecompiled gap). `sub_99A40` likewise does not exist (its VA is inside `sub_99A1E`).
- **Chip ID:** `0x4001ffe0`/`0x4001fff8` are **not** accessed in this image and `0x8485694d` appears nowhere; `0x4001FFE4` is the boot/RO-update status word.
- **Flash opcodes present here:** READ `0x16021765`, Ti50 PROGRAM `0xe89d48b7`. **Absent** (Cr50/family reference only): Cr50 PROGRAM `0x27182818`, ERASE `0x31415927`, BULK `0x1D1E2BAD` (erase is `TRANS=sub_9F9AC(desc,cmd=3)`, no magic opcode).
- **`0x400301B0/B4/B8/BC`** are generic pad-control array entries (indexed by `sub_A4E04`); no I2C evidence. **`0x4000004C`** is persistent PMU scratch/EXITPD software-flag bits, not a clock gate.

### Corrected registers

| Address | Evidence (funcs) | Function |
|---|---|---|
| `0x4000004C` | sub_806D6, sub_9026C, sub_904EA | 0x4000004C = persistent PMU scratch/state register (EXITPD); firmware stores sticky software flags in bit30 (set by sub_806D6, read by sub_9026C) and bit31 (set by sub_92834) and rewrites it 0x40000000 in the reset path — software state flags, not a clock-e… |
| `0x400301B0` | sub_A479A, sub_A4E04, sub_A4DC8 | 0x400301B0: pad-control register (entry 0 of array 0x1B0/B4/B8/BC indexed by sub_A4E04), RW; sub_A479A sets bit 0x4, sub_A4DC8/sub_A4DEE program a drive/mode field, sub_A4E90 reads bits 0x8/0x10. No code evidence of I2C. |
| `0x400301B4` | sub_A479A, sub_A4E04, sub_A4DC8 | 0x400301B4: pad-control register (entry 1 of array indexed by sub_A4E04), RW; sub_A479A sets bit 0x4, sub_A4DC8/sub_A4DEE program a field, sub_A4E90 reads bits 0x8/0x10. No code evidence of I2C. |
| `0x400301BC` | sub_A479A, sub_A4E04, sub_9EF22 | 0x400301BC: pad-control register (entry 3/default of array indexed by sub_A4E04), RW; sub_A479A sets bit 0x4, sub_9EF22 writes it as base of an indexed store (0x400301BC + 4*idx). No code evidence of I2C. |
| `0x40030484` | sub_A2ED0 | 0x40030484: GPIO interrupt/status word, write-only write-1-clear; sub_A2ED0 stores 0xFFFFFFFF to clear all pending bits (never read in this dump). |
| `0x40030488` | sub_A2ED0 | 0x40030488: GPIO interrupt/status word, write-only write-1-clear; sub_A2ED0 stores 0xFFFFFFFF (paired with 0x40030484) to clear all pending bits. |
| `0x40090000` | sub_A4774, sub_A4712, sub_AD798 | 0x40090000 (RBOX base) is a RAM-struct pointer, never a literal in the dump; the cited container sub_B6948 does not exist and VA 0xb6948 lies in an undecompiled gap (between stub sub_B3206 @0xB3206 and sub_B933A @0xB933A), so the only provable RBOX accessor… |
| `0x400C0000` | sub_806D6, sub_904EA | Timer/counter block control-enable register: written 0 to disable then 1 to enable, bracketing (re)configuration in sub_806D6 (init) and sub_904EA (pre-halt); not a console/UART register (the live console UART is 0x404D0000). |
| `0x400C0004` | sub_806D6 | Timer-block config register cleared to 0 during init (sub_806D6); not console/UART; specific field (interrupt-enable vs mode) is unsupported by this dump. |
| `0x400C0010` | sub_806D6, sub_8072E, sub_904EA | Timer prescale/scaling-mode register: init writes the constant 261 (0x105) (sub_92C84 returns 261 ignoring its arg, not a computed clock divisor); pre-halt writes 0; sub_8072E reads it and, when 0, right-shifts the 64-bit counter by 8 (/256). |
| `0x400C0020` | sub_806D6, sub_904EA | Timer-block config/compare register cleared to 0 during init (sub_806D6) and pre-halt (sub_904EA); not a console/UART FIFO register; specific field unknown. |
| `0x400C0028` | sub_806D6, sub_904EA | Timer-block config/compare register cleared to 0 during init (sub_806D6) and pre-halt (sub_904EA); not a console/UART FIFO register; specific field unknown. |
| `0x400C002C` | sub_806D6 | Timer-block register written 0xFFFFFFFF (-1) at init (sub_806D6); likely an interrupt/compare mask or W1C clear set to all-ones; not console/UART; exact field unknown. |
| `0x400C0034` | sub_806D6 | Timer-block register written 0xFFFFFFFF (-1) at init (sub_806D6); likely a mask/compare-max field; not console/UART; exact field unknown. |
| `0x400C0038` | sub_904EA | Timer period/reload register written in pre-halt path (sub_904EA): 256 when arg==0, else 256000*arg; armed before the block is enabled and the core enters _wfi(). |
| `0x400C0040` | sub_904EA | Timer-block config register cleared to 0 in pre-halt path (sub_904EA); not console/UART; specific field unknown. |
| `0x400C0060` | sub_904EA | Timer-block config register written 2 in pre-halt path (sub_904EA); not a console/UART FIFO watermark; specific field unknown. |
| `0x400C0068` | sub_904EA | Timer-block config register written 2 in pre-halt path (sub_904EA); not a console/UART FIFO watermark; specific field unknown. |
| `0x400C0078` | sub_904EA | Timer-block status register polled (busy/ready) in pre-halt path (sub_904EA): spins while bit 0x10 set, while bit 0x4 set, and while any bit other than bit0 is set ((val\|1)!=1); not console/UART. |
| `0x400E0000` | sub_A2B50, sub_110278, sub_91D0A | 0x400E0000 is the 0x400E-block base address (returned by sub_A2B50); register offset 0 is written 0 during init (reset/disable) and registered in the MMIO integrity-shadow table. |
| `0x400E00D4` | sub_A2B50, sub_120A32, sub_122010 | Engine control/start register: init=1; written a command value (v6) to trigger each operation and re-armed after polling status 0x400E0154. |
| `0x400E00D8` | sub_A2B50, sub_120A32, sub_122010 | Engine mode/config register: init=0; written 0x21F (543) before each operation. |
| `0x400E00DC` | sub_A2B50, sub_120A32, sub_122010 | Engine data register: init=0; written the operation command value v6 before launching an operation. |
| `0x400E0154` | sub_A2B50, sub_120A32, sub_122010 | Engine STATUS register: init set to -1, then READ at runtime with bit0 (&1) and bit1 (>>1) tested to branch on operation done/result. |
| `0x40100138` | sub_9083A | 0x40100138 = GLOBALSEC instance-1 region-2 reconfigure/commit gate flag; cleared (0) after region-2 window (base 0x40100280 / size 0x40100284 / perm 0x40100158) is programmed during RW handoff. |
| `0x40100154` | sub_91088, sub_9309E | 0x40100154 = GLOBALSEC instance-1 region-1 permission word; written 3 (RW) by sub_91088 when arming region-1 (base 0x40100278/size 0x4010027C), cleared (0) in fatal panic. |
| `0x40100158` | sub_9083A, sub_91428, sub_9309E | 0x40100158 = GLOBALSEC instance-1 region-2 permission word; written 3 (RW) by sub_9083A and 7 (RWX) by sub_91428 (each after setting region-2 base/size 0x40100280/0x40100284), cleared (0) in fatal panic. |
| `0x4010416C` | sub_A466A | Control register in the 0x40104xxx fatal/reset/PMU block; init routine sub_A466A sets bits 0x28000 via read-modify-write (`\|= 0x28000`); specific function unattested by this dump. |
| `0x40200034` | sub_80608, sub_9083A | 0x40200034: control/clear register in the 0x40200000 crypto/protection block, written all-ones (-1) both during sub_80608 crypto-verify arming and as a finalize/lock write in sub_9083A just before the image jump (attribution to sub_9083A alone is incomplete… |
| `0x40210054` | sub_9083A, sub_91D0A | 0x40210054: control register written 0x30 (48) then committed with value 2; sub_91D0A is an anti-glitch SHADOW recorder (stores value^0x34687195 for later re-verification), so the value 2 is the recorded expected/commit value, not a hardware read-back check. |
| `0x40250010` | sub_80434, sub_9083A | 0x40250010 = DRBG/CSRNG status/done handshake register (RW, bits[2:0]); sub_80434 polls it for completion and writes back the masked value (W1C) to clear; sub_9083A writes 0xFFFFFFFF to clear all status before jump-to-RW. Not a flash-protection lock. |
| `0x40250064` | sub_80504, sub_80488, sub_9083A | 0x40250064 = DRBG/CSRNG 256-bit reseed-from-flash input block (sub_80504); sub_9083A also writes magic 0xC7D40497 (= signed -942406505) here during pre-jump handoff. The doc's hex 0xC7D1BD97 is wrong; -942406505 = 0xC7D40497. |
| `0x4025006C` | sub_9083A | 0x4025006C = word in the 0x40250000 DRBG/keymgr block; sub_9083A writes image-header field *(image+392) (plausibly image base) here during the pre-jump handoff. |
| `0x40250084` | sub_9083A | 0x40250084 = block word; sub_9083A writes magic 0xC7D40497 (= -942406505), same as 0x40250064. (Doc's 0xC7D1BD97 hex is wrong.) |
| `0x4025008C` | sub_9083A | 0x4025008C = block word; sub_9083A writes image-header field *(image+392), duplicating 0x4025006C, during pre-jump handoff. |
| `0x402500AC` | sub_9083A | 0x402500AC = block word; sub_9083A writes *(image+392)+*(image+864) (image base + length, an upper boundary) during pre-jump handoff. Block is the DRBG/keymgr region, not a separate 'Flash/protection' unit. |
| `0x40450280` | sub_9281A, sub_92834 | 0x40450280: OTP/fuse flag (bit0, read-only) tested by sub_9281A which returns 1 when bit0 is set (else (0x4001FFE4 & 1)); the gated sub_92834 UART/diagnostic path runs only when that predicate is 0, so bit0 set SUPPRESSES it (lockout/disable), not enable. |
| `0x404D0014` | sub_928D0, sub_928EE, sub_92930 | 0x404D0014: Console UART STATE/status register (read); bit0 clear = TX ready (sub_928D0), bit7 clear = RX byte available (sub_92930), and bits 4-5 (mask 0x30) both set = ready/idle gate checked by sub_928EE. |
| `0x4062001C` | sub_920B0, sub_A2A02 | 0x4062001C is a writable TX-FIFO counter (second/denominator field of console 'tx %d/%d') that sub_A2A02 zeroes during TPM-SPI reset; calling it a 'limit/depth' is dubious since a static depth would not be cleared to 0 on reset. |
| `0xE000E02C` | sub_A2B50, sub_A4F40 | `0xE000E02C` (sub_A2B50, sub_A4F40): core-local interrupt-control register written one-hot line masks during 0x400E0000-peripheral init/teardown - `0x100000` (bit20) in sub_A2B50 and `0x80000` (bit19) in sub_A4F40; no timer evidence. |
| `0xE000E0E0` | sub_9083A | `0xE000E0E0` (sub_9083A): core next-stage entry-point/boot-address handoff register; written the RW image entry (`image_base + 0x400`, logged `jump @`) immediately before mtvec is set via CSR and the core jumps (`c.jr t0`) - it holds the entry address, not … |

### Newly discovered registers

| Address | Evidence (funcs) | Function |
|---|---|---|
| `0x400C0014` | sub_8072E | Low 32 bits of the 64-bit free-running timer/counter, read as the low half of __PAIR64__ in sub_8072E (read-current-time helper used for timeout deadlines). |
| `0x400C001C` | sub_8072E | High 32 bits of the 64-bit free-running timer/counter, read as the high half of __PAIR64__ in sub_8072E. |
| `0x400E0008` | sub_110278 | 0x400E0008: 0x400E-block config word written 3 during init and registered in the MMIO integrity-shadow table. |
| `0x400E00C4` | sub_110278 | 0x400E00C4: 0x400E-block config word written 3 during init and registered in the MMIO integrity-shadow table. |
| `0x400E00C8` | sub_120A32, sub_122010 | 0x400E00C8: 0x400E-block up/down counter register; seeded from a RAM value &0x3FF then read-modify-written by +/-1 depending on status 0x400E0154. |
| `0x400E00CC` | sub_120A32, sub_122010 | 0x400E00CC: 0x400E-block config/data register written a computed value during per-operation programming. |
| `0x400E00E8` | sub_120A32, sub_122010 | 0x400E00E8: 0x400E-block data word written during per-operation programming. |
| `0x400E00EC` | sub_120A32, sub_122010 | 0x400E00EC: 0x400E-block data word written during per-operation programming. |
| `0x400E00F0` | sub_120A32, sub_122010 | 0x400E00F0: 0x400E-block config word written constant 0x17340 (95040) before each operation. |
| `0x400E00F4` | sub_120A32, sub_122010 | 0x400E00F4: 0x400E-block config word written constant 0x176A0 (95904) before each operation. |
| `0x400E00F8` | sub_120A32, sub_122010 | 0x400E00F8: 0x400E-block config word written constant 0x17760 (96096) before each operation. |
| `0x400E00FC` | sub_120A32, sub_122010 | 0x400E00FC: 0x400E-block data word written during per-operation programming. |
| `0x400E0100` | sub_120A32, sub_122010 | 0x400E0100: 0x400E-block data word written during per-operation programming. |
| `0x400E0104` | sub_120A32, sub_122010 | 0x400E0104: 0x400E-block data word written during per-operation programming. |
| `0x400E0108` | sub_120A32, sub_122010 | 0x400E0108: 0x400E-block config word written constant 17 (0x11) before each operation. |
| `0x400E010C` | sub_120A32, sub_122010 | 0x400E010C: 0x400E-block config word written constant 50 (0x32) before each operation. |
| `0x400E0110` | sub_120A32, sub_122010 | 0x400E0110: 0x400E-block config word written constant 34 (0x22) before each operation. |
| `0x400E0114` | sub_120A32, sub_122010 | 0x400E0114: 0x400E-block config word written constant 18 (0x12) before each operation. |
| `0x400E0118` | sub_120A32, sub_122010 | 0x400E0118: 0x400E-block config word written constant 0 before each operation. |
| `0x400E011C` | sub_120A32, sub_122010 | 0x400E011C: 0x400E-block config word written constant 19 (0x13) before each operation. |
| `0x400E0120` | sub_120A32, sub_122010 | 0x400E0120: 0x400E-block config word written constant 35 (0x23) before each operation. |
| `0x400E0124` | sub_120A32, sub_122010 | 0x400E0124: 0x400E-block config word written constant 51 (0x33) before each operation. |
| `0x400E0128` | sub_120A32, sub_122010 | 0x400E0128: 0x400E-block data/command register written the operation command value v6 (mirrors 0x400E00DC/0x400E00D4). |
| `0x400E0144` | sub_120A32, sub_122010 | 0x400E0144: 0x400E-block config word written constant 3 before each operation. |
| `0x400E014C` | sub_120A32, sub_122010 | 0x400E014C: 0x400E-block config word written constant 3 before each operation. |
| `0x40100040` | sub_9127A, sub_913C0 | 0x40100040 = GLOBALSEC instance-0 region-0 permission word (0=off/1=R/3=RW/5=RX/7=RWX); paired with base 0x40100180 / size 0x40100184. |
| `0x40100044` | sub_9127A, sub_913C0 | 0x40100044 = GLOBALSEC instance-0 region-1 permission word; paired with base 0x40100188 / size 0x4010018C. |
| `0x40100048` | sub_9127A, sub_913C0 | 0x40100048 = GLOBALSEC instance-0 region-2 permission word; paired with base 0x40100190 / size 0x40100194. |
| `0x40100134` | sub_91088 | 0x40100134 = GLOBALSEC instance-1 region-1 reconfigure gate flag (read as 'request pending'; when nonzero firmware reprograms region-1 base/size 0x40100278/27C + perm 0x40100154, then writes 0 to clear). |
| `0x40100150` | sub_9FA72, sub_9FB5E | 0x40100150 = GLOBALSEC instance-1 region-0 permission word and base of the 8-entry control array (0x40100150+4N), paired 1:1 with the {base,size} descriptor array at 0x40100270+8N. |
| `0x40100180` | sub_9127A | 0x40100180 = GLOBALSEC instance-0 region-0 window base (set 0x107C0); paired with size 0x40100184 and permission word 0x40100040. |
| `0x40100184` | sub_9127A | 0x40100184 = GLOBALSEC instance-0 region-0 window size (set 0x20 = 32 bytes); paired with base 0x40100180 and permission 0x40100040. |
| `0x40100188` | sub_9127A | 0x40100188 = GLOBALSEC instance-0 region-1 window base (set 0x10980); paired with size 0x4010018C and permission 0x40100044. |
| `0x4010018C` | sub_9127A | 0x4010018C = GLOBALSEC instance-0 region-1 window size (set 0x20 = 32 bytes); paired with base 0x40100188 and permission 0x40100044. |
| `0x40100190` | sub_9127A | 0x40100190 = GLOBALSEC instance-0 region-2 window base (set 0x11960); paired with size 0x40100194 and permission 0x40100048. |
| `0x40100194` | sub_9127A | 0x40100194 = GLOBALSEC instance-0 region-2 window size (set 0x20 = 32 bytes); paired with base 0x40100190 and permission 0x40100048. |
| `0x401001D0` | sub_BD7DC | 0x401001D0 = read-only HW/ROM pointer to the alternate cryptolib image base (selected when caller bit a2&1 is set); magic 0xCA11AB1E validated at base+0x1008. |
| `0x40100278` | sub_91088 | `0x40100278` GLOBALSEC region[1] window BASE (set to 32-byte-aligned addr by sub_91088; ctrl at 0x40100154). |
| `0x4010027C` | sub_91088 | `0x4010027C` GLOBALSEC region[1] window SIZE (written 2048 by sub_91088). |
| `0x401002BC` | sub_9100E | `0x401002BC` GLOBALSEC region window register cleared to 0 by sub_9100E during window teardown (likely region[9] SIZE). |
| `0x401002DC` | sub_9100E | `0x401002DC` GLOBALSEC region window register cleared to 0 by sub_9100E during window teardown (likely region[13] SIZE). |
| `0x40100300` | sub_9100E | `0x40100300` GLOBALSEC region[18] window BASE cleared to 0 by sub_9100E (window disable). |
| `0x40100304` | sub_9100E | `0x40100304` GLOBALSEC region[18] window SIZE cleared to 0 by sub_9100E (window disable). |
| `0x40200038` | sub_80608 | 0x40200038: crypto-0x400E-block command/trigger register; written 0x080002A3 (134218403) by sub_80608 after loading operands and clearing 0x40200034, launching the verify computation read back at 0x40204040. |
| `0x40204000` | sub_80608 | 0x40204040-0x4020405C (base 0x40204000): 256-bit crypto-0x400E-block digest/result output array; sub_80608 reads all 8 words and XOR-compares them against the expected hash to verify a signature/hash. |
| `0x40204060` | sub_80608, sub_80746 | 0x40204060: 256-bit crypto-0x400E-block operand input register; sub_80608 writes 32 bytes (operand a3) into it via the sub_80746 word-copy before issuing the verify command. |
| `0x40204080` | sub_80608, sub_80746 | 0x40204080: 256-bit crypto-0x400E-block operand input register; sub_80608 writes 32 bytes (operand a4) via sub_80746. |
| `0x402040A0` | sub_80608, sub_80746 | 0x402040A0: 256-bit crypto-0x400E-block operand input register; sub_80608 writes 32 bytes (operand a5) via sub_80746. |
| `0x402040C0` | sub_80608, sub_80746 | 0x402040C0: 256-bit crypto-0x400E-block operand input register; sub_80608 writes 32 bytes (operand a1) via sub_80746. |
| `0x402040E0` | sub_80608, sub_80746 | 0x402040E0: 256-bit crypto-0x400E-block operand input register; sub_80608 writes 32 bytes (operand a2) via sub_80746. |
| `0x40250000` | sub_80504 | 0x40250000 = DRBG/CSRNG 0x400E-block control register (write-only); sub_80504 writes 0x7 to arm the 0x400E-block before loading seed material. |
| `0x40250014` | sub_80434 | 0x40250014 = DRBG/CSRNG start/trigger register (write-only); sub_80434 writes 0x1 to launch the op selected in 0x4025001C. |
| `0x4025001C` | sub_80504, sub_805C0 | 0x4025001C = DRBG/CSRNG command/mode register (write-only): 0=instantiate, 4=reseed-from-fuses, 3=reseed-from-flash, 1=generate. |
| `0x40250024` | sub_80504, sub_80488, sub_80476 | 0x40250024 (32 bytes) = DRBG/CSRNG 256-bit seed/entropy input register file; loaded with caller seed or default 0x44414544 ('DEAD'), then TRNG-wiped after use. |
| `0x40250044` | sub_80504, sub_80488, sub_80476 | 0x40250044 (32 bytes) = DRBG/CSRNG 256-bit personalization/additional-input register file; caller value or default 0x55555546. |
| `0x402500C8` | sub_80504, sub_80488, sub_8044E | 0x402500C8 (32 bytes) = DRBG/CSRNG 256-bit input register file (second seed buffer); loaded via sub_80488, TRNG-wiped via sub_8044E after use. |
| `0x402500E8` | sub_805C0, sub_80488 | 0x402500E8 (32 bytes) = DRBG/CSRNG 256-bit generated-output register file; read out after a generate (0x4025001C=1) operation. |
| `0x40520004` | sub_A3D1C | 0x40520004 (GPIO bank0 +0x04): write of bare pin mask (1<<pin) in the pin-config routine sub_A3D1C; per-bank register repeated at base+0x04. |
| `0x40520008` | sub_A3D92 | 0x40520008 (GPIO bank0 +0x08): single-pin mask write (1<<pin) by sub_A3D92; per-bank register at base+0x08. |
| `0x4052000C` | sub_A3D1C | 0x4052000C (GPIO bank0 +0x0C): unconditional pin-mask write (1<<pin) in sub_A3D1C; per-bank register at base+0x0C. |
| `0x40520014` | sub_A265C, sub_A3D1C | 0x40520014 (GPIO bank0 +0x14): pin-mask write (1<<pin) by sub_A265C and sub_A3D1C; likely W1 set/clear; per-bank register at base+0x14. |
| `0x4052001C` | sub_A3D1C | 0x4052001C (GPIO bank0 +0x1C, result[7]): per-pin RMW enable bank set/cleared by GPIO mode in sub_A3D1C; per-bank register at base+0x1C. |
| `0x40520020` | sub_A3D1C | 0x40520020 (GPIO bank0 +0x20, result[8]): per-pin RMW enable/direction bank set/cleared by GPIO mode in sub_A3D1C; per-bank register at base+0x20. |
| `0x40520024` | sub_A3D1C | 0x40520024 (GPIO bank0 +0x24, result[9]): per-pin RMW polarity/mode bank read-modified by GPIO mode in sub_A3D1C; per-bank register at base+0x24. |
| `0x4052002C` | sub_A3986, sub_A3CBE | 0x4052002C (GPIO bank0 +0x2C): per-pin interrupt/trigger-mode field written 0x10000<<pin (sub_A3986) or 0x10001<<pin (sub_A3CBE); per-bank register at base+0x2C. |
| `0x40520030` | sub_A399E | 0x40520030 (GPIO bank0 +0x30, last DWORD of the 0x34 block): per-pin enable bit set (\|=1<<pin) by sub_A399E during interrupt/handler routing; per-bank register at base+0x30. |
| `0x40620008` | sub_A479A | base+0x08 init config word: written 0x1c during sub_A479A bring-up (*(a1+8)+8 = 28). |
| `0x4062000C` | sub_A479A | base+0x0c init config word: cleared to 0 during sub_A479A bring-up (*(a1+8)+12). |
| `0x40620040` | sub_A479A | base+0x40 init config word: cleared to 0 during sub_A479A bring-up (*(a1+8)+64). |
| `0x4062004C` | sub_A479A | base+0x4c descriptor/config word written 0xFFF (sub_A479A *(a1+8)+76); extends the descriptor/config block down from 0x54 to 0x4c. |
| `0xE000E00C` | sub_B2EDC | `0xE000E00C` (sub_B2EDC): core-local interrupt-control register; firmware writes one-hot line masks, `0x80000` (bit19) during teardown and `0x100000` (bit20) during 0x400E0000-peripheral init; write-only. |

### Constants that look like MMIO but are NOT registers

Never dereferenced as memory — do not model as registers. Most are TPM 2.0 permanent-handle constants (`0x40000001..0x4000000D`, `0x40000110/11A/120`) that numerically fall in the PMU page.

| Address | Evidence (funcs) | Function |
|---|---|---|
| `0x40000001` | sub_DA05A, sub_DA290, sub_E3F0A | 0x40000001 is not MMIO: it is the TPM 2.0 TPM_RH_OWNER permanent-handle constant used as a switch/compare value; do not model as a register. |
| `0x40000002` | sub_D9F00, sub_DA05A | 0x40000002 is not MMIO: it is the TPM 2.0 TPM_RH_REVOKE permanent-handle constant (switch-case value); do not model as a register. |
| `0x40000003` | sub_D9F00, sub_DA05A | 0x40000003 is not MMIO: it is the TPM 2.0 TPM_RH_TRANSPORT permanent-handle constant (switch-case value); do not model as a register. |
| `0x40000004` | sub_D9F00, sub_DA05A | 0x40000004 is not MMIO: it is the TPM 2.0 TPM_RH_OPERATOR permanent-handle constant (switch-case value); do not model as a register. |
| `0x40000005` | sub_D9F00, sub_DA05A | 0x40000005 is not MMIO: it is the TPM 2.0 TPM_RH_ADMIN permanent-handle constant (switch-case value); do not model as a register. |
| `0x40000006` | sub_D9F00, sub_DA05A | 0x40000006 is not MMIO: it is the TPM 2.0 TPM_RH_EK permanent-handle constant (switch-case value); do not model as a register. |
| `0x40000007` | sub_DA05A, sub_DA290, sub_DBD9E | 0x40000007 is not MMIO: it is the TPM 2.0 TPM_RH_NULL permanent-handle constant stored/compared as an object type tag in SRAM; do not model as a register. |
| `0x40000009` | sub_DA05A, sub_DADB2, sub_DBA72 | 0x40000009 is not MMIO: it is the TPM 2.0 TPM_RS_PW (password session) handle constant compared/case-matched in SRAM; do not model as a register. |
| `0x4000000A` | sub_DA05A, sub_DA560, sub_DACCE | 0x4000000A is not MMIO: it is the TPM 2.0 TPM_RH_LOCKOUT permanent-handle constant used in handle compares; do not model as a register. |
| `0x4000000B` | sub_DA05A, sub_DC5D2, sub_E2F0C | 0x4000000B is not MMIO: it is the TPM 2.0 TPM_RH_ENDORSEMENT permanent-handle constant used in handle compares/cases; do not model as a register. |
| `0x4000000D` | sub_E3054 | 0x4000000D is not MMIO: it is the TPM 2.0 TPM_RH_PLATFORM_NV permanent-handle constant used in a single handle compare; do not model as a register. |
| `0x40000110` | sub_DA130, sub_DADB2, sub_D9F00 | 0x40000110 is not MMIO: it is the TPM 2.0 TPM_RH_ACT_0 permanent-handle constant (switch-case value); do not model as a register. |
| `0x4000011A` | sub_DA130, sub_DADB2, sub_D9F00 | 0x4000011A is not MMIO: it is the TPM 2.0 TPM_RH_ACT_A permanent-handle constant (switch-case value); do not model as a register. |
| `0x40000120` | sub_D9DE4, sub_E11F2 | 0x40000120 is not MMIO: it is a TPM permanent-handle range bound (one past TPM_RH_ACT_F) used for clamping and offset arithmetic; do not model as a register. |
| `0x40100000` | sub_A4466 | 0x40100000 is the GLOBALSEC page base (block label) — at this site it is a literal pointer-value argument, not a register access. |
| `0x40212F78` | sub_9083A | 0x40212F78 (1075916664): NOT a register; it is the conceptual base used in offset arithmetic to map the 0x40213100 MMIO write addresses back to image-header struct offsets (v21-0x40212F78 -> a1 offset). |
| `0x4048444A` | sub_D5558, sub_E5DF4, sub_155558 | ARTIFACT - structure type-tag / magic discriminant constant (0x4048444A), not an MMIO register. Used as `if (struct->tag == 0x4048444A)` to select a key/context variant; sibling tag 0x47425244 = ASCII 'DRBG'. Falls in the 0x40xxxxxx peripheral window only b… |
| `a1+0x14 (device struct field, NOT MMIO)` | sub_A479A | Line 13956 *(a1+20)=0xD3FFFF targets a RAM struct field (a1, not *(a1+8)); exclude from the FIFO register map. |

### Documented but UNVERIFIABLE in this image

Either base addresses with zero static occurrence (provenance is gscemu/Cr50/fw.bin cross-ref), or RBOX offsets whose code lives in an undecompiled region of this dump. Listed honestly rather than asserted.

| Address | Evidence (funcs) | Function |
|---|---|---|
| `0x4001FFE0` | — | 0x4001FFE0 is absent; no chip-ID read occurs there. The only present register in the 0x4001Fxxx region is 0x4001FFE4 (a boot/update status word, 18 occurrences). The chip-ID value 0x8485694d appears nowhere in the image (no 0x8485-prefix constant). Remove o… |
| `0x4001FFF8` | — | 0x4001FFF8 is absent; no chip-ID register read there. Value 0x8485694d also absent. The firmware does compare an 'unknown chip ID 0x%x' (string at lines 13904/14319) but that read does not use 0x4001FFF8. Mark chip-ID@0x1FFF8 as cross-ref/unconfirmed in thi… |
| `0x40030490` | — | 0x40030490: UNSUPPORTED — the string '0x40030490' has zero occurrences anywhere in ti50.bin.prod.c (case-insensitive); drop the HANDOVER 'status-ish +0x490' claim, it has no static-code basis in this dump. |
| `0x40040000` | — | Mark as NOT present in ti50.bin.prod.c. Provenance is runtime-trace/cross-ref only; no static literal, decimal, or lui upper-immediate exists for this base. |
| `0x40090004` | — | +0x04 (group-0 interrupt enable) is unverifiable in this dump: cited VA 0xb695c lies in the undecompiled gap (sub_B3206 ends 0xB3236, next fn sub_B933A); may be real but has no static evidence here. |
| `0x4009000C` | — | +0x0c (group-0 interrupt test) is unverifiable in this dump: cited VA 0xb6960 is in the undecompiled 0xB3236..0xB933A gap. |
| `0x40090010` | — | +0x10 (group-0 interrupt state) is unverifiable here; the 'reads zero after clear' is a runtime observation with no static backing in this dump (VA 0xb6964 not decompiled). |
| `0x40090018` | — | +0x18 (group-1 interrupt enable) is unverifiable here: BOTH cited regions are undecompiled gaps — 0xb696a (between sub_B3206/sub_B933A) and 0xb0632 (between sub_AFAB4 @line 24613 and sub_B2E82 @line 24623). |
| `0x40090020` | — | +0x20 (group-1 interrupt test) is unverifiable: cited VAs 0xb6.. and 0xb063.. both fall in undecompiled gaps of this dump. |
| `0x40090024` | — | +0x24 (group-1 interrupt state) is unverifiable; runtime 'reads zero after clear' has no static backing (VAs in undecompiled gaps). |
| `0x4009002C` | — | +0x2c (group-2 interrupt enable) is unverifiable: cited VA 0xb6978 is in the undecompiled 0xB3236..0xB933A gap. |
| `0x40090034` | — | +0x34 (group-2 interrupt test) is unverifiable: cited VA in undecompiled gap. |
| `0x40090038` | — | +0x38 (group-2 interrupt state) is unverifiable; runtime claim only (VA in undecompiled gap). |
| `0x40090058` | — | +0x58 (init-ready) is unverifiable in this dump: cited VA 0xb6bdc is in the undecompiled gap, and the claimed string 'RBOX: ERROR: init failed' does NOT exist anywhere in the dump (only 'RBOX: Failed to write crash logs' / 'RBOX: dispatcher command canceled… |
| `0x4009005C` | — | +0x5c..+0x80 (descriptors) are unverifiable in this dump: cited VA 0xb6b74..0xb6bb0 is in the undecompiled gap, and the live values 0x0063f000/0x00c73000/0x6657/0x0a3b are runtime observations not present as literals anywhere in the dump. |
| `0x40090098` | — | +0x98 (command/control) is unverifiable: cited VA 0xb6b82 is in the undecompiled gap. |
| `0x400900A0` | — | +0xa0 (control) is unverifiable: cited VA in undecompiled gap. |
| `0x400900A4` | — | +0xa4 (status) is unverifiable; 'reads zero' is a runtime-model observation with no static backing (VA 0xb6bd6 in undecompiled gap). |
| `0x400B0000` | sub_99A1E | 0x400B0000: UNSUPPORTED in this dump — the substring '0x400B' has zero occurrences (any case) so there is no base construction or deref; the cited 'sub_99A40' does not exist (VA 0x99a40 is inside sub_99A1E, lines 7738-7813, which only does an indirect call … |
| `0x400D0000` | — | Mark as NOT present in ti50.bin.prod.c; provenance is cross-ref/runtime only. Present neighbors are 0x400C0000 (46 hits) and 0x400E0000 (per mmio.md line 77). |
| `0x40410000` | — | Mark as NOT present in ti50.bin.prod.c; gscemu/Cr50 cross-ref only. mmio.md's scanned page list (line 77) includes 0x40450000 but not 0x40410000. |
| `0x40420000` | — | Confirmed: 0x40420000 is a Cr50-only legacy base with no Ti50 evidence. The doc already acknowledges this ('does not touch 0x40420000'); keep it flagged as Cr50 cross-ref pending live Ti50 relocation, not a Ti50 register. |
| `0x40630000` | — | 0x40630000 appears in NO form. The present I2C-range neighbor is 0x40620000 (12 hits), which mmio.md line 77 lists among found pages. The I2C base is most likely 0x40620000, not 0x40630000; correct the HANDOVER 4c row or mark it as a cross-ref pending confi… |
| `opcode Cr50 PROGRAM 0x27182818` | — | Cr50 PROGRAM 0x27182818 (=655894552) is ABSENT from this image. Grep for both 0x27182818 and 655894552 returns 0 hits. This Ti50 build uses only the Ti50 PROGRAM opcode 0xe89d48b7. |
| `opcode ERASE 0x31415927` | sub_A0DEA, sub_A0EB6, sub_9F9AC | ERASE opcode 0x31415927 (=826366247) is ABSENT (0 hits for hex or decimal). The erase path (sub_A0DEA -> sub_A0EB6) does NOT write a 0x31415927 opcode; it encodes the erase via TRANS = sub_9F9AC(desc, cmd=3, 0) at line 11726 and arms PE_EN = 0xB11924E1 at l… |
| `opcode BULK 0x1D1E2BAD` | — | BULK 0x1D1E2BAD (=488516525) is ABSENT (0 hits for 0x1D1E2BAD/1d1e2bad/488516525). It is a family/spec constant not used by this firmware image. |

### Flash opcode presence

| Opcode | Present in this image? |
|---|---|
| opcode READ 0x16021765 | present |
| opcode Ti50 PROGRAM 0xe89d48b7 | present |
| opcode Cr50 PROGRAM 0x27182818 | ABSENT (reference-only) |
| opcode ERASE 0x31415927 | ABSENT (reference-only) |
| opcode BULK 0x1D1E2BAD | ABSENT (reference-only) |
| READ 0x16021765 | present (sub_9F74C L10343) |
| Ti50 PROGRAM 0xe89d48b7 | present (sub_9F976 L10585) |