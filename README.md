<h1 align="center">rax</h1>

<h5 align="center">
rax is a CPU emulator that does not trust itself. It implements four instruction sets in software —<br/>
x86-64, AArch64, Hexagon, and RISC-V — and checks every one of them, instruction by instruction,<br/>
against a reference that cannot be argued with: real silicon (KVM) for x86-64, and QEMU for the rest.<br/>
<br/>
The x86-64 core is a complete machine. It boots a real Linux kernel two ways — through hardware<br/>
virtualization (KVM on Linux, Hypervisor.framework on macOS) at near-native speed, or through a<br/>
from-scratch interpreter you can trace, single-step, snapshot, and profile — and it covers the ISA out<br/>
to AVX-512, AVX10.2, and Intel APX. Alongside it run three more software CPUs of real depth: AArch64<br/>
with SVE/SVE2, NEON, and the Cortex-M line; Hexagon with its VLIW packets and HVX vectors; and a<br/>
correctly-rounded RV64GC. A shared multi-architecture IR (SMIR) lifts all four toward one interpreter<br/>
and one in-progress JIT.
</h5>

<div align="center"><code>Rust</code> • <code>x86-64 · AArch64+SVE · Hexagon+HVX · RV64GC</code> • <code>boots Linux</code> • <code>121k+ tests</code></div>

---

## The thirty-second version

Build it, then run a Linux kernel — at silicon speed, or one instruction at a time:

```bash
cargo build --release

# 1. Boot a real Linux kernel on hardware virtualization (Linux + KVM).
./target/release/rax --kernel bzImage --initrd initrd.img

# 2. Boot the same kernel on the software CPU. Slower, but every instruction is yours.
./target/release/rax --backend emulator --kernel bzImage --initrd initrd.img

# 3. ...and trace every instruction the kernel executes, SDE-compatible.
./target/release/rax --backend emulator --kernel bzImage --trace boot.trace

# 4. ...or single-step it from your debugger.
./target/release/rax --backend emulator --kernel bzImage --gdb 1234 --wait-gdb
```

The other three CPU cores aren't VM backends — they're software ISAs you exercise through their oracle
harnesses, which run each instruction on both rax and QEMU and diff the result:

```bash
cargo test --release --test arm_diff           # AArch64     vs. qemu-aarch64
cargo test --release --test hexagon_hvx_diff   # Hexagon HVX vs. qemu-hexagon
cargo test --release --test riscv_diff         # RV64GC      vs. qemu-riscv64
cargo test --release --test differential       # x86-64      vs. KVM (the silicon)
```

> **Good to know** Every oracle harness self-skips cleanly if the cross-compiler / QEMU / `/dev/kvm`
> isn't present, so the suite is green on any host. They only fail when rax and the reference genuinely
> disagree.

---

## Why it exists

If you have ever wondered what actually happens between launching a kernel and seeing a shell, most tools
give you one of two unsatisfying answers. A real hypervisor (QEMU/KVM) runs the kernel so fast you cannot
watch it; the CPU is a black box. A pure emulator (Bochs, Unicorn) lets you watch, but its instruction
coverage trails the hardware by years, and you have no easy way to know whether what it *did* matches
what a real chip would have done.

rax is built around the second problem. A software CPU is only as good as your confidence that it is
*right*, and the only honest way to earn that confidence is to compare it, instruction by instruction,
against something authoritative. So that comparison is the project's spine, not an afterthought:

- **x86-64** is checked against **KVM** — the actual silicon in your machine. The same machine code runs
  on the interpreter and on hardware from an identical architectural state, and the final state is
  diffed. When you want to know what an instruction *should* do, you ask the chip.
- **AArch64, Hexagon, and RISC-V** are each checked against **QEMU** in user mode, the same way: a tiny
  reference harness loads a state, runs one instruction, and reports back; rax runs it from the identical
  state; any divergence is a bug, reported precisely.

That methodology is what lets rax be both *legible* — you can open `insn/arith/add.rs` and read exactly
what `ADD` does to the flags — and *trusted*: it tracks four instruction sets out to their modern vector
extensions, and tens of thousands of cases stand between a change and a regression.

---

## What a run looks like

A throughput benchmark of the x86-64 interpreter's hot path (`examples/bench_loop.rs`, a tight
register-only guest loop) reports sustained MIPS — the apples-to-apples metric for interpreter work:

```text
$ RUSTFLAGS="-C target-cpu=native" cargo run --release --example bench_loop
[bench] iterations    : 268435456 (0x10000000)
[bench] expected insns: 1342177283
[bench] executed insns: 1342177283
[bench] elapsed       : 12.78 s
[bench] throughput    : 105.0 MIPS
[bench] final eax=0x20000000 ecx=0x0
```

Boot a kernel under the emulator with `--trace`, and every retired instruction lands in an
SDE-compatible trace file — instruction, register changes, and (when they happen) memory reads/writes
and XMM updates — that you can diff against Intel's own Software Development Emulator:

```text
$ ./target/release/rax --backend emulator --kernel bzImage --trace boot.trace
...
$ head -4 boot.trace
INS 0x00000000010000f0   xor eax, eax                                       | eax=0x00000000
INS 0x00000000010000f2   mov ecx, 0x80000000                                | ecx=0x80000000
INS 0x00000000010000f7   mov cr0, eax                                       | cr0=0x80000011
Write *(UINT64*)0x9000 = 0x000000000000a003
```

> **Good to know** The trace, GDB stub, snapshot facility, and per-mnemonic profiler are all wired into
> the *interpreter's* step loop, so they observe the genuine instruction stream — not a re-derived
> approximation. The KVM backend traps only on I/O, so it is fast but opaque by design.

---

## Four CPUs

x86-64 is the complete VM target — it boots, with the full device platform, boot protocol, tracing, GDB,
and snapshots. The other three are software CPU cores of real depth, validated standalone against QEMU
(not yet driveable as bootable VM backends from the CLI). All four also have SMIR lifters.

| Core | Size | Coverage | Oracle |
|------|-----:|----------|--------|
| **x86-64** | ~50k LOC | Legacy → SSE/AVX/AVX2 → AVX-512 → AVX10.1/10.2 → APX; x87; AES/SHA/GFNI; XSAVE | KVM (real hardware) |
| **AArch64 / ARM** | ~43k LOC | A64 base, SVE/SVE2, NEON/VFP, FP16; AArch32/Thumb; Cortex-M (M0–M85), Cortex-R | qemu-aarch64 + ASL |
| **Hexagon** | ~33k LOC | V68 scalar, VLIW packets, HVX vectors | qemu-hexagon |
| **RISC-V** | ~4k LOC | RV64GC (IMAFDC) + Zicsr/Zifencei + Zba/Zbb/Zbc/Zbs | qemu-riscv64 |

### x86-64 — the complete machine

The primary target and the only bootable one. A full decoder handles the entire encoding zoo (REX and
REX2, every legacy prefix including the `0x67` address-size override, ModR/M + SIB, VEX2/VEX3, EVEX
including APX Map 4, RIP-relative), feeding 88 instruction-implementation files.

| Category | Coverage |
|----------|----------|
| **Integer / logic / bit** | full ALU, ADCX/ADOX, BT/BTS/BTR/BTC, BSF/BSR, POPCNT/LZCNT/TZCNT; `#DE` on ÷0/overflow |
| **Shifts / strings / BCD** | SHL…RCR, SHLD/SHRD; REP MOVS/STOS/SCAS/CMPS (bulk fast path); DAA…AAD |
| **x87 FPU** | escape codes D8–DF via f64 |
| **SSE → SSE4 / AVX / AVX2** | moves, arithmetic, all compare predicates, shuffle/permute/convert (XMM/YMM) |
| **FMA / BMI1 / BMI2** | VFMADD/SUB/NMADD/NSUB {132,213,231}; ANDN, BZHI, PEXT, PDEP, MULX, … |
| **AVX-512** | F / VL / BW / DQ / CD; masked ops, opmask k0–k7 |
| **AVX10.1 / 10.2** | VNNI, IFMA, VPOPCNTDQ, VBMI, BF16; VMPSADBW, VMINMAX, saturating converts |
| **APX** | REX2, EGPRs R16–R31, NDD (3-operand), NF (no-flags), EVEX Map 4 |
| **Crypto / state / system** | AES, SHA1/256, GFNI (FIPS/SDM known-answer tested); XSAVE/XRSTOR/XCR0; CPUID, MSRs, CR/DR, descriptor-table loads — CPL-checked, faults injected (`#UD`/`#GP`) |

### AArch64 / ARM — deep, and growing fast

A near-complete A64 base (arithmetic, logical, bitfield, load/store incl. LSE atomics, branches, system
register access across EL0–EL3, 4-level MMU, GICv3) with substantial recent vector work:

- **SVE / SVE2** — ~120 decoded mnemonics at VL=128: predicate ops (PTRUE, PFALSE, WHILE, PFIRST, PNEXT,
  PTEST, predicate count/logical), permutes (ZIP/UZP/TRN, EXT, TBL, COMPACT, SPLICE, REV), reductions
  (SADDV…ORV/EORV), predicated integer & FP ALU, CPY/DUP/SEL/CMP, shifts, INDEX/CNT*; SVE2 unpredicated
  multiplies. (Some SVE2 bit-permute/crypto families are still being filled in.)
- **NEON / VFP** — full Advanced SIMD and scalar FP, including FP16, across V0–V31.
- **AArch32 / Thumb-2** — A32 and Thumb decoders with IT-block conditional execution.
- **Cortex-M (M0–M85)** — NVIC, SysTick, SCB, MPU; ARMv6-M through ARMv8.1-M (MVE/Helium on M55/M85).
- **Features** — 30+ optional extensions gated through `features.rs`/`isa.rs`, spanning ARMv8.0–v9.5.

### Hexagon — VLIW and HVX

A Qualcomm Hexagon (V68) implementation that takes the hard parts seriously:

- **VLIW packets** — true parallel-packet semantics: all instructions read the old register file and
  commit atomically at packet end; `.new` value forwarding for scalars *and* HVX vectors; duplex
  encodings; hardware loops (SA0/LC0, SA1/LC1) with circular and bit-reversed addressing; dual stores.
- **Scalar core** — full ALU, multiplies, shifts, loads/stores, control flow, predicates P0–P3.
- **HVX** — 1024-bit vector registers V0–V31 and predicates Q0–Q3: add/sub/avg, compare, min/max,
  multiplies (vmpyi/vmpyv/vmpys/rmpy/cmpy), permute, shift, round/saturate, LUT, vector-predicate ops,
  and `vmem` loads/stores with `.cur`/`.tmp` and scalar-predicated forms. (Carry-chain, conversion, and
  histogram families are scaffolded for a later wave.)

### RISC-V — small and correct

A complete **RV64GC** interpreter in ~4k lines: RV64I base, M (mul/div), A (LR/SC + AMO, single-hart),
F/D, C (compressed), Zicsr (21 CSRs, machine-mode trap state), Zifencei, and the Zba/Zbb/Zbc/Zbs
bit-manipulation extensions. The floating-point core is the highlight — it computes the round-to-nearest
result, recovers the *exact* residual (2Sum / FMA / Newton), and uses it to select the correctly-rounded
answer in all five RISC-V rounding modes without depending on the host's rounding, setting all five IEEE
exception flags per operation.

---

## Correctness: every architecture has an oracle

This is the part that matters. rax's claim is not "it implements a lot of instructions" — it is "the
instructions are *checked against an authority*." Each harness builds an initial architectural state,
runs one instruction (or a short sequence) on both rax and the reference from that identical state, then
diffs the full register file (and, for x86, a scratch memory page). Inputs are enumerated over encoding
fields and driven with many pseudo-random states, so a single `#[test]` function covers a large family.

| Harness | rax core | Oracle | `#[test]` fns | Compares |
|---------|----------|--------|-------------:|----------|
| `tests/differential.rs` | x86-64 | **KVM** (hardware) | 463 | GPRs, RIP, RFLAGS, XMM, memory |
| `tests/arm_diff.rs` | AArch64 | `qemu-aarch64` | 86 | X0–X30, SP, NZCV, V0–V31 |
| `tests/hexagon_*_diff.rs` | Hexagon (scalar / cf / float / mem / HVX / HVX-mem) | `qemu-hexagon` | 86 | GPRs, P3:0, USR, loop regs, V0–V31, Q0–Q3 |
| `tests/riscv_diff.rs` | RV64GC | `qemu-riscv64` | 16 | x1–x31, f0–f31, fcsr, scratch |
| `tests/diff_fuzz.rs` | SMIR (lift → interp / native) | KVM | 28 | guest state after lift+run |
| `tests/smir_avx10_roundtrip.rs` | SMIR AVX10 | — | 48 | lift → lower fidelity |

> **Good to know** Those `#[test]` counts understate the work by orders of magnitude — each function
> enumerates many encodings and many random input states internally (the ARM families alone drive ~1,000
> cases apiece). The reference harnesses are tiny C/asm programs (`tools/{arm,riscv,hexagon}-diff/`) that
> QEMU runs as the ground truth; for x86 the ground truth is KVM itself.

### Tests by the numbers

On top of the oracles, there are exhaustive unit suites:

| Suite | Count | How |
|-------|------:|-----|
| **ARM (ASL-generated)** | 92,131 | generated from ARM's official machine-readable **ASL** spec via `tools/asl-parser/` |
| **x86-64 instruction suite** | 28,554 | `tests/x86_64/` (850 files), behind `--features x86_64-suite` |
| **Everything else** | ~900 | oracle harnesses, Hexagon bare-metal, crypto known-answer (FIPS/SDM), SMIR |
| **Total** | **121,603** | `#[test]` functions across `tests/` |

The ARM tests are not written by hand: the `asl-parser` downloads and parses ARM's ASL release and emits
exhaustive instruction tests from it, which is how 92,000+ ARM cases exist at all.

---

## SMIR — the shared IR

**SMIR** (Sigma Machine IR, `src/smir/`, ~35k LOC; spec in
[`docs/specifications/smir/`](docs/specifications/smir/)) is the layer that makes "four CPUs" one
project. Each guest architecture has a *lifter* that translates its instructions into a common set of
100+ typed operations; the IR is then interpreted directly today, and lowered to native host code on an
in-progress JIT path.

```text
  x86-64        AArch64        Hexagon        RISC-V        AVX10
    │              │              │              │             │
    ▼              ▼              ▼              ▼             ▼
 ┌──────────────────────────────────────────────────────────────┐
 │                          Lifters                             │
 └───────────────────────────────┬──────────────────────────────┘
                                 ▼
                      ┌────────────────────┐
                      │     SMIR Module    │   SmirFunction → SmirBlock → SmirOp
                      └─────────┬──────────┘
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
        Interpreter       optimizer        x86-64 JIT lowering
        (primary)      (O0/O1/O2 passes)   (emitter + regalloc)
```

| Piece | Where | State |
|-------|-------|-------|
| **Lifters** | `lift/` | x86-64 (most mature), AArch64, Hexagon, RISC-V, and a dedicated AVX10 lifter |
| **Interpreter** | `interp.rs` | the primary execution path; lazy flags, block caching |
| **Optimizer** | `opt.rs` | dead-flag elimination, constant propagation, strength reduction, block merging |
| **JIT lowering** | `lower/x86_64.rs`, `lower/regalloc.rs` | a real x86-64 emitter + register allocator that JIT-compiles SMIR to machine code |

> **Good to know — honest status of the JIT.** The lowering path emits genuine x86-64 and *runs*:
> hand-built SMIR (e.g. `add rbx, rcx`) lowers to native code and executes correctly
> (`smir_native_m0_add` passes). The end-to-end path — lift a real x86-64 binary → lower → execute
> natively — still has integer-encoding codegen bugs (malformed immediate widths) that crash it, so the
> auto-lifted native test (`smir_native_alu`) is `#[ignore]`d while those are fixed. The interpreter is
> the production path; the JIT is close but not yet trustworthy on lifted code.

---

## How the x86-64 machine works

### The Linux boot protocol

Both x86-64 backends bring a kernel to its 64-bit entry point the same way:

1. Load the kernel (ELF or bzImage) at physical `0x1000000` (16 MiB) and the initrd at `0x4000000`.
2. Build initial page tables: identity-map the first 8 GiB with 1 GiB huge pages, kernel space at
   `0xFFFFFFFF80000000`, direct physical map at `0xFFFF888000000000`.
3. Install a minimal GDT with 64-bit code/data segments.
4. Enter long mode (`CR0.PG=1`, `CR4.PAE=1`, `EFER.LME=1`) and jump to the kernel's entry.

### The interpreter loop

Fetch / decode / execute, with two twists that make it both fast and honest:

```text
loop {
    entry = decode_cache[rip & 0xFFF];          // 4096-entry, RIP-indexed
    insn  = if entry.matches(rip, mode) {
        entry.bytes                              // HIT: skip the memory fetch entirely
    } else {
        decode(fetch(rip))                       // MISS: prefixes, ModR/M, SIB, VEX/EVEX, immediates
    };
    execute(insn);                               // update regs / memory / lazy flags
    if (++insn_count & 1023) == 0 { poll_lapic_and_yield(); }
}
```

| Mechanism | What it does |
|-----------|--------------|
| **Decode cache** | 4096 entries indexed by RIP, keyed on a mode tag (`CR3 \| CS.L \| CS.D`). A hit reuses the cached bytes and **skips the guest-memory fetch entirely** — the biggest hot-path win. Kept coherent by SMC detection on guest writes and a flush on external state changes. |
| **Lazy flags** | Arithmetic records its operands and defers RFLAGS materialization until a consumer (a `Jcc`, a `PUSHF`) reads them. Most computed flags are never needed. |
| **Fast paths** | A direct host-pointer path for physical RAM (bypassing the `vm-memory` round-trip), a fast path for common ModR/M memory operands, and page-at-a-time `REP MOVS`/`STOS`. |
| **TLB** | 256-entry direct-mapped cache over the 4-level page walk (4 KiB / 2 MiB / 1 GiB pages). |
| **Deterministic TSC** | RDTSC is `insn_count × 3000` — reproducible across runs, enough to satisfy kernel delay loops. |

On a modern host (`target-cpu=native`), the register-only loop sustains around **105 MIPS**.

---

## Devices

The running machine wires up a classic PC platform: a 16550 serial console, 8254 PIT, 8259 PIC, LAPIC +
IOAPIC, RTC/CMOS, a PCI host bridge, QEMU `fw_cfg`, and the Bochs-style debug port.

Alongside those, `src/devices/` carries a growing library of full **register-level controller models** —
1,000–1,500 lines each — built and tested ahead of being attached to the default machine:

| Class | Models |
|-------|--------|
| **Storage** | AHCI, NVMe, IDE, virtio-blk, floppy (FDC) |
| **Network** | Intel e1000 |
| **Display / audio / USB** | VGA, AC97, UHCI |
| **Platform** | HPET, i8042 (PS/2), DMA, IOAPIC, system-control ports |

> **Good to know** The classic boot set is live in the VM today; the larger controllers (AHCI/NVMe/e1000/
> VGA/…) are implemented as standalone device models and not yet bound to the guest's I/O bus, so a guest
> won't see an NVMe disk until that wiring lands. The code is real; the cabling is in progress.

---

## Observability & tooling

Because the interpreter owns the step loop, the introspection tools see the real instruction stream:

| Tool | Flag / feature | What you get |
|------|----------------|--------------|
| **Instruction trace** | `--trace <file>` (`--features trace`) | SDE-compatible per-instruction trace, diffable against Intel SDE |
| **GDB stub** | `--gdb <port> --wait-gdb` (`--features debug`) | Remote Serial Protocol server: registers, memory, stepping |
| **Snapshots** | `--snapshot-interval N` / `--snapshot-at a,b,c` / `--resume <file>` | full VM state (registers + zstd-compressed memory, bincode-serialized); save at instruction counts, resume later |
| **Profiler** | `--profile` (`--features profiling`) | per-mnemonic execution counts and a hot-instruction report, optional JSON export |

---

## Usage

x86-64 is the bootable target; these options drive the VM.

```
--kernel <path>            Kernel image: ELF or bzImage (required)
--initrd <path>            Initial ramdisk
--backend <kvm|emulator>   Virtualization backend (hvf on macOS)
--memory <size>            Guest memory, e.g. "512M", "2G"
--vcpus <N>                Number of vCPUs
--cmdline <string>         Kernel command line
--config <file>            Load a TOML config
--trace <file>             Write an SDE-compatible instruction trace   (--features trace)
--gdb <port> [--wait-gdb]  Start a GDB stub, optionally wait for attach (--features debug)
--snapshot-interval <N>    Snapshot every N instructions (0 = off)
--snapshot-at <a,b,c>      Snapshot at specific instruction counts
--resume <file>            Resume from a snapshot
--profile [--profile-output <json>]   Instruction profiling             (--features profiling)
```

```toml
# config.toml
backend = "emulator"
memory  = "512M"
kernel  = "/path/to/bzImage"
initrd  = "/path/to/initrd.img"
cmdline = "console=ttyS0 earlyprintk=serial"
```

---

## Building

```bash
# Default (Linux): KVM backend enabled.
cargo build --release

# Cross-platform: software emulator only, no KVM.
cargo build --release --no-default-features

# Fastest local interpreter (uses your host's full ISA).
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

> **Good to know** `.cargo/config.toml` ships `target-cpu=x86-64-v3` as a portable default — it still
> lets LLVM emit AVX2/BMI2/FMA and autovectorize the scalar SIMD/flag loops while staying runnable on any
> 2013-or-later x86-64 host. The release profile is fat-LTO, one codegen unit, `panic=abort`, stripped.

| Feature | Default | Enables |
|---------|---------|---------|
| `kvm` | ✓ (Linux) | KVM backend (`kvm-bindings` / `kvm-ioctls`) |
| `trace` | | SDE-compatible instruction tracing |
| `debug` | | GDB Remote Serial Protocol server |
| `profiling` | | per-mnemonic profiler + JSON export |
| `x86_64-suite` | | the 28,554-case x86-64 instruction test suite |

---

## The microkernel test harness

`microkernel/` is a freestanding bare-metal x86-64 kernel used to exercise the interpreter end to end
without a full Linux image — an N-body physics simulation, a bump allocator, and broad instruction
coverage — the same binary runnable on rax and on Intel SDE for cross-checking.

```bash
cd microkernel
make baremetal     # build the bare-metal ELF
make test-rax      # boot it in the rax software emulator
make test-sde      # run it under Intel SDE for a reference trace
```

---

## Repository map

```
src/
├── main.rs · lib.rs · config.rs · vmm.rs   # CLI, VM monitor, run loop
├── memory.rs · timing.rs · trace.rs · snapshot.rs
├── cpu/            # VCpu trait, register/system state, exit reasons
├── arch/x86_64/    # boot protocol, GDT, page tables, ACPI, device setup
├── backend/
│   ├── kvm/        # Linux hardware virtualization (HVF for macOS)
│   └── emulator/
│       ├── x86_64/ # ~50k LOC: decoder, mmu, flags, dispatch/{legacy,twobyte,vex,evex}, insn/ (88 files)
│       └── hexagon/# ~33k LOC: scalar core, VLIW packets, HVX (sem/hvx_*.rs)
├── arm/            # ~43k LOC: aarch64 (+SVE) · cortex_m · decoder · vfp · sysreg · cp15 · features
├── riscv/          # ~4k LOC: RV64GC interpreter — cpu · decode · rvc · float · csr
├── smir/           # ~35k LOC: ir · ops · types · interp · opt · lift/ · lower/
├── devices/        # serial·pit·pic·lapic·ioapic·rtc·hpet·pci·fw_cfg  +  ahci·nvme·ide·virtio·e1000·vga·ac97·uhci·fdc·dma
├── gdb/            # Remote Serial Protocol server      (--features debug)
└── profiling/      # per-mnemonic profiler              (--features profiling)

tests/              # differential (x86↔KVM) · arm_diff/riscv_diff/hexagon_*_diff (↔QEMU)
                    # x86_64/ (28,554) · arm/generated (92,131, from ASL) · diff_fuzz · smir_avx10_roundtrip
tools/              # asl-parser (ARM ASL → tests) · arm-diff · riscv-diff · hexagon-diff (QEMU oracles)
microkernel/        # bare-metal x86-64 test kernel
docs/specifications/# smir/ (the IR spec) · riscv/ (vendored RISC-V specs) · arm/
```

---

## Status

| Path | State |
|------|-------|
| **x86-64 — KVM/HVF** | Boots Linux to an interactive shell |
| **x86-64 — software** | Runs the full modern ISA; 463 differential cases vs. KVM; runs the bare-metal microkernel; driving toward a complete software Linux boot |
| **AArch64 / ARM** | A64 + SVE/SVE2 + NEON + Cortex-M; validated vs. qemu-aarch64; ~92k ASL-generated tests |
| **Hexagon** | V68 scalar + VLIW + HVX; validated vs. qemu-hexagon |
| **RISC-V** | Complete RV64GC interpreter; validated vs. qemu-riscv64 |
| **SMIR** | 5 lifters + interpreter + optimizer; x86-64 JIT runs hand-built IR, lifted-code path in progress |

### What's missing

A production hypervisor this is not — by design. The VM is x86-64 only (the ARM/Hexagon/RISC-V cores are
validated software ISAs, not yet bootable backends). There is no SMP (one vCPU executes), and the larger
device controllers aren't attached to the default machine yet. The software emulator's full Linux boot is
still being chased (the last known sticking point is fixmap virtual-address computation during early
kernel init); the KVM path boots cleanly. And the SMIR JIT runs hand-built IR but not yet lifted code.

---

## A note on the name

`rax` is the x86-64 accumulator register — the first register the manuals introduce. The project started
x86-64-centric and the name stuck even as it grew three more instruction sets; it is also just the crate
name, so `cargo run` and you are off.

---

## See also

- [kvm-ioctls](https://github.com/rust-vmm/kvm-ioctls) / [kvm-bindings](https://github.com/rust-vmm/kvm-bindings) — KVM access
- [linux-loader](https://github.com/rust-vmm/linux-loader) / [vm-memory](https://github.com/rust-vmm/vm-memory) — boot protocol & guest memory
- [QEMU](https://www.qemu.org/) — the user-mode reference oracle for AArch64, Hexagon, and RISC-V
- [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) · [Arm ASL](https://developer.arm.com/Architectures/A-Profile%20Architecture) · [RISC-V specs](https://riscv.org/technical/specifications/)
- [`docs/specifications/smir/`](docs/specifications/smir/) — the SMIR IR specification

## License

MIT
