<h1 align="center">rax</h1>

<img width="1536" height="750" alt="rax" src="assets/hero.png" />

<h5 align="center">
rax is a CPU emulator that does not trust itself. It implements four instruction sets in software<br/>
(x86-64, AArch64, Hexagon, and RISC-V) and checks every one of them, instruction by instruction,<br/>
against a reference that cannot be argued with: real silicon (KVM) for x86-64, and QEMU for the rest.<br/>
<br/>
The x86-64 core is a complete machine. It boots a real Linux kernel two ways: through hardware<br/>
virtualization (KVM on Linux, Hypervisor.framework on macOS) at near-native speed, or through a<br/>
from-scratch interpreter that traces, single-steps, snapshots, and profiles every instruction it<br/>
runs, and now boots all the way to a BusyBox shell. It covers the ISA out to AVX-512, AVX10.2, and<br/>
Intel APX, and behind it sits SMIR, a shared multi-architecture IR whose hot-block JIT lifts hot<br/>
x86-64 loops to native code at ~80× the interpreter.<br/>
<br/>
Three more software CPUs run alongside: a fully oracle-verified Hexagon (every opcode, scalar + HVX),<br/>
an AArch64 with complete SVE, and a correctly-rounded RV64GC. RISC-V and Hexagon are bootable<br/>
emulator backends in their own right.
</h5>

<div align="center"><code>Rust</code> • <code>x86-64 · AArch64+SVE · Hexagon+HVX · RV64GC</code> • <code>boots Linux</code> • <code>hot-block JIT</code> • <code>121k+ tests</code></div>

---

## The thirty-second version

Build it, then run a Linux kernel, at silicon speed, or one instruction at a time:

```bash
cargo build --release

# 1. Boot a real Linux kernel on hardware virtualization (Linux + KVM).
./target/release/rax --kernel bzImage --initrd initrd.img

# 2. Boot it on the software CPU instead: slower, but every instruction is yours, and it
#    now runs all the way to a BusyBox shell. (Use an ELF vmlinux; bzImage real-mode boot is WIP.)
./target/release/rax --backend emulator --kernel vmlinux --initrd initrd.cpio

# 3. ...and trace every instruction the kernel executes, SDE-compatible.
./target/release/rax --backend emulator --kernel vmlinux --trace boot.trace

# 4. ...turn on the native JIT for hot loops (~80× on register-heavy code).
cargo run --release --features smir-jit -- --backend emulator --kernel vmlinux
```

RISC-V and Hexagon are bootable emulator backends too (bare-metal programs, UART + halt):

```bash
./target/release/rax --arch riscv64 --backend emulator --kernel program.elf
```

And all four cores are checked against a reference oracle. Each harness runs an instruction on both rax
and the reference from an identical state, then diffs the result:

```bash
cargo test --release --test differential       # x86-64  vs. KVM (the silicon)
cargo test --release --test arm_diff           # AArch64 vs. qemu-aarch64
cargo test --release --test hexagon_hvx_diff   # Hexagon vs. qemu-hexagon
cargo test --release --test riscv_diff         # RV64GC  vs. qemu-riscv64
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

- **x86-64** is checked against **KVM**, the actual silicon in your machine. The same machine code runs
  on the interpreter and on hardware from an identical architectural state, and the final state is
  diffed. When you want to know what an instruction *should* do, you ask the chip.
- **AArch64, Hexagon, and RISC-V** are each checked against **QEMU** in user mode, the same way: a tiny
  reference harness loads a state, runs one instruction, and reports back; rax runs it from the identical
  state; any divergence is a bug, reported precisely.

That methodology is what lets rax be both *legible* (you can open `insn/arith/add.rs` and read exactly
what `ADD` does to the flags) and *trusted*: it tracks four instruction sets out to their modern vector
extensions, and well over a hundred thousand cases stand between a change and a regression. It is also
what lets the JIT exist at all: a native code generator is only safe if you can prove its output matches
the interpreter, and the same oracle does that proof.

---

## What a run looks like

A throughput benchmark of the x86-64 interpreter's hot path (`examples/bench_loop.rs`, a tight
register-only guest loop) reports sustained MIPS, the apples-to-apples metric for interpreter work:

```text
$ RUSTFLAGS="-C target-cpu=native" cargo run --release --example bench_loop
[bench] iterations    : 268435456 (0x10000000)
[bench] expected insns: 1342177283
[bench] executed insns: 1342177283
[bench] elapsed       : 9.26 s
[bench] throughput    : ~145 MIPS
[bench] final eax=0x20000000 ecx=0x0
```

Turn on `--features smir-jit` and that same loop is detected as hot, lifted to SMIR, lowered to native
x86-64, and run directly: **~11,000 MIPS, roughly 80×**, bit-identical to the interpreter (the JIT-tier
vcpu test asserts register-for-register equality).

Boot a kernel under the emulator with `--trace`, and every retired instruction lands in an
SDE-compatible trace file: instruction, register changes, and (when they happen) memory reads/writes
and XMM updates, which you can diff against Intel's own Software Development Emulator:

```text
$ ./target/release/rax --backend emulator --kernel vmlinux --trace boot.trace
...
$ head -4 boot.trace
INS 0x00000000010000f0   xor eax, eax                                       | eax=0x00000000
INS 0x00000000010000f2   mov ecx, 0x80000000                                | ecx=0x80000000
INS 0x00000000010000f7   mov cr0, eax                                       | cr0=0x80000011
Write *(UINT64*)0x9000 = 0x000000000000a003
```

> **Good to know** The trace, GDB stub, snapshot facility, and per-mnemonic profiler are all wired into
> the *interpreter's* step loop, so they observe the genuine instruction stream, not a re-derived
> approximation. The KVM backend traps only on I/O, so it is fast but opaque by design.

---

## Four CPUs

x86-64 is the complete VM target: it boots Linux, with the full device platform, boot protocol, tracing,
GDB, snapshots, and the JIT. Hexagon and RISC-V are bootable emulator backends for bare-metal programs.
AArch64 is the deepest-tested core but the one *not* yet wired as a runnable backend. It lives entirely
behind its oracle. All four also have SMIR lifters.

| Core | Size | Runnable? | Coverage | Oracle |
|------|-----:|-----------|----------|--------|
| **x86-64** | ~50k LOC | **boots Linux** (KVM/HVF/emulator) + JIT | Legacy → SSE/AVX/AVX2 → AVX-512 → AVX10.1/10.2 → APX; x87; AES/SHA/GFNI; XSAVE | KVM (real hardware) |
| **Hexagon** | ~37k LOC | bare-metal (`--arch hexagon`) | V73 scalar + VLIW packets + HVX, **every opcode verified** | qemu-hexagon |
| **RISC-V** | ~10k LOC | bare-metal (`--arch riscv64`) | full RVA23 *scalar* set (RV64GC + Zfh/Zicond/Zfa/Zbk\*/Zcb + scalar crypto + vector-config) | qemu-riscv64 |
| **AArch64 / ARM** | ~48k LOC | validated only (no backend yet) | A64 base, **complete SVE** + SVE2, NEON/VFP, FP16; AArch32/Thumb; Cortex-M (M0-M85) | qemu-aarch64 + ASL |

### x86-64: the complete machine

The primary target and the one that boots Linux. A full decoder handles the entire encoding zoo (REX and
REX2, every legacy prefix including the `0x67` address-size override, ModR/M + SIB, VEX2/VEX3, EVEX
including APX Map 4, RIP-relative), feeding 88 instruction-implementation files.

| Category | Coverage |
|----------|----------|
| **Integer / logic / bit** | full ALU, ADCX/ADOX, BT/BTS/BTR/BTC, BSF/BSR, POPCNT/LZCNT/TZCNT; `#DE` on ÷0/overflow |
| **Shifts / strings / BCD** | SHL…RCR, SHLD/SHRD; REP MOVS/STOS/SCAS/CMPS (bulk fast path); DAA…AAD |
| **x87 FPU** | escape codes D8-DF via f64 |
| **SSE → SSE4 / AVX / AVX2** | moves, arithmetic, all compare predicates, shuffle/permute/convert (XMM/YMM) |
| **FMA / BMI1 / BMI2** | VFMADD/SUB/NMADD/NSUB {132,213,231}; ANDN, BZHI, PEXT, PDEP, MULX, … |
| **AVX-512** | F / VL / BW / DQ / CD; masked ops, opmask k0-k7 |
| **AVX10.1 / 10.2** | VNNI, IFMA, VPOPCNTDQ, VBMI, BF16; VMPSADBW, VMINMAX, saturating converts |
| **APX** | REX2, EGPRs R16-R31, NDD (3-operand), NF (no-flags), EVEX Map 4 |
| **Crypto / state / system** | AES, SHA1/256, GFNI (FIPS/SDM known-answer tested); XSAVE/XRSTOR/XCR0; CPUID, MSRs, CR/DR, descriptor-table loads, CPL-checked, faults injected (`#UD`/`#GP`) |

### Hexagon: complete, every opcode

A Qualcomm Hexagon (V73) implementation where **all 2,178 instruction opcodes are decoded, executed, and
differentially verified against qemu-hexagon at zero divergence**: scalar core, the full HVX vector set,
even the awkward corners (CABAC bin decode, scatter/gather, FP reciprocal/sqrt seed tables recovered from
the oracle). It takes the hard parts seriously:

- **VLIW packets** give true parallel-packet semantics: all instructions read the old register file and
  commit atomically at packet end; `.new` value forwarding for scalars *and* HVX vectors; duplex
  encodings; hardware loops (SA0/LC0, SA1/LC1) with circular and bit-reversed addressing; dual stores.
- **HVX** provides 1024-bit vectors V0-V31 and predicates Q0-Q3: ALU, compare, min/max, the full multiply
  family, permute, shift, round/saturate, LUT, histogram, vector-predicate ops, `vmem` loads/stores
  (`.cur`/`.tmp`, scalar-predicated), and V65 scatter/gather.

### RISC-V: small, correct, and bootable

A complete **RV64GC** core (~7k lines) wired into the VMM as a real `--arch riscv64 --backend emulator`
target: it loads an ELF, drives a 16550 UART over MMIO, and halts on `ecall`. Coverage is the **entire
RVA23 scalar set**: RV64I/M/A/F/D, **Zfh** half-precision, C (compressed), Zicsr/Zifencei,
Zba/Zbb/Zbc/Zbs, Zicond, Zfa, Zbkb/Zbkx/Zcb, the full scalar **crypto** suite (Zknh SHA-256/512, Zksh
SM3, Zksed SM4, Zkne/Zknd AES), and the vector *configuration* instructions (vsetvl\*, VLEN=128). The
floating-point core computes the round-to-nearest result, recovers the *exact* residual (2Sum / FMA /
Newton), and uses it to deliver correctly-rounded answers in all five rounding modes with all five IEEE
flags. It's checked against qemu-riscv64 by fuzzers that drive ~300k comparisons across the whole
non-control-flow opcode space.

### AArch64 / ARM: the deepest core

The largest and most thoroughly tested ISA, even though it isn't a runnable backend yet:

- **SVE** is **complete**: no valid SVE encoding is unhandled. The full data-processing set (predicate
  generation/logical, predicated integer & FP ALU, reductions, permutes, CPY/SEL/CMP, shifts), the
  entire memory subsystem (contiguous, gather/scatter, LD2-4/ST2-4, first-fault + FFR), all at VL=128.
- **SVE2** is broad and growing: long/wide/narrow integer ops, complex arithmetic, bit-permute,
  saturating multiplies, pairwise, FP conversions, indexed multiplies.
- **NEON / VFP**: full Advanced SIMD and scalar FP including FP16; full crypto (AES, SHA1/256, SM3, SM4).
- **AArch32 / Thumb-2 / Cortex-M (M0-M85)**: A32 + Thumb decoders, NVIC/SysTick/SCB/MPU, ARMv6-M → v8.1-M.

---

## Correctness: every architecture has an oracle

This is the part that matters. rax's claim is not "it implements a lot of instructions"; it is "the
instructions are *checked against an authority*." Each harness builds an initial architectural state,
runs one instruction (or a short sequence) on both rax and the reference from that identical state, then
diffs the full register file (and, for x86, a scratch memory page). Inputs are enumerated over encoding
fields and driven with many pseudo-random states, so a single `#[test]` function covers a large family.

| Harness | rax core | Oracle | `#[test]` fns | Compares |
|---------|----------|--------|-------------:|----------|
| `tests/differential.rs` | x86-64 | **KVM** (hardware) | 463 | GPRs, RIP, RFLAGS, XMM, memory |
| `tests/arm_diff.rs` | AArch64 + SVE/SVE2 | `qemu-aarch64` | 134 | X0-X30, SP, NZCV, V0-V31, P0-P15 |
| `tests/hexagon_*_diff.rs` | Hexagon (scalar / cf / float / mem / HVX / HVX-mem) | `qemu-hexagon` | 134 | GPRs, P3:0, USR, loop regs, V0-V31, Q0-Q3 |
| `tests/riscv_diff.rs` | RV64GC | `qemu-riscv64` | 29 | x1-x31, f0-f31, fcsr, scratch |
| `tests/diff_fuzz.rs` | SMIR (lift → interp / native) | KVM | 35 | guest state after lift+run |
| `tests/riscv_smir_lift.rs` | RISC-V → SMIR lift | rax RISC-V interp | 5 | x/f/fcsr (~150k insns, 0 divergence) |
| `tests/hexagon_smir_lift.rs` | Hexagon → SMIR lift | rax Hexagon interp | 305 | R/P/USR/V/Q (entire ISA: scalar + 100% HVX) |
| `tests/smir_jit_vcpu.rs` | SMIR JIT in the real vcpu | interpreter | 7 | register-for-register + throughput |

> **Good to know** Those `#[test]` counts understate the work by orders of magnitude. Each function
> enumerates many encodings and many random input states internally (the ARM and RISC-V fuzzers drive
> hundreds of thousands of comparisons per run). The reference harnesses are tiny C/asm programs
> (`tools/{arm,riscv,hexagon}-diff/`) that QEMU runs as ground truth; for x86 the ground truth is KVM.

### Tests by the numbers

On top of the oracles, there are exhaustive unit suites:

| Suite | Count | How |
|-------|------:|-----|
| **ARM (ASL-generated)** | 92,131 | generated from ARM's official machine-readable **ASL** spec via `tools/asl-parser/` |
| **x86-64 instruction suite** | 28,554 | `tests/x86_64/` (850 files), behind `--features x86_64-suite` |
| **Everything else** | ~1,500 | oracle + SMIR-lift harnesses, Hexagon bare-metal, RISC-V boot, crypto known-answer (FIPS/SDM) |
| **Total** | **122,151** | `#[test]` functions across `tests/` |

The ARM tests are not written by hand: the `asl-parser` downloads and parses ARM's ASL release and emits
exhaustive instruction tests from it, which is how 92,000+ ARM cases exist at all.

---

## SMIR and the hot-block JIT

**SMIR** (Sigma Machine IR, `src/smir/`, ~64k LOC; spec in
[`docs/specifications/smir/`](docs/specifications/smir/)) is the layer that makes "four CPUs" one
project. Each guest architecture has a *lifter* that translates its instructions into a common set of
100+ typed operations; the IR is interpreted directly, optimized, and, for x86-64, lowered to native
host machine code.

```text
  ┌─────────────────────────────────────────────────┐
  │   x86-64 · AArch64 · Hexagon · RISC-V · AVX10   │   per-arch lifters
  └────────────────────────┬────────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────┐
  │                   SMIR Module                   │   SmirFunction → SmirBlock → SmirOp
  └────────────────────────┬────────────────────────┘
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
     Interpreter       optimizer        x86-64 JIT → native
     (lazy flags)      (O0/O1/O2)       (emit · regalloc · W^X)
```

The native JIT is real and integrated. Behind the `smir-jit` feature, the `X86_64Vcpu` run loop
auto-detects hot loops (a back-edge counter promotes a region at a threshold of 64), lifts the region to
SMIR, lowers it to native x86-64, caches the compiled block, and runs it through a W^X `mmap` trampoline.
On the bench loop the lowered body is one native instruction per guest instruction: **~80× the
interpreter (~11,000 MIPS)**, bit-identical to interpreting it.

What makes that safe to ship is a **fail-safe whitelist**: only register-only operations that have been
proven equal to KVM (ALU, shifts, multiply, mov/extend, LEA, BSF/BSR, setcc/cmov, branches) are JIT-eligible. Anything
touching memory, division (the RDX:RAX double-width model isn't lowered yet), FP/SIMD, or an unknown op
makes the region **bail back to the interpreter**: it never executes natively unless it is known
correct. Self-modifying code invalidates compiled blocks via the MMU's dirty-page journal, and a
frontier-less spin loop is refused so native code can't trap the vcpu.

| Piece | Where | State |
|-------|-------|-------|
| **Lifters** | `lift/` | x86-64, AArch64, RISC-V, AVX10, and a lift-complete Hexagon (every opcode, scalar + 100% HVX, verified) |
| **Interpreter** | `interp.rs` | direct execution; lazy flags, block caching |
| **Optimizer** | `opt.rs` | dead-flag elimination, constant propagation, strength reduction |
| **JIT lowering** | `lower/x86_64.rs`, `lower/regalloc.rs`, `lower/runtime.rs` | x86-64 emitter, 1:1 register map, W^X exec runtime + trampoline |
| **JIT integration** | `backend/.../x86_64/cpu.rs` (`smir-jit`) | hot-loop detection, region cache, safety gate, SMC invalidation |

> **Good to know** The JIT accelerates without changing behaviour: a kernel boots identically with it on
> or off, because every region it can't prove correct degrades gracefully to the interpreter. What
> remains for a *general* JIT is memory-operand blocks (guest RAM mapped at host addresses), the
> double-width DIV model, and native block-to-block chaining.

> **Good to know** The lifters are checked too, not just the JIT's native output. `tests/riscv_smir_lift.rs`
> and `tests/hexagon_smir_lift.rs` lift each instruction to SMIR, interpret it, and diff against that
> architecture's own qemu-verified interpreter: RISC-V lifts the integer RV64GC set at zero divergence over
> ~150k instructions, and Hexagon lifts its entire ISA, every composable scalar op and all of HVX, across 305 verified families.

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
| **Decode cache** | 4096 entries indexed by RIP, keyed on a mode tag (`CR3 \| CS.L \| CS.D`). A hit reuses the cached bytes and **skips the guest-memory fetch entirely**. Kept coherent by SMC detection on guest writes. |
| **Lazy flags** | Arithmetic records its operands and defers RFLAGS materialization until a consumer (a `Jcc`, a `PUSHF`) reads them. Most computed flags are never needed. |
| **Fast paths** | A direct host-pointer path for physical RAM, a fast path for common ModR/M memory operands, and page-at-a-time `REP MOVS`/`STOS`. |
| **Hot-block JIT** | With `--features smir-jit`, hot loops promote to native code (see above). |
| **TLB** | 256-entry direct-mapped cache over the 4-level page walk (4 KiB / 2 MiB / 1 GiB pages). |

The interpreter sustains around **145 MIPS** on the register loop; the JIT tier lifts that to ~11,000 on
hot regions.

---

## Devices

The machine boots a full legacy PC platform, always on: a 16550 serial console (interrupt-driven, so
guest console input works), 8254 PIT, 8259 PIC, LAPIC + IOAPIC, RTC/CMOS, the 8237 DMA controller,
i8042 PS/2 keyboard, primary and secondary IDE, a floppy controller, system-control ports, QEMU
`fw_cfg`, and the Bochs-style debug port.

On top of that sits a functional **PCI host bridge** with BAR-mapped routing and an MMU MMIO aperture.
Pass `--pci-devices` and rax attaches real controllers that Linux enumerates and drives:

| Class | Device | Status |
|-------|--------|--------|
| **Network** | Intel e1000 (82540EM) | `eth0` comes up; Microwire EEPROM bit-banged via EECD |
| **Storage** | AHCI, NVMe, IDE | enumerate and bind; AHCI reports SATA link state correctly |
| **Audio / USB** | AC97, UHCI | enumerate as PCI endpoints |

> **Good to know** `--pci-devices` is opt-in, so the default boot stays byte-identical and the
> interpreter hot path is untouched (the MMIO aperture collapses to a no-op when no bridge is set). VGA
> is the one model still on the shelf: its legacy `0xA0000` window shadows guest RAM in the flat-memory
> model, and it is display-only, so it is pointless on a serial VM.

---

## Observability & tooling

Because the interpreter owns the step loop, the introspection tools see the real instruction stream:

| Tool | Flag / feature | What you get |
|------|----------------|--------------|
| **Interactive console** | on by default on a TTY | raw-mode serial console with a qemu-style `Ctrl-A` mux (`Ctrl-A s` checkpoints, `x` quits, `h` helps); termios restored even on panic or signal |
| **Machine checkpoints** | `Ctrl-A s` / `SIGUSR1` / `--snapshot-interval N`; resume with `--checkpoint <f.rxc>` | a self-contained `.rxc` image: embedded config + CPU + zstd RAM + every device's serialized state + a timing anchor. `rax --checkpoint m.rxc` brings a live machine back with no `--kernel` or `--config` |
| **Instruction trace** | `--trace <file>` (`--features trace`) | SDE-compatible per-instruction trace, diffable against Intel SDE |
| **GDB stub** | `--gdb <port> --wait-gdb` (`--features debug`) | Remote Serial Protocol server: registers, memory, stepping |
| **Profiler** | `--profile` (`--features profiling`) | per-mnemonic execution counts and a hot-instruction report, optional JSON export |

---

## Usage

```
--kernel <path>            Kernel image: ELF or bzImage (required)
--initrd <path>            Initial ramdisk
--arch <x86_64|riscv64|hexagon|…>   Target architecture (default x86_64)
--backend <kvm|emulator>   Virtualization backend (hvf on macOS)
--memory <size>            Guest memory, e.g. "512M", "2G"
--cmdline <string>         Kernel command line
--config <file>            Load a TOML config
--trace <file>             Write an SDE-compatible instruction trace   (--features trace)
--gdb <port> [--wait-gdb]  Start a GDB stub, optionally wait for attach (--features debug)
--pci-devices              Attach the optional PCI devices (e1000, AHCI, NVMe, UHCI, AC97)
--snapshot-interval <N>    Checkpoint every N instructions (0 = off)
--snapshot-out <file>      Where Ctrl-A s / SIGUSR1 checkpoints land (default checkpoint.rxc)
--checkpoint <file.rxc>    Resume a whole machine from a checkpoint (no --kernel/--config needed)
--profile [--profile-output <json>]   Instruction profiling             (--features profiling)
```

```toml
# config.toml
backend = "emulator"
memory  = "512M"
kernel  = "/path/to/vmlinux"
initrd  = "/path/to/initrd.cpio"
cmdline = "console=ttyS0 earlyprintk=serial"
```

---

## Building

```bash
# Default (Linux): KVM backend enabled.
cargo build --release

# Cross-platform: software emulator only, no KVM.
cargo build --release --no-default-features

# With the native hot-block JIT (x86-64 host).
cargo build --release --features smir-jit

# Fastest local interpreter (uses your host's full ISA).
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

> **Good to know** `.cargo/config.toml` ships `target-cpu=x86-64-v3` as a portable default. It still
> lets LLVM emit AVX2/BMI2/FMA and autovectorize the scalar SIMD/flag loops while staying runnable on any
> 2013-or-later x86-64 host. The release profile is fat-LTO, one codegen unit, `panic=abort`, stripped.

| Feature | Default | Enables |
|---------|---------|---------|
| `kvm` | ✓ (Linux) | KVM backend (`kvm-bindings` / `kvm-ioctls`) |
| `smir-jit` | | SMIR native hot-block JIT tier (x86-64 host; brings in the W^X exec runtime) |
| `trace` | | SDE-compatible instruction tracing |
| `debug` | | GDB Remote Serial Protocol server |
| `profiling` | | per-mnemonic profiler + JSON export |
| `x86_64-suite` | | the 28,554-case x86-64 instruction test suite |

---

## The microkernel test harness

`microkernel/` is a freestanding bare-metal x86-64 kernel used to exercise the interpreter end to end
without a full Linux image: an N-body physics simulation, a bump allocator, and broad instruction
coverage, the same binary runnable on rax and on Intel SDE for cross-checking.

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
├── cpu/            # VCpu trait, register/system state (x86 · hexagon · riscv), exit reasons
├── arch/           # boot protocols + loaders: x86_64/ · riscv.rs · hexagon · arm
├── backend/
│   ├── kvm/        # Linux hardware virtualization (HVF for macOS)
│   └── emulator/
│       ├── x86_64/ # ~50k LOC: decoder, mmu, flags, dispatch/{legacy,twobyte,vex,evex}, insn/ (88 files), JIT integration
│       ├── hexagon/# ~37k LOC: scalar core, VLIW packets, full HVX, every opcode verified
│       └── riscv/  # RiscVVcpu bridges the rax::riscv interpreter into the VMM
├── arm/            # ~48k LOC: aarch64 (complete SVE) · cortex_m · decoder · vfp · sysreg · cp15
├── riscv/          # ~10k LOC: RV64GC + RVA23 scalar · cpu · decode · rvc · float · csr · crypto · disasm
├── smir/           # ~64k LOC: ir · ops · types · interp · opt · lift/ · lower/ (x86_64 · regalloc · runtime)
├── devices/        # serial·pit·pic·lapic·ioapic·rtc·hpet·pci·fw_cfg  +  ahci·nvme·ide·virtio·e1000·vga·ac97·uhci·fdc·dma
├── gdb/            # Remote Serial Protocol server      (--features debug)
└── profiling/      # per-mnemonic profiler              (--features profiling)

tests/              # differential (x86↔KVM) · arm_diff/riscv_diff/hexagon_*_diff (↔QEMU) · smir_jit_vcpu · riscv_boot
                    # x86_64/ (28,554) · arm/generated (92,131, from ASL) · diff_fuzz · smir_avx10_roundtrip
tools/              # asl-parser (ARM ASL → tests) · arm-diff · riscv-diff · hexagon-diff (QEMU oracles)
microkernel/        # bare-metal x86-64 test kernel
docs/specifications/# smir/ (the IR spec) · riscv/ (vendored RISC-V specs) · arm/
```

---

## Status

| Path | State |
|------|-------|
| **x86-64 (KVM/HVF)** | Boots Linux to an interactive shell |
| **x86-64 (software)** | Boots Linux to a BusyBox shell; full modern ISA; 463 differential cases vs. KVM; native JIT (`smir-jit`) at ~80× on hot loops |
| **Hexagon** | **Every opcode** (scalar + HVX) verified vs. qemu-hexagon; bootable bare-metal backend |
| **RISC-V** | Full RVA23 scalar set + crypto; bootable `--arch riscv64` backend; verified vs. qemu-riscv64 |
| **AArch64 / ARM** | Complete SVE + broad SVE2 + NEON + Cortex-M; ~92k ASL tests; not yet a runnable backend |
| **SMIR** | JIT integrated, auto-triggered, fail-safe (register-only hot loops native, bit-exact vs. KVM); lifters verified for x86-64 / RISC-V; Hexagon lift-complete |
| **Platform** | Legacy PC devices wired; PCI host bridge + `--pci-devices` (e1000 `eth0`, AHCI/NVMe/UHCI/AC97); interactive console + full `.rxc` machine checkpoint/resume |

### What's missing

A production hypervisor this is not, by design. Only x86-64 boots a general-purpose OS, and the ARM
core, though the most thoroughly tested, is validated only through its oracle and isn't a runnable
backend yet. There is no SMP (one vCPU executes), VGA isn't wired (serial console only), and PCI
interrupts run in polled mode. The JIT covers register-only hot loops; memory-operand blocks,
double-width DIV, and native block chaining are future work. RISC-V lacks the RVV vector data path and
a privileged/Sv39 MMU. The **software** Linux boot reaches a BusyBox shell on a mitigations-off ELF
kernel; wider configurations (CFI/FineIBT, bzImage real-mode entry) are still being worked through, and
the KVM path boots cleanly throughout.

---

## A note on the name

`rax` is the x86-64 accumulator register, the first register the manuals introduce. The project started
x86-64-centric and the name stuck even as it grew three more instruction sets; it is also just the crate
name, so `cargo run` and you are off.

---

## See also

- [kvm-ioctls](https://github.com/rust-vmm/kvm-ioctls) / [kvm-bindings](https://github.com/rust-vmm/kvm-bindings): KVM access
- [linux-loader](https://github.com/rust-vmm/linux-loader) / [vm-memory](https://github.com/rust-vmm/vm-memory): boot protocol & guest memory
- [QEMU](https://www.qemu.org/): the user-mode reference oracle for AArch64, Hexagon, and RISC-V
- [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) · [Arm ASL](https://developer.arm.com/Architectures/A-Profile%20Architecture) · [RISC-V specs](https://riscv.org/technical/specifications/)
- [`docs/specifications/smir/`](docs/specifications/smir/): the SMIR IR specification

## License

MIT
