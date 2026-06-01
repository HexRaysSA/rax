<h1 align="center">rax</h1>

<h5 align="center">
rax is an x86-64 CPU you can read. It boots a real Linux kernel two ways: through hardware<br/>
virtualization — KVM on Linux, Hypervisor.framework on macOS — at near-native speed, or through a<br/>
from-scratch software interpreter that executes (and lets you trace, single-step, snapshot, and<br/>
profile) every instruction the kernel runs.<br/>
<br/>
The interpreter covers almost the entire modern x86-64 surface — out to AVX-512, AVX10.1/10.2, and<br/>
Intel APX — and it does not take its own word for any of it: a differential harness runs the same<br/>
machine code on KVM and on the interpreter from an identical state and compares the result, so the<br/>
silicon is the oracle. ARM/AArch64 and Hexagon front-ends ride alongside, and a shared multi-architecture<br/>
IR (SMIR) lifts all three toward one interpreter and one future JIT.
</h5>

<div align="center"><code>Rust</code> • <code>x86-64 · AArch64 · Hexagon</code> • <code>KVM · HVF · software</code> • <code>boots Linux</code> • <code>120k+ tests</code></div>

---

## The thirty-second version

Build it, then run a kernel — at silicon speed, or one instruction at a time:

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

Both backends share the same memory model, device set, and Linux boot protocol. The only thing that
changes is whether instructions run on your CPU or on rax's.

---

## Why it exists

If you have ever wondered what actually happens between pressing Enter on a kernel image and seeing a
shell, most tools give you one of two unsatisfying answers. A real hypervisor (QEMU/KVM) runs the kernel
so fast you cannot watch it; the CPU is a black box. A pure emulator (Bochs, Unicorn) lets you watch, but
its instruction coverage trails the hardware by years and you have no easy way to know whether what it
*did* matches what a real chip would have done.

rax is built to be both halves at once:

- **The KVM/HVF backend** runs the kernel on real hardware virtualization. It is the fast path, and — more
  importantly — it is the *reference*. When you want to know what an instruction "should" do, you ask the
  silicon.
- **The software backend** is a complete x86-64 interpreter written from scratch in Rust. It decodes and
  executes one instruction at a time, so it can trace, single-step, snapshot, count, and profile anything —
  including the parts of a boot that a real CPU executes far too quickly to observe.

Because the two backends accept the *same* architectural state, you can run a sequence on both and diff
the outcome. That is not a debugging convenience bolted on after the fact; it is the project's correctness
model. Every interpreter instruction is, in principle, falsifiable against the chip in your machine.

The result is a CPU implementation that is legible — you can open `insn/arith/add.rs` and read exactly
what `ADD` does to flags — without being a toy: it tracks the instruction set out to APX and AVX10.2, and
it is checked against tens of thousands of cases.

---

## What a run looks like

A throughput benchmark of the interpreter's hot path (`examples/bench_loop.rs`, a tight register-only
guest loop) reports sustained MIPS — the apples-to-apples metric for interpreter work:

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

> **Good to know** The trace, the GDB stub, the snapshot facility, and the per-mnemonic profiler are all
> wired into the *interpreter's* step loop, so they observe the genuine instruction stream — not a
> re-derived approximation of it. The KVM backend traps only on I/O, so it is fast but opaque by design.

---

## What it covers

rax is a multi-architecture machine. x86-64 is the primary, most complete target; ARM and Hexagon are
substantial and growing; everything funnels toward SMIR, the shared IR.

| Layer | What it is | Status |
|-------|-----------|--------|
| **x86-64 emulator** | ~48k LOC software CPU: full decoder + 88 instruction-implementation files | Near-complete ISA, validated vs. KVM |
| **ARM emulator** | ~37k LOC: AArch64, ARMv7-A, ARMv8 AArch32, Cortex-M; VFP/NEON, system regs, CP15 | Large ISA subset, ASL-tested |
| **Hexagon emulator** | ~19k LOC VLIW/DSP front-end | Bare-metal test corpus runs |
| **SMIR IR** | ~35k LOC retargetable IR: lift → optimize → interpret (JIT scaffolded) | Lifters for x86-64 / AArch64 / Hexagon / RISC-V / AVX10 |
| **KVM backend** | Linux hardware virtualization | Boots Linux to an interactive shell |
| **HVF backend** | macOS Hypervisor.framework (libc FFI) | Present |

### x86-64 instruction coverage

| Category | Instructions | Notes |
|----------|--------------|-------|
| **Integer** | ADD, SUB, ADC, SBB, CMP, INC, DEC, NEG, MUL, IMUL, DIV, IDIV, ADCX, ADOX | all operand forms; `#DE` on overflow/÷0 |
| **Logic / bit** | AND, OR, XOR, TEST, NOT, BT/BTS/BTR/BTC, BSF, BSR, POPCNT, LZCNT, TZCNT | register and memory |
| **Shifts / rotates** | SHL, SHR, SAL, SAR, ROL, ROR, RCL, RCR, SHLD, SHRD | by 1, CL, or imm8 |
| **Data movement** | MOV, LEA, MOVZX/SX/SXD, XCHG, CMPXCHG, BSWAP, PUSH/POP, ENTER/LEAVE | all addressing modes |
| **Control flow** | JMP, CALL, RET/RETF, Jcc, LOOP, SETcc, CMOVcc | all conditions |
| **Strings** | MOVS, STOS, LODS, SCAS, CMPS | with REP/REPE/REPNE, bulk fast path |
| **BCD** | DAA, DAS, AAA, AAS, AAM, AAD | legacy |
| **x87 FPU** | FLD, FST, FADD, FSUB, FMUL, FDIV, FCOM, … | escape codes D8–DF, via f64 |
| **SSE → SSE4** | MOV*, ADD/SUB/MUL/DIV/SQRT, CMP* (all predicates), MIN/MAX, shuffle/convert | XMM |
| **AVX / AVX2** | VEX-encoded SSE forms, integer ops, permute (VPERM2F128, VINSERT/EXTRACTF128) | XMM/YMM |
| **FMA** | VFMADD/SUB/NMADD/NSUB {132,213,231}{ps,pd,ss,sd} | fused multiply-add |
| **BMI1 / BMI2** | ANDN, BEXTR, BLSI/MSK/R, BZHI, SARX/SHRX/SHLX, RORX, PEXT, PDEP, MULX | |
| **AVX-512** | VMOVDQU32/64, VPADDD, VPORD/XORD, masked ops, opmask k0–k7 | F, VL, BW, DQ, CD |
| **AVX10.1** | VNNI (VPDPBUSD/WSSD), IFMA, VPOPCNTDQ, VBMI, BF16 | |
| **AVX10.2** | VMPSADBW, VMINMAX, saturating converts, media acceleration | |
| **APX** | REX2 prefix, EGPRs R16–R31, NDD (3-operand), NF (no-flags) | EVEX Map 4 |
| **Crypto** | AESENC/DEC/IMC/KEYGENASSIST, SHA1/SHA256 rounds, GFNI (GF2P8*) | FIPS/SDM known-answer tested |
| **State** | XSAVE/XRSTOR, XCR0, FXSAVE | |
| **System** | CPUID, RDMSR/WRMSR, MOV CR/DR, LGDT/LIDT, INVLPG, SWAPGS, RDTSC(P) | CPL-checked; `#UD`/`#GP` injected |

The decoder handles the full encoding zoo: REX and REX2 prefixes, every legacy prefix (operand-size,
address-size including `0x67`, REP, segment overrides), ModR/M + SIB, VEX2/VEX3, EVEX (including APX
Map 4), and RIP-relative addressing.

### Registers modeled

GP RAX–R15 and APX R16–R31 · XMM0–31 / YMM0–31 / ZMM0–31 (upper halves tracked) · opmask K0–K7 ·
x87 ST(0)–ST(7) + status/control/tag · CR0–CR4/CR8, DR0–DR7, EFER, XCR0, GDT/IDT, segment registers.

### Devices

Just enough hardware to bring up Linux and probe cleanly:

| Device | Ports / MMIO | Role |
|--------|--------------|------|
| Serial 16550 | `0x3F8–0x3FF` | console I/O, interrupt-driven |
| PIT 8254 | `0x40–0x43` | system timer, IRQ 0 |
| PIC 8259 | `0x20–0x21`, `0xA0–0xA1` | master/slave interrupt controllers |
| LAPIC | `0xFEE00000` (MMIO) | local APIC + timer |
| HPET | MMIO | high-precision event timer |
| i8042 | `0x60`, `0x64` | PS/2 keyboard / mouse controller |
| RTC / CMOS (MC146818) | `0x70–0x71` | real-time clock |
| System control | `0x92`, `0xCF9`, `0x61`, `0x80` | A20, reset, NMI, POST |
| PCI | `0xCF8–0xCFF` | config-space stub |
| Debug | `0xE9` | Bochs-style port-E9 output |

---

## How it works

### The Linux boot protocol

Both backends bring a kernel to its 64-bit entry point the same way:

1. Load the kernel (ELF or bzImage) at physical `0x1000000` (16 MiB) and the initrd at `0x4000000`.
2. Build initial page tables: identity-map the first 8 GiB with 1 GiB huge pages, kernel space at
   `0xFFFFFFFF80000000`, direct physical map at `0xFFFF888000000000`.
3. Install a minimal GDT with 64-bit code/data segments.
4. Enter long mode (`CR0.PG=1`, `CR4.PAE=1`, `EFER.LME=1`) and jump to the kernel's entry.

### The interpreter loop

The software CPU is the usual fetch/decode/execute, with two twists that make it both fast and honest:

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
| **Decode cache** | 4096 entries indexed by RIP, keyed on a mode tag (`CR3 \| CS.L \| CS.D`). A hit reuses the cached instruction bytes and **skips the guest-memory fetch entirely** — the single biggest hot-path win. Kept coherent by SMC detection on guest writes and a full flush on external state changes. |
| **Lazy flags** | Arithmetic records its operands and defers RFLAGS materialization until a consumer (a `Jcc`, a `PUSHF`) actually reads them. Most computed flags are never needed. |
| **TLB** | 256-entry direct-mapped cache over the 4-level page walk (4 KiB / 2 MiB / 1 GiB pages, cross-page handling). |
| **Host-pointer fast path** | Accesses to physical RAM resolve straight to a host pointer, bypassing the `vm-memory` round-trip. |
| **Bulk string ops** | `REP MOVS`/`STOS` copy page-at-a-time instead of one element per iteration. |
| **Deterministic TSC** | RDTSC is `insn_count × 3000` — reproducible across runs, and enough to satisfy kernel delay loops. |

> **Good to know** The interpreter raises real faults: a bad encoding injects `#UD`, a privilege
> violation injects `#GP`, a divide overflow raises `#DE` — it does not abort the VM. CPL checks gate the
> privileged instructions. This is what lets it run guest fault handlers instead of falling over.

---

## Correctness: the silicon is the oracle

rax's headline feature is not an instruction count — it is *how the instructions are checked*.

### Differential testing against KVM

`tests/differential.rs` is the centerpiece. Each case is a short machine-code sequence ending in `HLT`.
The harness builds one identity-mapped long-mode initial state, then runs the sequence on **both** the
software interpreter and **KVM**, and compares the final architectural state — GPRs, RIP, the
architecturally-defined RFLAGS status bits, XMM registers, and a scratch memory page. Any divergence is
an interpreter bug, reported precisely.

> **Good to know** If `/dev/kvm` cannot be opened, every differential case self-skips rather than failing,
> so the suite stays green in CI and on non-Linux hosts. Execution on both backends is iteration-bounded,
> so a buggy case can never hang the run.

### Tests, by the numbers

| Suite | Count | How |
|-------|------:|-----|
| **x86-64 instruction suite** | **27,975** | 850 files under `tests/x86_64/`, gated behind `--features x86_64-suite` |
| **ARM suite** | **92,131** | hand-written + **auto-generated from ARM's official ASL** specifications |
| **Differential (vs. KVM)** | 48 | interpreter-vs-silicon parity |
| **SMIR AVX10 round-trip** | 48 | lift → IR → lower fidelity |
| **Total** | **120,399** | `#[test]` functions across `tests/` |

The ARM tests are not written by hand. `tools/asl-parser/` parses ARM's machine-readable **ASL**
(Architecture Specification Language) release and generates exhaustive instruction tests from it — which
is how 92,000+ ARM cases exist at all. The crypto instructions (AES, SHA, GFNI) are checked against
**FIPS / Intel SDM known-answer vectors**, not just self-consistency.

```bash
cargo test --release --features x86_64-suite --test x86_64   # the x86-64 suite
cargo test --release --test differential                     # interpreter vs. KVM (Linux + /dev/kvm)
cargo test --release --test smir_avx10_roundtrip             # IR round-trip
```

---

## SMIR — the shared IR

**SMIR** (Sigma Machine IR) is a multi-architecture intermediate representation (`src/smir/`, ~35k LOC;
spec in [`docs/specifications/smir/`](docs/specifications/smir/)). Each guest architecture has a *lifter*
that translates its instructions into a common set of ~150 typed operations; the IR can then be
interpreted directly today and lowered to native code in the future.

```text
  x86-64        AArch64        Hexagon        RISC-V
    │              │              │              │
    ▼              ▼              ▼              ▼
 ┌──────────────────────────────────────────────────┐
 │                     Lifters                      │
 └───────────────────────┬──────────────────────────┘
                         ▼
                ┌──────────────────┐
                │   SMIR Module    │   SmirFunction → SmirBlock → SmirOp
                └────────┬─────────┘
            ┌────────────┼────────────┐
            ▼            ▼            ▼
       Interpreter   JIT (future)  Analysis / opt passes
```

| Piece | Where | What |
|-------|-------|------|
| **IR + types** | `ir.rs`, `ops.rs`, `types.rs` | modules/functions/blocks/ops, virtual registers, the type lattice (i8…i64, f32/f64, v128/256/512, ptr, flags) |
| **Lifters** | `lift/` | x86-64, AArch64, Hexagon, RISC-V, and a dedicated AVX10 lifter |
| **Lowerers** | `lower/` | x86-64 emitter + register allocation (JIT groundwork) |
| **Interpreter** | `interp.rs` | direct execution with lazy flags |
| **Optimizer** | `opt.rs` | dead-flag elimination, constant propagation, and friends |

> **Good to know** SMIR's design target is <2× the cost of direct interpretation while staying
> JIT-ready — lazy flags and unified addressing are in the IR, not bolted on per architecture.

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

### CLI options

```
--kernel <path>            Kernel image: ELF or bzImage (required)
--initrd <path>            Initial ramdisk
--backend <kvm|emulator>   Virtualization backend (hvf on macOS)
--arch <x86_64|hexagon|…>  Target architecture
--memory <size>            Guest memory, e.g. "512M", "2G"
--vcpus <N>                Number of vCPUs
--cmdline <string>         Kernel command line
--config <file>            Load a TOML config
--trace <file>             Write an SDE-compatible instruction trace   (--features trace)
--gdb <port> [--wait-gdb]  Start a GDB stub, optionally wait for attach (--features debug)
--snapshot-interval <N>    Snapshot every N instructions (0 = off)
--snapshot-at <a,b,c>      Snapshot at specific instruction counts
--snapshot-dir <dir>       Where to write snapshots
--resume <file>            Resume from a snapshot
--profile [--profile-output <json>]   Instruction profiling             (--features profiling)
```

### TOML config

```toml
arch    = "x86_64"
backend = "emulator"
memory  = "512M"
vcpus   = 1
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

> **Good to know** `.cargo/config.toml` ships `target-cpu=x86-64-v3` as a portable default — it still lets
> LLVM emit AVX2/BMI2/FMA and autovectorize the scalar SIMD/flag loops (most of the codegen win) while
> staying runnable on any 2013-or-later x86-64 host. For a benchmark on the machine you're sitting at,
> prefer `target-cpu=native`. The release profile is fat-LTO, one codegen unit, `panic=abort`, stripped.

### Feature flags

| Feature | Default | Enables |
|---------|---------|---------|
| `kvm` | ✓ (Linux) | KVM backend (`kvm-bindings` / `kvm-ioctls`) |
| `trace` | | SDE-compatible instruction tracing |
| `debug` | | GDB Remote Serial Protocol server |
| `profiling` | | per-mnemonic profiler + JSON export |
| `x86_64-suite` | | the 27,975-case x86-64 instruction test suite |

---

## The microkernel test harness

`microkernel/` is a freestanding bare-metal x86-64 kernel used to exercise the interpreter end to end
without a full Linux image — an N-body physics simulation, a bump allocator, and broad instruction
coverage, the same binary runnable on rax and on Intel SDE for cross-checking.

```bash
cd microkernel
make baremetal     # build the bare-metal ELF
make test-rax      # boot it in the rax software emulator
make test-sde      # run it under Intel SDE (usermode build) for a reference trace
```

---

## Status

| Path | State |
|------|-------|
| **KVM backend** | Boots Linux to an interactive shell |
| **Software x86-64 interpreter** | Runs the full modern ISA; validated instruction-by-instruction against KVM; runs the bare-metal microkernel; driving toward a complete software Linux boot |
| **ARM / AArch64** | Large ISA subset, ~92k ASL-generated tests |
| **Hexagon** | VLIW/DSP front-end, bare-metal corpus |
| **SMIR** | Lifters + interpreter + optimizer; JIT lowering scaffolded |

### What's missing

A production hypervisor this is not — by design. There is no SMP (one vCPU executes), no full APIC bus
(basic interrupt routing only), and no disk/network/graphics devices. The software emulator's full
Linux boot is still being chased down (the last known sticking point is fixmap virtual-address
computation during early kernel init); the KVM path boots cleanly.

---

## A note on the name

`rax` is the x86-64 accumulator register — the first thing the manuals introduce and the place results
accumulate. For a project whose whole job is to implement that instruction set faithfully, it seemed
like the right register to name it after. It is also just the crate name: `cargo run` and you are off.

---

## See also

- [kvm-ioctls](https://github.com/rust-vmm/kvm-ioctls) / [kvm-bindings](https://github.com/rust-vmm/kvm-bindings) — KVM access
- [linux-loader](https://github.com/rust-vmm/linux-loader) / [vm-memory](https://github.com/rust-vmm/vm-memory) — boot protocol & guest memory
- [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) — the x86-64 reference rax implements
- [`docs/specifications/smir/`](docs/specifications/smir/) — the SMIR IR specification

## License

MIT
