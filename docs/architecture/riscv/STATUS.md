[← Documentation home](../../../README.md)

# RISC-V in rax — Implementation Status

This is a historical ISA/JIT implementation report. Current execution scope
and qualifications are maintained in [RISC-V architecture](README.md) and
[Status and limitations](../../reference/status-and-limitations.md).
The report's completeness and proof terminology applies only to its named
corpora and compared state; self-skipped tests establish no comparison.
It does not inventory the newer RV64 Linux process personality (`rax-user`).

This document records the state of RISC-V support in rax across two layers:

1. **The interpreter** (`src/isa/riscv/`) — a self-contained, spec-faithful RV64
   software interpreter, differentially verified against `qemu-riscv64`.
2. **The SMIR lifter and x86-64 cross-JIT** (`src/smir/lift/riscv.rs`,
   `src/smir/lower/cross/riscv_guest_to_x86_64_host.rs`) — translation of
   RISC-V machine code to rax's SMIR and state-backed native x86-64 code.

Companion docs: [`REMAINING.md`](REMAINING.md) (interpreter roadmap — privileged
arch / MMU). The two verification harnesses compare their named finite corpora;
both fail on observed divergence and self-skip when their toolchain is absent.
They do not establish a formal correctness guarantee.

---

## 1. Interpreter (`src/isa/riscv/`)

A foundational RV64 interpreter structured to parallel `src/isa/arm/`, intentionally
decoupled from the VMM so the differential oracle drives it directly.

### Coverage

The **entire RVA23 unprivileged scalar ISA** plus the **complete RVV 1.0 vector
data path**:

| Group | Extensions |
|-------|-----------|
| Base + GC | RV64I, **M**, **A** (LR/SC + AMO), **F** + **D**, **C** (compressed) |
| FP | full IEEE-754, all 5 rounding modes; **Zfh** (half); integer-significand soft-float (`float.rs`) generic over `Fmt = {F16,F32,F64}`; **Q** decode/disassembly parity behind `Isa::q` with execution still trapping |
| Bit-manip | **Zba / Zbb / Zbc / Zbs**, **Zbkb** incl. RV32 `zip`/`unzip`, **Zbkx**, **Zcb** |
| Code-size / compressed adjuncts | **Zcmp / Zcmt / Zclsd / Zilsd** (explicit profile flags for overlap-prone encodings) |
| Conditional / FP-aux | **Zicond**, **Zfa** |
| Scalar crypto | **Zknh** (SHA-256/512), **Zksh** (SM3), **Zksed** (SM4), **Zkne/Zknd** (AES-32/AES-64) — S-box tables + GF(2⁸) |
| Atomics / cache / wait / hints | **Zacas**, **Zawrs**, **Zicbom / Zicboz / Zicbop**, **Zihintpause / Zihintntl** |
| CSR / fence / privileged decode | **Zicsr**, **Zifencei**, **JVT** CSR for Zcmt; `uret`, `sfence.vm`, `sfence.vma`, Svinval, and H fence/virtual-load-store opcodes decode/disassemble with flat-memory no-op or memory-access semantics |
| IDA compatibility | Opt-in `xida_sltw` flag for Hex-Rays/IDA's non-standard RV64 OP-32 `sltw` decode; disabled in `rv64gc()` because standard hardware reserves the encoding |
| Vendor custom | **Xsoteria**, **XHazard3** (`h3.block`/`h3.unblock`, `h3.bextm`/`h3.bextmi`), **XAndesPerf**, **XThead scalar**, **XTheadVdot** (`th.vmaqa*` executes; undocumented packed forms decode/disasm-only) |
| **Vector** | **V (RVV 1.0)** — see below |

### Vector (RVV 1.0) — the entire data path

`VLEN = 128` (matches qemu's default `vlenb = 16`), a flat `v[32×16]` register
file so LMUL groups and element strides index naturally. Implemented and verified
family-by-family (32 differential suites in `tests/suites/differential/riscv/vector.rs`):

- **Config**: `vsetvli` / `vsetivli` / `vsetvl` (vill, VLMAX, vl clamping)
- **Integer arithmetic**: add/sub/rsub, and/or/xor, min/max(u), shifts (vv/vx/vi)
- **Compares** → mask registers (`vmseq` … `vmsgt`)
- **Merge / move** (`vmerge`, `vmv.v.*`)
- **Multiply / divide**: `vmul`, `vmulh`/`vmulhu`/`vmulhsu`, `vdivu`/`vdiv`/`vremu`/`vrem` (div-by-zero / signed-overflow corners)
- **Fixed-point**: saturating add/sub (`vsadd…`, sets `vxsat`), averaging (`vaadd…`), scaling shifts (`vssrl`/`vssra`), fractional multiply (`vsmul`), narrowing clip (`vnclip…`) — all four `vxrm` rounding modes
- **Carry/borrow**: `vadc`/`vmadc`/`vsbc`/`vmsbc`
- **Integer extension**: `vzext`/`vsext` `.vf2/.vf4/.vf8`
- **FP arithmetic**: add/sub/rsub/mul/div/rdiv/min/max/sgnj/sqrt; all 8 **FMA** variants; `vfrsqrt7`/`vfrec7` (spec lookup tables); `vfclass`
- **FP compares** → mask
- **Reductions**: integer + FP (incl. ordered/unordered) and **widening** (`vwredsum…`, `vfwredsum…`)
- **Mask**: register logicals (`vmand…`), manipulation (`vcpop`/`vfirst`/`vmsbf`/`vmsif`/`vmsof`/`viota`/`vid`)
- **Scalar moves**: `vmv.x.s` / `vmv.s.x` / `vfmv.f.s` / `vfmv.s.f`
- **Permutes**: slides (incl. `vfslide1*`), gather (`vrgather`/`vrgatherei16`), `vcompress`
- **Widening integer**: add/sub (+ `.w`), multiply, multiply-accumulate (all signed/unsigned conventions)
- **Narrowing**: shifts + clip
- **Conversions**: single-width, widening, and narrowing `vfcvt`/`vfwcvt`/`vfncvt` (incl. `rtz` and round-to-odd)
- **Widening FP**: arithmetic, FMA
- **Whole-register move** (`vmv<nr>r.v`)
- **Load/store — all addressing modes**: unit-stride, strided, indexed, mask (`vlm`/`vsm`), whole-register, **segment** (unit/strided/indexed), and fault-only-first (`vleff`, non-fault path)

### Interpreter verification

The golden oracle is `qemu-riscv64` (user mode). Two static RV64 ELF oracles run
under qemu-user; a prologue loads register/vector state from a `MAP_FIXED` block,
runs one patched instruction, then `EBREAK`, and a `SIGTRAP` handler captures the
machine state and `siglongjmp`s back.

- `tools/riscv-diff/oracle.c` — scalar state (x/f/fcsr/pc). Reserves `x3/x4`
  (`gp`/`tp`) so the handler's glibc TLS survives.
- `tools/riscv-diff/voracle.c` — vector state (the V signal-frame context, magic
  `0x53465457`, holding `vstart/vl/vtype/vcsr/vlenb` + the 512-byte register
  file). Extended this session to load/capture **`vcsr`** so `vxsat`/`vxrm` are
  verified for the fixed-point families.

Test inventory (all green; self-skip without qemu + `riscv64-linux-gnu-gcc`):

- `tests/suites/differential/riscv/scalar.rs` — **29 scalar suites** including massive fuzzers
  (`diff_decode_fuzz` 140k words, `diff_mem_fuzz` 70k, `diff_fuzz_exhaustive` 90k,
  `diff_compressed_fuzz` 8k) → **~300k+ comparisons/run**, plus structured suites
  for FP, Zfh, crypto, bit-manip, Zicond, Zfa.
- `tests/suites/differential/riscv/vector.rs` — **32 vector suites**, every family above, across SEW
  8/16/32/64, vv/vx/vi/vf forms, masked/unmasked, all rounding modes; compares
  the full x/f/v register file + vl/vtype/fcsr/vcsr/scratch window.
- `tests/suites/machine/riscv_virt/boot.rs` — end-to-end VMM boot (UART @ `0x10000000`, `ecall`→halt).
- `cargo test --lib riscv::` — ~45 unit tests.

### VMM integration

`ArchKind::Riscv64`, `CpuState::RiscV`/`RiscVRegisters`, `src/machine/riscv_virt.rs`
(ELF/raw load, 16550 UART), `src/backend/emulator/riscv/cpu.rs` (`RiscVVcpu`).
Run with `--backend emulator`.

### Known limitation (interpreter)

Vector register-group **overlap / alignment illegal-instruction** traps are not
enforced — `rax` executes some encodings qemu rejects (widening/narrowing/gather
dest-vs-source overlap, EMUL>1 misalignment). A `PROBE` against qemu showed it
enforces alignment + source-source different-EEW rules *beyond* the written spec,
so a spec-faithful checker both over- and under-traps; matching qemu is
implementation reverse-engineering and was deliberately not shipped (affects only
illegal encodings no compiler emits). Privileged arch / Sv39 MMU / real
translation invalidation semantics: see
[`REMAINING.md`](REMAINING.md).
Quad-precision **Q** currently has decode/disassembly parity only. Executing Q
ops traps because the interpreter still stores FP registers as 64-bit values and
`float.rs` provides soft-float only for F16/F32/F64.

---

## 2. SMIR lifter (`src/smir/lift/riscv.rs`)

`RiscVLifter` (exposed as `rax::smir::RiscVLifter`) translates RISC-V machine code
to SMIR ops for the hot-block JIT.

### Verification harness — `tests/suites/smir/lift/riscv.rs`

For each instruction: lift to SMIR → run on `SmirInterpreter` from a seeded state
→ compare x/f/fcsr/scratch against the (qemu-verified) `RiscVCpu`. The interpreter
is the golden oracle, so no external toolchain is needed and encodings are
generated directly. **The test fails on any divergence**; an op the lifter doesn't
implement is reported as an honest *gap*, never silently mis-lifted.

> Architectural x/f/PC/CSR operands remain explicit `VReg::Arch` values. This
> matches the x86 and AArch64 lifters and is required by state-backed cross-JIT
> lowering: architectural destinations are committed directly to the persistent
> guest state, while instruction-local intermediates remain SSA virtual regs.

Historical five-sweep snapshot (**zero divergence across all of them**; counts
predate the opaque `RvFp`/`RvIntCrypto` additions):

| Sweep | matched | gap-ops | diverged |
|-------|---------|---------|----------|
| `lift_mem` (load/store/AMO) | 40000 | **0** | 0 |
| `lift_c` (compressed) | 20000 | **0** | 0 |
| `lift_op_imm` (OP-IMM/LUI/AUIPC) | 39993 | 1 | 0 |
| `lift_op` (OP/OP-32) | 30378 | 12 | 0 |
| `lift_fp` (FP load/store/op/fma) | 9690 | 99 | 0 |

### Lifted & verified

- **Integer**: RV64I; **M** — multiply, and **div/rem (64-bit + word) via a
  non-trapping `Select`-based sequence** (SMIR's `DivS`/`DivU` trap x86-`#DE` on
  zero; the sequence sanitizes the divisor and selects RISC-V's `/0`→all-ones &
  `MIN/-1`→`MIN`), plus **`mulhsu`** (= `mulhu − (a<0?b:0)`)
- **A**: LR/SC and all AMOs
- **C**: **100% complete** — base + Zcb (`c.mul`/`zext`/`sext`/`not`,
  `c.lbu`/`lhu`/`lh`/`sb`/`sh`) + compressed FP load/store (`c.fld`/`c.fsd`)
- **Zba / Zbb / Zbs / Zicond**: decode-driven `lift_zb_op`/`lift_zb_imm`/
  `lift_zb_imm32` (reuse the rax decoder for the precise `Op`); `andn`/`orn`/
  `xnor`, rotates, min/max, sh-add(.uw), bset/clr/inv/ext, clz/ctz/cpop, sext/
  zext, **`rev8`/`brev8`** (`brev8 = bswap(rbit(x))`), `czero.eqz/nez`
- **Zbkb**: `pack`/`packh`/`packw`
- **Zk-hash**: **SHA-256/512 + SM3** (`crypto_xor3` — rotate/xor folds)
- **FP — the entire fflags/rounding-free subset** (bit ops on the f-register
  VRegs): `FMV.*` moves, `FSGNJ/N/X.S/D/H` (sign inject; `.S`/`.H` canonicalize
  an improperly-NaN-boxed operand via an `unbox` `Select`), `FLW`/`FLD`/`FLH`/
  `FSW`/`FSD`/`FSH` load/store, and **`FCLASS.S/D/H`** (10-bit classify)

### Bugs found & fixed (caught by the harness)

1. `FlatMemory::atomic_rmw` did signed min/max on full-64-bit values regardless of
   access width and didn't mask the operand → `AMOMIN/MAX.W` wrong. Now width-
   masks operands and sign-extends from `size` (fixes **all** architectures' AMOs).
2. AMOs with `rd == x0` skipped the **entire** op, dropping the memory RMW (RISC-V
   still performs it). Now always emits the RMW with a throwaway destination.
3. The C-extension sign-extended 6-bit immediates from bit 7 (`as i8`) instead of
   bit 5 → `c.addi`/`c.addiw`/`c.li`/`c.andi` off by 64 for negative immediates.
4. Word AMO/LR results were not sign-extended into `rd`.
5. The original lifter silently mis-lifted bit-manip variants as base shifts
   (e.g. `rori` as `srai` — it checked `funct7` bits that overlap the 6-bit
   `shamt`). Now anything that isn't a base op routes to the decode-driven path,
   so the lifter **never emits a wrong op** — it lifts correctly or returns
   `Unsupported`.

### Opaque architecture-exact operations

The former SMIR-op-set gaps are represented by explicit RISC-V operations:

- `RvFp` evaluates scalar FP/FMA with RISC-V rounding, NaN canonicalization,
  and FCSR/fflags updates;
- `RvIntCrypto` evaluates AES, SM4, carry-less multiply, and XPERM families;
- `RvVector` evaluates RVV while explicitly threading the scalar x/f/CSR
  register state required by vector/scalar transfer operations.

These operations are exact in `SmirInterpreter`; `RvIntCrypto`, scalar `RvFp`,
and `RvVector` also have the bounded helper-backed x86-64 lowering described
below. The vector boundary transfers the complete scalar, floating-point,
128-bit vector-register, and vector-CSR state for one instruction.

---

## 3. x86-64 cross-JIT lowering

`RiscVX86_64Lowerer` uses an explicit
`extern "sysv64" fn(*mut RiscVGuestRegs)` ABI;
it does not reuse the x86-guest identity-register ABI. The 1168-byte state holds
`x[32]`, `f[32]`, PC, FCSR, exit classification, memory context, scalar
load/store and atomic helper pointers, pure scalar integer-crypto and
floating-point helper pointers, `v[32][16]`, `vl`, `vtype`, `vstart`, `vcsr`,
and the vector helper pointer. Reads of x0 are hard-wired to zero, writes are
discarded, and the externally visible x0 backing slot is canonicalized on
entry.

When the x86-64 test/runtime binary is translated by Rosetta, released JIT
mappings are changed to `PROT_NONE` and advised for physical-page discard while
their virtual addresses remain reserved. This prevents Rosetta from aliasing a
stale translated block when parallel lowerings rapidly recycle executable
addresses; native x86-64 and non-macOS execution still unmap normally.

Implemented native scalar families:

- RV32/RV64 integer move, add/sub, Boolean operations, shifts and rotates;
- compare/SETcc/select, zero/sign extension, CLZ/CTZ/CPOP, byte/bit reversal;
- M-extension low/high multiply and quotient/remainder, including totalized
  divide-by-zero and signed-overflow paths that cannot raise host `#DE`;
- f-register bit moves/sign injection/classification and FCSR CSR access (the
  generic, rounding-free scalar-FP subset);
- all 91 scalar `RvFp` operations through a two-register helper result that
  preserves exact NaN boxing/canonicalization, five rounding modes, accrued
  `fflags`, half precision, and traps before architectural writes for invalid
  static or dynamic rounding modes;
- scalar loads/stores through the guest-memory helper ABI; load returns
  `{value, success}` and store returns `success`, so a failed access exits at
  the faulting guest PC with the generic trap classification before committing
  a destination or any store bytes;
- A-extension AMO, AMOCAS, and LR/SC through indivisible helper calls; the ABI
  carries exact operation, width, and memory-order codes and preserves the
  two-register results. AMO/LR/SC distinguish access completion from the
  architectural result, while CAS distinguishes fault, compare failure, and
  swap success; faults exit before result commit;
- direct conditional native CFG, indirect dispatcher exits, exact caller-supplied
  resume PCs for 16-bit compressed instructions, and classified trap/syscall/
  breakpoint exits.

`tests/suites/smir/jit/riscv_x86_64.rs` performs the complete machine-code →
lift → lower → W^X execute path and compares x-registers, PC, and memory against
`RiscVCpu` at both O0 and O2. The corpus covers RV64I ALU/branch/load/store,
M-extension high/low multiply and signed/unsigned divide/remainder (including
`/0` and `MIN/-1`), Zbb rotate/count operations, word operations, JAL/JALR,
compressed PC advance, FP bit operations and FCSR access, every RV32/RV64 AMO
operation and ordering code, AMOCAS success/failure, and LR/SC
success/reservation-failure paths. It also covers all 24 `RvIntCrypto` operation
codes across RV32/RV64, every SM4/AES32 byte selector, and every legal AES64KS1I
round immediate. The scalar-FP corpus round-trips all 91 helper ABI selectors at
O0/O2 and separately lifts representative arithmetic, FMA, min, compare, and
integer/float conversion encodings, including dynamic rounding and invalid-mode
trap paths. RVV tests cover RV32/RV64 vector configuration, arithmetic,
integer/floating scalar transfers, vector loads/stores, current SSA scalar
sources, and the complete vector state round-trip at O0/O2. Scalar, atomic, and
vector out-of-range accesses are forced through their status paths and checked
for no register or memory commit; noncanonical statuses fail closed. The
generated count sequence is baseline x86-64 and does not require host `POPCNT`.
Remaining native gaps are detailed fault-cause reporting, a production
dispatcher/helper provider, and architectural vector memory restart/partial-
completion reporting beyond the current transactional helper failure contract.

The LR/SC reservation is owned by the helper context. Cross-hart or device writes
must invalidate it in the memory backend; the in-tree differential helper models
the current single-hart `RiscVCpu` behavior and verifies reservation replacement,
missing reservations, width/address mismatch, and clearing after SC.

## 4. Commit index (this session, RISC-V-specific)

**Vector data path (interpreter):** `521d6ff` config · `5a1825f` basic ld/st +
int arith · `f4ac4a3` min/max/shift/merge · `3d5aec9` compares · `4dedf44`
mul/div · `79e6bff` FP · `1484a20` FMA · `deba9b5` int reductions · `94f4a32` FP
reductions · `e3d6fe8` scalar moves · `9543e6c` mask logicals · `da157bb`
zext/sext · `a29141e` mask manip · `053b2ff` slides · `97fd740` gather ·
`54795fb` compress · `85c511f` carry/borrow · `29fb294` sat add/sub (+vcsr
harness) · `a6a2750` averaging · `4b7e58e` scaling/vsmul · `906ed62` widening
add/sub · `2cf150b` widening mul · `16e797f` narrowing shift/clip · `816d9cb`
single-width conv · `8b8fee4` widening conv · `e6fc31c` narrowing conv ·
`4d96619` widening FP arith · `bbee9cd` widening FP FMA · `2b5055a` widening
reductions · `1482ffe` vfclass + whole-reg move · `959e54d` advanced ld/st ·
`592c9a2` segment ld/st · `c7530a5` vfrsqrt7/vfrec7 · `29bf643` fault-only-first.

**SMIR lift:** `cc9757b` harness + shift/div/atomic fixes · `15547e0`
Zba/Zbb/Zbs/Zicond · `acaecc7` bit-manip immediates · `b3a34b0` C-ext immediate
sign-ext fix · `a8d9449` SHA/SM3 · `453122e` pack · `751486d` word div/rem ·
`8b3693d` brev8/mulhsu · `fcaf30e` + `75af4d6` Zcb · `ebe64ef` FP load/store +
moves/sign · `684f5d5` compressed FP load/store · `a3fc2d5` `.S`/`.H` sign-inject
· `90792cc` fclass.

---

## Summary

The **unprivileged RV64GCV ISA is comprehensively implemented and verified** in
the interpreter (29 scalar + 32 vector differential suites + ~300k fuzz
comparisons/run, all at zero divergence vs qemu). The **SMIR lift covers the
scalar, compressed, atomic, FP, crypto, and vector families**, using explicit
architecture-exact opaque ops where generic SMIR primitives cannot carry the
required RISC-V state. The state-backed x86-64 cross-JIT executes the admitted
scalar integer/control/memory and atomic families directly, and crosses bounded
helper ABIs for every scalar-FP, integer-crypto, and RVV opaque operation.
Production dispatcher/helper integration, detailed fault causes, and RVV
partial-completion/restart reporting remain. Privileged translation/MMU
execution remains a separate interpreter/VMM scope described in `REMAINING.md`.
