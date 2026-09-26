[← Documentation home](../../../README.md)

# RISC-V (`rax::isa::riscv`) — Remaining Work

This is an ISA/privileged-machine roadmap snapshot. Current runtime scope is
maintained in [RISC-V architecture](README.md): `rax-user` runs RV64 Linux
programs without a privileged Linux-capable machine. Completeness language
below describes the named historical instruction corpora, not exhaustive
architectural conformance or the Linux syscall personality.

Status snapshot for the self-contained RISC-V interpreter at `src/isa/riscv/`. The
**user-mode ISA is complete and differentially verified** against `qemu-riscv64`;
what remains is privileged/system architecture, a few illegal-encoding fidelity
gaps, and additional (mostly optional) extensions.

## Done (for context)

- **RV64GC**: I, M, A (LR/SC + AMO), F + D, C (compressed).
- **FP**: full IEEE-754 incl. **Zfh** (half), all 5 rounding modes, integer-significand
  soft-float in `float.rs` generic over `Fmt = {F16, F32, F64}`.
- **Bit-manip / crypto**: Zba/Zbb/Zbc/Zbs, Zicond, Zfa, Zbkb, Zbkx, Zcb, and full
  **scalar crypto** (Zknh SHA-256/512, Zksh SM3, Zksed SM4, Zkne/Zknd AES-32/AES-64).
- **Zicsr + Zifencei**, user-visible counters (cycle/time/instret read paths).
- **V (RVV 1.0) — the entire data path**: config (`vsetvl*`), all integer/FP
  arithmetic, multiply/divide, FMA, reductions (incl. widening), fixed-point
  (sat/avg/scaling/clip with `vxsat`/`vxrm`), mask ops, permutes (slide/gather/
  compress), widening/narrowing, all conversions (`vfcvt`/`vfwcvt`/`vfncvt` incl.
  rtz + round-to-odd), `vfrsqrt7`/`vfrec7`, and **all load/store addressing modes**
  (unit/strided/indexed/mask/whole-register/segment + `vleff`).
- **Verification**: 29 scalar + 32 vector differential suites
  (`tests/suites/differential/riscv/scalar.rs`,
  `tests/suites/differential/riscv/vector.rs`) + ~45 lib unit tests, all green. Oracles:
  `tools/riscv-diff/{oracle,voracle}.c` (static RV64 ELF run under qemu-user;
  SIGTRAP handler captures the register/vector frame).

---

## Tier 1 — Privileged architecture + MMU (needed to boot Linux)

This is the single largest remaining frontier. The current privileged support is a
**minimal M-mode trap model only**: `mstatus/mtvec/mepc/mcause/mie/mip/medeleg/
mscratch` exist, synchronous trap entry into M-mode works, and `mret` restores
state. `sret` currently **aliases** `mret` (single-mode model — see
`cpu.rs` "single-mode model: same restore path"). There is **no S-mode and no
address translation**.

Concretely missing:

- **S-mode CSRs**: `sstatus, stvec, sepc, scause, stval, sscratch, sie, sip,
  satp, scounteren` (none are in `csr.rs`). Proper `sret` distinct from `mret`.
- **Trap delegation**: `mideleg` wiring, interrupt vs. exception routing to S-mode,
  `mstatus` SUM/MXR/SPP/SPIE semantics, `mstatus.TVM/TW/TSR`.
- **Sv39 (and Sv48/Sv57) page-table walk + TLB**: `satp` MODE/ASID/PPN, multi-level
  walk, A/D bit updates, permission checks (R/W/X/U), page-fault causes
  (12/13/15), and real TLB invalidation for `sfence.vma`/Svinval/HINVAL. The
  invalidation opcodes decode and execute as flat-memory no-ops today.
- **Interrupt controllers**: CLINT (mtime/mtimecmp/msip) and PLIC (external
  interrupt claim/complete). Timer interrupts (`mip.MTIP/STIP`).
- **SBI** (Supervisor Binary Interface): `ecall`-from-S handling for console,
  timer, IPI, HSM, system-reset (enough for OpenSBI → Linux).
- **WFI** beyond a nop; **counters** as real M-mode counters (`mcycle`/`minstret`
  writable, `mcounteren`/`scounteren` gating).

**Verification problem (the hard part):** the qemu-*user* signal-frame trick that
makes the current methodology "provable" does not exist for system mode. A
qemu-*system* differential oracle is a separate infrastructure project — options:
(a) gdbstub register/memory compare against `qemu-system-riscv64 -s -S` stepping a
known ROM; (b) a custom bare-metal test program whose final state is compared; or
(c) golden traces. None reuse the existing harness. Until one exists, privileged
work can only be unit-tested, not oracle-verified.

See [[rax-kernel-boot]] for the analogous x86 boot blocker, and the existing
end-to-end wiring in `tests/suites/machine/riscv_virt/boot.rs` (UART @ 0x10000000,
`ecall` → shutdown).

---

## Tier 2 — ISA fidelity gaps (user-mode, illegal/edge encodings only)

These don't affect any real (compiler-emitted) program; they're correctness only
on malformed encodings or fault paths.

- **Vector register-group illegal-instruction traps** — `rax` executes some
  encodings qemu rejects (widening/narrowing/gather/extension dest-vs-source
  overlap, EMUL>1 group misalignment). **Investigated and intentionally not
  shipped:** a `PROBE=1` sweep showed qemu enforces group *alignment* and even
  *source-source different-EEW* overlap rules that go beyond the written spec, so a
  spec-faithful checker both over- and under-traps. Matching qemu here is
  implementation reverse-engineering; a half-correct checker was reverted. To do it
  properly: build the checker against the qemu probe data, not the spec text.
- **`vleff` fault-trim path** — the non-fault path is verified (identical to `vle`);
  the "trim `vl` on a fault past element 0, suppress the trap" path is best-effort
  and **not** differentially tested (the scratch window never faults). Needs a fault
  injection point in the harness.
- **`vstart` resumption** — mid-instruction restart (`vstart > 0`) is handled for
  the simple loop forms but not exhaustively swept; non-zero `vstart` corner cases
  (esp. for slides/gather/segment) are unverified.

---

## Tier 3 — Additional optional extensions

Recently closed optional slices:

- **Zacas** — atomic compare-and-swap (`amocas.w/d/q`), including RV64
  register-pair `.q`.
- **Zawrs** — wait-on-reservation (`wrs.nto`/`wrs.sto`) as single-hart no-ops.
- **Zicboz / Zicbom / Zicbop** — cache-block zero/management/prefetch.
- **Zihintpause** (`pause`) and **Zihintntl** (`ntl.*` compressed/uncompressed).
- **Zbkb RV32 bit shuffles** — `zip`/`unzip` decode/disasm/execute as RV32-only
  Zbkb overlays.
- **Zcmp / Zcmt / Zclsd / Zilsd** — compressed push/pop/double-move/table-jump
  and RV32 register-pair load/store forms. Zcmp/Zcmt/Zclsd are disabled by
  default because they overlap baseline compressed encodings; enable their
  `Isa` flags explicitly for those profiles.
- **Privileged/H decode parity slice** — `uret`, legacy `sfence.vm`,
  `sfence.vma`, Svinval (`sinval.vma`, `sfence.w.inval`, `sfence.inval.ir`),
  H fences/invalidation, and H virtual load/store encodings decode/disassemble.
  In the current flat-memory model, fences/invalidation are no-ops and H
  virtual loads/stores use ordinary flat memory.
- **IDA compatibility `sltw`** — Hex-Rays/IDA decodes the non-standard RV64
  OP-32 `funct7=0, funct3=2` table entry as `sltw`. rax supports it behind the
  opt-in `xida_sltw` flag; it remains disabled in `rv64gc()` because standard
  hardware reserves the encoding.
- **Q decode/disassembly parity** — `flq`/`fsq` and Q-format FP arithmetic,
  conversions, compare, classify, and FMA encodings decode/disassemble behind
  `Isa::q`. Execution intentionally traps until binary128 storage/arithmetic
  exists.
- **XHazard3** — Hazard3/RP2350 `h3.block`/`h3.unblock` power hints and
  `h3.bextm`/`h3.bextmi` bit-extract-multiple custom instructions.
- **XAndesPerf** — Andes GP-relative load/store/add, bit-field, branch,
  load-effective-address, and byte-scan custom instructions.
- **XThead scalar/vendor** — T-Head cache/sync/int hints, address-generation,
  bit-manip, single-bit, conditional-move, MAC, high-word FP move, integer
  indexed/pair memory, and FP indexed memory custom instructions. The custom-0
  priority now matches IDA's Soteria -> Andes -> T-Head -> Hazard3 order.
- **XTheadVdot** — T-Head vector four-byte multiply/add custom instructions.
  `th.vmaqa*` decode/disasm/execute with SEW=32 and byte-granular masks;
  IDA-only undocumented packed forms (`th.vpmaqa*`, `th.vpnclip*`,
  `th.vpwadd*`) decode/disassemble for parity and intentionally trap on
  execution because the upstream XUANTIE-RV spec does not define semantics.

Remaining optional groups:

- **Zimop/Zcmop** — may-be-ops.
  The comparison decoder does not currently decode these; they remain a general
  optional-ISA gap rather than a cross-decoder parity gap. The remaining
  mnemonic-only deltas are simplification aliases such as `rdcycle`, `csrw`,
  `beqz`, and RVV aliases; rax keeps canonical instruction disassembly for those
  encodings.
- **Q execution** — quad-precision floating point execution. rax now has
  decode/disassembly parity for the comparison decoder's Q-format coverage, but
  the FP register file is still 64-bit and `float.rs` only implements
  F16/F32/F64. Real Q support needs 128-bit FP register storage plus binary128
  soft-float.
- **Vector crypto** (Zvbb, Zvbc, Zvkg, Zvkned, Zvknha/Zvknhb, Zvksed, Zvksh) —
  large family, mirrors the scalar crypto already in `crypto.rs`.
- **BF16** (Zfbfmin scalar, Zvfbfmin/Zvfbfwma vector) — bfloat16 convert + dot.
- **Hypervisor (H)** semantics — VS/VU modes and two-stage translation (only if
  nested virtualization is ever a goal; large). Basic H opcodes are decoded as
  described above.
- **Sstc** (`stimecmp`), **Svnapot/Svpbmt**, **Sscofpmf** — S-mode add-ons that
  pair with Tier 1. Svinval opcodes decode now, but real address-translation
  invalidation still depends on the Tier 1 MMU/TLB.

---

## Tier 4 — Infrastructure / testing

- **RV32 oracle** — RV32 dual-width is unit-tested only; there is no
  `riscv32-linux-gnu` multilib in the environment, so `oracle32` can't build. The
  decode/exec already thread `Xlen::Rv32`; a 32-bit oracle would close it.
- **qemu-system differential harness** — prerequisite for Tier 1 verification
  (see above).
- **Control-flow oracle coverage** — branch/jal/jalr/lui/auipc are unit-tested
  (excluded from the PC-relative oracle); a PC-aware oracle variant could fold them
  into the differential sweep.
- **Performance** — the interpreter is correctness-first; no block/JIT path for
  RISC-V (cf. the SMIR JIT used for x86). Not needed for the foundational goal.

---

## Suggested order

1. **qemu-system oracle harness** (unblocks everything in Tier 1).
2. **S-mode CSRs + Sv39 walk + sret** → **CLINT/PLIC** → **SBI** → boot OpenSBI/Linux.
3. Tier-3 extensions opportunistically (each is a self-contained, verifiable unit).
4. Tier-2 fidelity gaps last (lowest real-world impact).
