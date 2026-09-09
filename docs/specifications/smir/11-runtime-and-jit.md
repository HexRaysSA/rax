# 11. Runtime and JIT

## 1. Cargo feature

`smir-jit` is enabled by default in `Cargo.toml`. Runtime dispatch may still disable promotion by environment or safety gate.

## 2. Runtime module

`lower/runtime.rs` provides the executable-code bridge. It is gated by `smir-jit` and includes host-specific support for x86-64 and AArch64.

## 3. x86 GuestRegs

`GuestRegs` layout:

```text
gpr[32]
rflags
exit_pc
ctx
load_fn
store_fn
fs_base
gs_base
call_fn
```

GPR indices are x86 register encodings. APX R16-R31 are present in the state even when the host has no corresponding physical GPR path.

## 4. AArch64GuestRegs

`Aarch64GuestRegs` layout:

```text
x[31]
sp
pc
nzcv
fpcr
fpsr
v[64]
ctx
load_fn
store_fn
exclusive_addr
exclusive_size
exclusive_valid
vec_load_fn
vec_store_fn
exit_flags
```

The vector array stores V0-V31 as two `u64` words each. `exit_flags` is appended
after every helper field so the pre-existing trampoline/helper offsets remain
stable. Bit 0 distinguishes a recorded native exit from an ordinary return;
bits 1 and 2 encode an AArch32 CPSR.T value and its validity, respectively.

### 4.1. AArch32GuestRegs

`Aarch32GuestRegs` is the AArch32 scalar identity-bridge state:

```text
r[16]
cpsr
```

On an AArch64 host, the bridge zero-extends AArch32 R0-R15 into W0-W15 of a temporary `Aarch64GuestRegs` state, imports CPSR.NZCV into PSTATE.NZCV, executes the lowered block through the existing AArch64 identity trampoline, and narrows W0-W15 back to 32 bits. CPSR bits N, Z, C, and V are replaced on return. Every other CPSR field is preserved from the entry snapshot except when a validated interworking exit explicitly exports a new CPSR.T value.

Native admission is fail-closed. The current AArch32-to-AArch64 scalar gate accepts W32 regions over R0-R14 from either A32 or T16/T32 without hidden instruction predication, with exact integer operations covered by the lowerer: moves, add/subtract with carry or borrow, integer comparisons and flag-setting arithmetic, logical operations with no flag update or the exact T16 N/Z update, immediate shifts with no flag update or the exact T16 N/Z/C update, T16/T32 register-controlled shifts and rotates with their exact low-byte count and optional N/Z/C update, unflagged rotates, multiply with no flag update or the exact T16 N/Z update, multiply-add/subtract, signed/unsigned division, count-leading-zero, bit reverse, byte reverse, signed/unsigned byte and halfword extension, and bitfield operations. It also admits closed direct control-flow graphs, including backward edges. Condition-code terminators must be preceded immediately by a `TestCondition` whose virtual destination is consumed by that terminator; the lowerer folds the pair into AArch64 `B.cond` without materializing a host register. Thumb `CBZ`/`CBNZ` instead retain their R0-R7 operand as the terminator condition and lower to register `CBZ`/`CBNZ`, leaving NZCV unchanged. A32 and Thumb condition codes EQ, NE, CS/HS, CC/LO, MI, PL, VS, VC, HI, LS, GE, LT, GT, and LE map directly to the corresponding NZCV predicate. Every successor must name a present block; phi nodes, locals, parity predicates, indirect memory control flow, speculative indirect target lists, and value-returning terminators fail closed. A direct A32/Thumb `BL` call is admitted only when the block's final W32 operation writes the exact continuation address (with Thumb bit 0 set where applicable) to R14, the direct target and continuation are valid 32-bit aligned guest addresses, and no SMIR arguments are present. With `Aarch64Lowerer::set_guest_call_exits(true)`, the R14 write executes before a native-exit stub records the callee PC and returns to the dispatcher. A32/T16 `BX Rm` over R0-R14 lifts to a register-indirect terminator; after the same gate admits it, `Aarch64Lowerer::set_guest_indirect_exits(true)` records the zero-extended W32 value `(Rm & 0xfffffffe)` as the dispatcher PC and exports Rm bit 0 as CPSR.T. A32-immediate and T32-immediate `BLX` carry the destination execution state separately from the architectural PC: A32 enters Thumb at a halfword-aligned target and T32 enters ARM at a word-aligned target. A32/T16 `BLX Rm` over R0-R14 derives CPSR.T from target bit 0 and records `(Rm & 0xfffffffe)` as PC after writing the source-state return address to R14. `BLX LR` first snapshots old R14 into the sole admitted materialized W32 virtual call target, preserving the architectural read-before-link-write order through optimization. These forms require `Aarch64Lowerer::set_guest_interworking_call_exits(true)`. Every interworking exit uses non-flag-setting AArch64 operations and returns to the dispatcher without emitting native `BR`/`BLR` through guest data. Generic direct-function, ordinary indirect-call, runtime, argument-bearing, and PC-register forms remain disabled. Frontier blocks remain present but are excluded from admission and lowered as native-exit stubs. `run_aarch32_identity_until_exit` returns the recorded PC for compatibility; `run_aarch32_identity_exit` additionally distinguishes a valid exit to address zero from an ordinary return. `run_aarch32_identity` discards the exit result. R15 is excluded from data operations because AArch32 reads of the program counter have pipeline and alignment semantics rather than ordinary W15 identity semantics.

The complete A32 data-processing register-shifted-register opcode space—`AND`, `EOR`, `SUB`, `RSB`, `ADD`, `ADC`, `SBC`, `RSC`, `TST`, `TEQ`, `CMP`, `CMN`, `ORR`, `MOV`, `BIC`, and `MVN`—lifts through `ArmDpRegShift`. The shifter consumes `Rs[7:0]`: zero preserves shifter C, LSL/LSR distinguish counts equal to and greater than 32, ASR sign-fills at and above 32, and nonzero ROR is modulo 32 with C equal to result bit 31. Logical S forms update N/Z/C and preserve V; arithmetic S forms update N/Z/C/V; flagless forms preserve NZCV, except that ADC/SBC/RSC still consume incoming C as data. Test/compare forms have no destination. MOV/MVN have no first operand. The decoder retains `Rs` explicitly rather than conflating bits 11:7 with an immediate count. The lifter validates the fixed Rn/Rd fields and excludes R15 in every relevant operand. The interpreter, optimizer metadata, fail-closed runtime gate, and AArch64 lowerer preserve every Rd/Rn/Rm/Rs equality partition by snapshotting the shifter operands before the destination write. Dead-flag elimination may remove the output update; carry remains a live input only for ADC/SBC/RSC or for a logical form whose C output remains requested.

The memory-aware form of the gate additionally admits A32 `LDR`, `LDRB`, `LDRH`, `LDRSB`, `LDRSH`, `STR`, `STRB`, and `STRH` over R0-R14. Immediate offset, pre-index, and post-index forms are supported; positive register offset/pre-index forms are admitted when the address is representable as base plus an unshifted index or `LSL #0..3`, and post-index register writeback admits the validated W32 add/subtract shifter forms. A32 immediate literal forms of all five load widths/sign variants freeze `(instruction_address + 8) ± immediate` modulo 2^32 into a bounded SMIR absolute address. Literal destinations may be R0-R14 and have no writeback; predicated, load-to-PC, store-from-PC-base, writeback-PC-base, and register-offset-PC-base shapes fail closed. Other unsupported register-address forms and load/writeback destination-base aliases also fail closed. Pre- and post-index writeback operations are emitted after the helper access, so a helper fault leaves both the destination and base uncommitted. The AArch64 memory-helper lowerer has an explicit W32 address mode for this bridge: effective-address additions wrap modulo 2^32 before the AAPCS64 helper receives the zero-extended address, bounded literal addresses are materialized directly into W1, and successful load results are canonicalized through W0 before state storage so a sign-extended byte or halfword can be reused as a 32-bit address. `Aarch32MemHelpers` supplies the opaque context and load/store callback addresses; `run_aarch32_identity_with_mem` returns the recorded fault or frontier PC.

A32 and T32 `LDRD`/`STRD` decode through the SMIR `LoadPair`/`StorePair` operations for validated adjacent even register pairs. In helper mode, `LoadPair` performs both scalar reads while the original guest state remains frozen and publishes both destinations only after the second read succeeds. A first- or second-word load fault therefore leaves both registers unchanged. `StorePair` performs ordered scalar writes, so a successful first store remains committed if the second faults. Pair writeback occurs only after the complete pair succeeds, and the second effective address wraps modulo 2^32 independently. PC-bearing pairs and writeback aliases between the base and either pair register remain fail-closed.

A32 `LDM`, `LDMIA`, `LDMIB`, `LDMDA`, `LDMDB`, `STM`, `STMIA`, `STMIB`, `STMDA`, `STMDB`, `PUSH`, and `POP` are expanded into ordered B4 helper operations when the register list is nonempty and contains only R0-R14. The lowest-numbered listed register is transferred at the lowest effective address for all four IA/IB/DA/DB modes. Each successful transfer commits before the next helper call; if a later transfer faults, earlier loads or stores remain committed and the final base writeback is not executed. Address generation and writeback wrap modulo 2^32. R15-bearing lists or bases, A32 S-bit user-bank/exception-return forms, load/base aliases, and store/writeback base aliases remain fail-closed.

The Thumb lifter retains the decoded 2-byte or 4-byte width, normalizes architectural R13 to the identity-mapped X13/W13 register rather than AArch64 SP, and uses the Thumb `PC + 4` branch base. Direct BL writes `(PC + 4) | 1` to R14. T16 `CBZ`/`CBNZ` and T16/T32 condition-code branches become explicit two-edge SMIR terminators with an exact 2-byte or 4-byte fallthrough PC; T16 `BX` and `BLX` become the interworking dispatcher exits described above. T32-immediate `BLX` aligns the `PC + 4` base to 4 bytes before adding its signed offset. A32 and Thumb instruction addresses, fallthrough addresses, branch targets, call targets, link values, and literal addresses are restricted to the 32-bit guest address domain and wrap modulo 2^32 at its boundary. The native subset admits T16 arithmetic forms whose architectural contract updates all NZCV bits, unflagged high-register moves/adds and REV, T16 `MOVS`, `ANDS`, `EORS`, `ORRS`, `BICS`, `MVNS`, `TST`, and `MULS` with an exact N/Z-only `FlagUpdate::Specific` contract, and T16 immediate `LSLS #1..31`, `LSRS #1..32`, and `ASRS #1..32` with an exact N/Z/C contract. T16/T32 register `LSL`, `LSR`, `ASR`, and `ROR` forms lower through `ArmRegShift`: the effective count is the low byte of the count register; zero preserves incoming C when flags are requested while still recomputing N/Z; LSL/LSR distinguish counts 32 and greater than 32; ASR sign-fills for every count at or above 32; and nonzero ROR counts use modulo 32 while setting C from result bit 31. T32 independently encodes destination, value, and count registers and admits every R0-R14 equality partition. Its S bit selects either an exact N/Z/C update with V preserved or no architectural flag access. Constant propagation may replace a known count register with an immediate without changing this low-byte contract, and dead-flag elimination may erase the N/Z/C update while retaining the result semantics and removing the incoming-C dataflow dependency. The AArch64 lowerer snapshots both inputs before any destination write, produces the requested flags, and merges only their native bit positions; C/V or V therefore remain bit-for-bit unchanged as required. The SMIR interpreter performs the same selective merge after committing any preceding lazy producer. Generic shifts retain their existing six-bit SMIR count and remain separate, so LSR/ASR by 32 saturates rather than being incorrectly reduced modulo 32. Native regressions exhaust all 16 prior NZCV states across zero, sign, carry, every destination/value/count alias partition, low-byte wrap, and boundary-shift inputs while checking non-destination registers, scratch registers, and stack restoration. The subset also admits unflagged T32 arithmetic/logical/shift, multiply/divide, bit-manipulation, MOVW/MOVT, extend, and bitfield forms. It admits T16/T32 scalar single-transfer `LDR`/`STR` byte, halfword, word, and signed-load variants, including T16 register/immediate/SP-relative addresses and T32 positive immediate, scaled-register, and immediate pre/post-index forms. T16 `LDR` literal and T32 `LDR`/`LDRB`/`LDRH`/`LDRSB`/`LDRSH` literal forms freeze `Align(instruction_address + 4, 4) ± immediate` into bounded absolute-address IR; the T32 decoder retains the full positive or negative imm12 independently of `imm12[11]`. Literal destinations R0-R14 and precise helper faults are admitted, while load-to-PC and PC-relative stores remain fail-closed. T16/T32 `LDM`/`STM` and `PUSH`/`POP` without R15 use the same ordered expansion, partial-commit-on-fault, deferred-writeback, and modulo-2^32 contracts as A32; T32 `LDRD`/`STRD` uses the pair contract described above. T16 list transfers always write back; T32 forms follow their encoded W bit. Predicated data operations, nonzero IT state, rotated extend operands, RRX, other R15 data operands, R15-bearing list transfers, VFP/NEON, system state, other indirect control flow, and materialized virtual-register results other than flag-only destinations and the exact BLX-LR snapshot retain interpreter fallback until their complete architectural contracts are represented and lowered. The bridge preserves both split IT fields and all CPSR fields outside NZCV unless an admitted interworking exit explicitly updates CPSR.T.

## 5. x86-64 trampoline

`rax_smir_enter_native`:

1. preserves host callee-saved registers;
2. stores entry/state pointers on the host stack;
3. loads guest RFLAGS and GPRs into host registers;
4. calls the lowered block;
5. stores host registers and flags back to `GuestRegs`;
6. sanitizes host EFLAGS bits before returning to Rust;
7. restores host state.

Guest RSP is not loaded into host RSP. The block runs on the host stack.

## 6. AArch64 trampolines

`rax_a64_enter_native` marshals GPRs and NZCV for identity-mapped AArch64 native blocks. `rax_a64_enter_native_fp` additionally marshals V0-V31 plus FPCR/FPSR for scalar FP/SIMD regions and restores host FPCR/FPSR afterward.

The x86 VCPU also uses the scalar AArch64 trampoline for eligible x86-lifted SMIR. Legacy x86 GPR encodings RAX-R15 map to X0-X15. The bridge maps x86 CF/ZF/SF/OF to PSTATE.C/Z/N/V and merges only those four flags back into RFLAGS; PF, AF, control flags, and reserved bits remain from the pre-region snapshot. Eligibility rejects live PF/AF definitions or consumers, unsupported registers/virtual temporaries, memory, and flag contracts whose AArch64 carry convention is not normalized. The x86-register SBB lowering normalizes canonical x86 borrow-CF to AArch64 no-borrow-C around SBC; live CF outputs from SUB/CMP/NEG and generic CF-based unsigned conditions remain excluded. Flag-setting SBB remains eligible only when its unavailable PF/AF definitions are dead. The strict x86 lifter continues to reject the architecturally invalid APX NF ADC/SBB encodings; no-flag SBB coverage exercises the SMIR lowering contract directly.

The architecture-specific scalar whitelist admits exact register-only BMI1 BLS, ADX, BT/BTS/BTR/BTC, CLC/STC/CMC, MOV, NOT, low-byte SETcc, 16-bit register CMOVcc, 16-bit XCHG, 16-bit MOVSX/MOVZX and CBW, and APX NDD SHLD/SHRD lowering in addition to the shared scalar set. ADD, SUB, ADC, SBB, NEG, INC, DEC, AND, OR, XOR, SHL, SHR, SAR, ROL, ROR, RCL, and RCR admit legacy x86 GPR destinations at 8/16/32/64 bits; BT, its update forms, destructive SHLD/SHRD, APX NDD SHLD/SHRD, single-result signed multiply, BSF/BSR, primitive CLZ/CTZ/POPCNT, and architectural x86 POPCNT/TZCNT/LZCNT operations admit 16/32/64 bits. Exact no-flag implicit W16 MUL/IMUL pairs are also admitted, and W32 MULX/full-product forms use widening multiply rather than an unavailable W32 high-half instruction. Every admitted 8/16-bit destination path explicitly merges its result into the original x86 register after computing the narrow result and flags. W16 extension results are formed in a saved scratch register before the low word is merged, preserving the original source in destructive CBW and source/destination aliases; optimizer-folded immediate sources use the same merge path. BSF/BSR merge only their `Specific(ZF)` output into NZCV, preserving live CF/SF/OF across both full-width and W16 paths. `X86Count` preserves all NZCV bits under APX NF, implements POPCNT's represented all-zero/ZF contract, and merges only requested CF/ZF for TZCNT/LZCNT; live POPCNT PF/AF outputs still force interpreter fallback because NZCV cannot represent them. W16 multiply computes the complete product before merging either architectural half, preserving both destination upper parts and all source aliases; single-result signed multiply likewise computes into a saved scratch destination, including destructive and APX NDD source aliases. MULX with identical output registers retains the architecturally final high half at both W32 and W64. The strict APX lifter consumes opcode-69's width-dependent imm16 payload without absorbing the following instruction. Destructive W16 double shifts snapshot the original destination before computing and merging the low word. APX NDD double shifts compute through a saved scratch destination so independent-destination aliases with the base, fill, or CL count retain the original inputs; flag-setting W16 register-count forms and immediate effective counts above 16 remain excluded. Other destination-producing operations remain limited to 32/64-bit forms unless their lowerer has a separately validated x86 partial-register merge: AArch64 W-register writes zero-extend, while x86 8/16-bit writes preserve the destination's upper bits. Unsupported subregister shapes fail before native execution.

Register-only x86 CRC32C is admitted for byte, halfword, word, and doubleword data when the AArch64 host exposes FEAT_CRC32. Native CRC32C{B,H,W,X} writes Wd, exactly zero-extending the architectural x86 result while preserving NZCV; unsupported hosts retain interpreter fallback.

Guest SP/X18/X28/X30 restrictions are part of the identity-map contract and must be enforced by clobber gates or lowerer rejection.

## 7. Executable memory

`ExecMem` creates a page-aligned executable mapping. Host-specific behavior:

- non-AArch64 Unix: RW `mmap`, copy, `mprotect` RX;
- Linux/AArch64: RW `mmap`, copy, `mprotect` RX, `__clear_cache`;
- macOS/AArch64: `MAP_JIT`, `pthread_jit_write_protect_np`, copy, write-protect, `sys_icache_invalidate`.

This is the W^X / MAP_JIT boundary.

## 8. Run methods

`ExecMem` supports:

```text
run                  x86 identity mapped block through GuestRegs
run_aarch64          state-backed AArch64-on-x86 ABI fn(*mut Aarch64GuestRegs)
run_aarch64_identity AArch64 identity mapped block through AArch64 trampoline
run_aarch64_identity_fp AArch64 identity mapped FP/SIMD block through FP trampoline
run_aarch32_identity AArch32 scalar state through the AArch64 identity trampoline
run_aarch32_identity_until_exit AArch32 scalar state plus exact frontier-exit PC
run_aarch32_identity_exit AArch32 scalar state plus unambiguous exit-valid and PC result
run_aarch32_identity_with_mem AArch32 scalar state plus MMU helper callbacks
```

## 9. Hot-block policy

The x86 VCPU hot-block JIT is on by default on supported x86-64 and AArch64 hosts: hot loops are promoted, lifted to SMIR, optimized at O2, lowered through the selected host backend, cached, and run through W^X executable memory. The x86-64 backend's verification mode re-runs native regions in the interpreter and diffs state. AArch64 production regressions directly compare the bridged native result with the interpreter.

## 10. Native exits

A native exit records a resume PC plus an explicit valid bit in runtime state and returns to the host dispatcher. The valid bit distinguishes guest PC zero from an ordinary return. Exits can replace a complete frontier block or a specific `(source block, target block)` edge. Edge exits let auto-promoted regions yield on backward edges without globally replacing the target block. Native exits are also used for helper faults, call-helper bails, interworking branches, and unsupported frontiers.

EVEX gather/scatter can return within an instruction after earlier lanes have
committed. Their append-only lane and dynamic-instruction-ordinal metadata
allow verification to reconstruct the same partial frontier, including native
loops. See [native EVEX VSIB boundaries](../../development/emulation/x86-native-vsib.md)
for the lowering, state, source-validation, and trace contracts.

## 11. Cache invalidation

Self-modifying code must invalidate decode/lift/JIT caches. Store helpers must detect writes to code pages and bail if needed.
