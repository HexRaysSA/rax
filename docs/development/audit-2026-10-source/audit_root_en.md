# RAX: Detailed Analysis of Implementation, Correctness, and Oracles

## 1. Conclusions and scope

**The RAX implementation examined here does not reproduce every behavior of a real CPU.** Its implementation is extensive, and some components use independent validation. Nevertheless, small programs linked against the original library reproduced differences in instruction results, floating-point status, address translation, exceptions, packet execution, and checkpoint configuration. Passing existing tests and conforming to an entire architecture are distinct claims.

This report examines commit **`2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b`** of `HexRaysSA/rax`. The commit timestamp is **2026-10-22 23:36:43 UTC**, and its message is `feat(user): select fixed GRE_Initialize registry subtree`. No tracked files in the original repository were modified for the analysis. The findings are not asserted to remain applicable to a subsequently changed HEAD.

The review distinguishes six layers:

1. Which byte sequences and CPU feature combinations the decoder accepts.
2. How instructions change registers, memory, flags, exceptions, and the PC.
3. How the implementation handles MMUs, permissions, interrupts, atomicity, and packet or instruction boundaries.
4. Whether the direct interpreter, SMIR interpreter, optimizer, and native lowering/JIT preserve the same semantics.
5. Which execution environments the virtual machine, devices, OS personalities, loaders, and C API provide.
6. Who generates each test's expected results, which state is actually compared, and which state is omitted.

**The completed work comprises a repository-wide structural inventory, static analysis of major implementation paths, minimal counterexamples across several ISAs, reruns of selected existing tests, and an analysis of oracle independence. It does not constitute an exhaustive proof over every instruction input or every operating-system and device state.** Unexamined areas are not counted as correct. No overall accuracy percentage is reported: neither a defensible denominator nor a sampling design for the relevant state space is available.

### Evidence grades

| Label | Meaning | Limit of the evidence |
|---|---|---|
| D-full | Reproduced by executing the relevant CPU or facility in the unmodified original RAX library | A counterexample for the exercised state and path, not a statistical measure over all inputs |
| D-module | Executed in a small harness that includes or extracts an original module without changing it | Does not establish CPU-wrapper or platform integration behavior |
| S | Explicit handling or an omission established from source | Frequency and reachability in a deployed environment require separate validation |
| P | An existing repository test or recorded result was rerun or reviewed | Meaning depends on compared state, independence, skip conditions, and recording date |
| U | Structure and scope examined, but equivalence unverified | Counted as neither a failure nor a pass |

## 2. Validation actually performed

### 2.1 Tools and environment

| Item | Value used in this analysis |
|---|---|
| Host | Linux 6.18.55, x86_64, container environment |
| RAX build | Rust 1.98.0, `--locked --no-default-features --lib` |
| RAX reproduction harnesses | Linked against the original `librax.rlib`, Rust 2024 edition |
| Separate JIT tests | Rust 1.98.0, `--no-default-features --features smir-jit` |
| Host target | `-C target-cpu=x86-64`; the repository's host baseline was explicitly lowered for this environment |
| Native x86 oracle | Separate C/inline-assembly ELF, not linked against RAX; identical SSE bytes, inputs, and MXCSR |
| QEMU execution | `qemu-x86_64-static` 8.2.2, Ubuntu package `1:8.2.2+ds-0ubuntu1.18` |
| Unicorn execution | Python package 2.1.4; A32 Cortex-A15 and x86_64 instruction execution |
| KVM/HVF | These backends were not executed because `/dev/kvm` and a macOS environment were unavailable |

With the initially selected Rust 1.99.1 toolchain, building the library succeeded, but consuming its rlib metadata with the same compiler produced `E0786`. Rust 1.98.0 successfully built the library, linked the external harnesses, and ran the tests below. This observation alone does not establish a RAX source defect or a Rust compiler defect. The failure logs are included in the evidence bundle.

The native oracle records x86 behavior on the current host. It does not represent tests across all Intel and AMD processor generations. The container's `lscpu` query failed because the required sysfs information was absent; the CPU model and microcode revision remain unknown.

### 2.2 Results of existing tests

| Explicit Cargo target | Passing test functions | Failed / ignored | Nature of the execution |
|---|---:|---:|---|
| `ebpf_diff` | 12 | 0 / 0 | RFC reference, checked-in kernel/Anza corpora, encoding and execution comparisons |
| `ebpf_smir_lift` | 46 | 0 / 0 | eBPF direct/SMIR comparison and memory, call, and trap boundaries |
| `isa_oracle` | 80 | 0 / 0 | Contracts of the JSON decoder/lifter/seeded-evaluator API |
| `smir_jit_evex_masking` | 30 | 0 / 0 | EVEX masking and native-execution boundaries |
| `smir_jit_vcpu` | 231 | 0 / 0 | Native tier, exception boundaries, state preservation, SMC, and multiple x86 instruction families |
| **Total** | **399** | **0 / 0** | This is not a count from the complete Cargo test suite |

The `ebpf_diff` log reports, for little and big endian respectively, **1,980,208 encodings** each, **477/401 explained disagreements**, and **1,410 kernel programs / 147,698 cases / 4 planes** each. It also reports **312 positive + 45 negative conformance cases / 4 planes** and replay of **20 Anza corpus digests**. An `explained disagreement` cannot immediately be counted as incorrect bytecode execution, but it also does not mean complete equivalence to the kernel. Admission policy, version, and the scope of the verdict must be examined.

The kernel/Anza data above are **replays of records pinned in the repository**. This analysis did not launch the Linux BPF verifier, the complete Anza runtime, or the Kani solver to recollect a corpus of that size. For tests with optional external dependencies, fallback and early-return behavior were distinguished from actual external execution. Cargo's `0 ignored` count alone does not prove that an external oracle ran.

## 3. Implementation map

The repository contains **30,330 tracked files**. The following counts were obtained directly from Rust files and newline characters under each path. They include comments, generated code, and in-file tests; they are not measures of semantic implementation size or coverage. The appendices and evidence manifests include per-file inventories and Git object IDs.

| Implementation area | Rust files | Newlines | Principal responsibilities |
|---|---:|---:|---|
| `src/isa/x86_64` | 323 | 127,978 | x86 decoding and execution, FP/SIMD, system state, MMU, JIT integration |
| `src/isa/arm` | 116 | 82,924 | A64/A32, ARM/Thumb, VFP/NEON, M/R profiles, MMU/MPU |
| `src/isa/riscv` | 26 | 21,494 | RV64 scalar/vector operations, CSRs, privilege, memory |
| `src/isa/hexagon` | 43 | 38,721 | Packet decoding, slots/`.new`, scalar/HVX, memory, branches |
| `src/isa/ebpf` | 12 | 4,553 | RFC eBPF/SBPF versioned decoding, execution, platform behavior |
| `src/smir/ir` | 276 | 85,845 | Intermediate representation, types, state, side-effect and trap contracts |
| `src/smir/lift` | 291 | 170,600 | Guest instructions to SMIR |
| `src/smir/interpret` | 106 | 82,665 | SMIR evaluation and shared arithmetic/FP helpers |
| `src/smir/optimize` | 31 | 16,770 | Liveness, flags, folding/propagation, DCE, CFG transformations |
| `src/smir/lower` | 1,102 | 567,562 | Host lowering, register/ABI integration, native admission/runtime |
| `src/user` | 949 | 334,681 | Images/memory and Linux, Darwin, and Windows personalities |
| `src/devices` | 30 | 28,185 | Interrupt, timer, UART, storage, network, and SoC devices |
| `src/machine` | 18 | 14,979 | Board memory/device layouts and firmware/kernel boot environments |
| `src/backend` | 27 | 8,446 | Software emulator, KVM, HVF |
| `src/vm` | 8 | 4,028 | VMM execution loop, RAM, timing, checkpoints |
| `src/oracle` | 11 | 6,664 | Static analysis, decoding/lifting, seeded-SMIR JSON API |
| `capi/src` | 43 | 17,158 | C engine, memory, register, hook, and process APIs |

Additional components include `config`, `host`, `debug`, `observability`, the CLI, and tools. The root package sets `autotests=false` and declares 50 explicit test targets. Its default features are `kvm` and `smir-jit`. A file's presence under `tests/`, or a decoder's recognition of an instruction, does not establish that the program was executed and compared. [Cargo configuration](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/Cargo.toml)

### Why support must be assessed at every layer

`Decoded → lifted to SMIR → lowered to host code → admitted by the runtime → executed natively → full state matched` comprises distinct stages. A count at one stage does not establish support at the next. An instruction rejected by the native gate may fall back correctly to an interpreter; two interpreters can also agree because they share the same incorrect helper.

## 4. Summary of established differences

| ID | Area | Observed difference | Evidence |
|---|---|---|---|
| X-FP | x86 scalar SSE | Some paths do not apply guest rounding/DAZ to results; MXCSR sticky flags omitted | D-full + native + QEMU + Unicorn |
| X-NX | x86 paging | A NOP on an NX page executes through system-mode CPU.step | D-full |
| X-WP | x86 paging | Rejects an R/W=0 write that should be allowed at CPL0 with CR0.WP=0 | D-full MMU |
| X-TLB | x86 paging | TLB-hit path does not revalidate current access/CPL conditions | D-full MMU |
| X-AD | x86 paging | Page-table accessed/dirty bits are not updated after accesses/writes | D-full MMU |
| X-FALLBACK | x86 paging | Linux direct-map fallback converts a non-present #PF into a successful RAM mapping; source inspection also shows protection/reserved faults entering the same branch | D-full MMU + S |
| X-RSVD | x86 paging | Accepts a reserved PML4 PS bit | D-full MMU |
| X-SMAP | x86 privilege | A supervisor read accesses a user page with SMAP=1 and AC=0 | D-full CPU |
| X-PKRU | x86 privilege | Reads a user-key page after WRPKRU disables access for key 1 | D-full CPU |
| X-PRIV | x86 privileged instructions | CPL3 INVD/WBINVD advance instead of raising #GP(0) | D-full + native trap |
| A-PAGE | A64 memory | A cross-page LDR does not translate the second VA, changing both data and fault behavior | D-full |
| A-ALIGN | A64 memory | Allows an ordinary unaligned LDR with SCTLR.A=1 | D-full |
| A-SP | A64 memory | Raises an SP-alignment fault with SCTLR.SA/SA0=0 | D-full |
| A-APTABLE | A64 MMU | OR-based handling reverses APTable[0]'s EL0 access restriction | D-full CPU memory API |
| A-DESC | A64 MMU | Treats reserved L3 descriptor `01` as a page | D-full CPU memory API |
| A-EL1X | A64 MMU | Allows an EL1 instruction fetch from an EL0-writable page | D-full |
| A-PA | A64 MMU | Accepts an output address exceeding configured PA width; CPU configuration also has limited TCR.IPS handling | D-module + S |
| A32-FP | A32 VFP | Incorrect FPSCR behavior for infinity/NaN/division by zero, and incorrect rounding/FZ handling | D-full + Unicorn + ASL |
| R-AMO | RISC-V | Failed AMOADD.W read produces load access fault (5), rather than store/AMO access fault (7) | D-full + specification |
| H-PRED | Hexagon | Multiple compare writes to one predicate in a packet retain the last value instead of applying auto-AND | D-full + specification |
| H-ALIGN | Hexagon | Executes an unaligned scalar word load as a normal load | D-full + specification |
| H-COMMIT | Hexagon | An earlier store remains in memory when a later store in the packet faults | D-full + specification |
| H-PC | Hexagon | A later PC-relative jump in a packet uses the instruction PC instead of the packet PC | D-full; encoding validation is detailed in the appendix |
| C-PCI | Checkpoint | `pci_devices=true` becomes false after a configuration round trip | D-full configuration API |
| C-STATE | Checkpoint | Serialized/restored device set is limited to PIC/PIT/16550/LAPIC | S |
| C-SMP | System runtime | Creates multiple vCPUs, but the main execution loop runs only vCPU 0 | S |
| C-HVF | Intel Mac HVF | MMIO write data is a four-byte zero placeholder; read width is fixed; some CR/XSETBV exits only advance RIP | S; platform not executed |

These rows are not separate severity scores or vulnerability identifiers. One underlying cause can produce several observations, and some findings describe scope limitations. Their count is not converted into a measure of overall performance, security, or product quality.

## 5. Reproductions that explain the main failure classes

### 5.1 x86: comparing only the result misses MXCSR

All result values below are 32-bit IEEE binary32 bit patterns. Native execution and QEMU ran the same separate C/assembly program. RAX used the original CPU's scalar SSE decode/execute path. Unicorn received the same machine code and initial registers.

| Input and conditions | Native x86 host | QEMU 8.2.2 | Unicorn 2.1.4 | RAX direct |
|---|---|---|---|---|
| ADDSS `1 + 2^-24`, round toward +infinity, initial MXCSR=`5f80` | `3f800001 / 5fa0` | `3f800001 / 5fa0` | `3f800001 / 5f80` | `3f800000 / 5f80` |
| DIVSS `1 / +0`, masked, initial=`1f80` | `7f800000 / 1f84` | `7f800000 / 1f84` | `7f800000 / 1f80` | `7f800000 / 1f80` |
| ADDSS smallest subnormal + 0, DAZ=1, initial=`1fc0` | `00000000 / 1fc0` | `00000000 / 1fc0` | `00000000 / 1fc0` | `00000001 / 1fc0` |

Each cell is **result / MXCSR**. The binary32 ULP at `1.0` is `2^-23`. The addend `2^-24` is exactly half an ULP: nearest-even remains at `1.0`, whereas rounding toward +infinity must select the next representable value, `0x3f800001`. The inexact result sets PE, bit 5: `0x5f80 | 0x20 = 0x5fa0`. Division `1 / 0` sets ZE, bit 2: `0x1f80 | 0x04 = 0x1f84`.

The examined RAX scalar paths use host Rust `f32/f64` arithmetic instead of applying guest MXCSR. They omit updates to guest MXCSR sticky flags; changes to host MXCSR were also observed in this experiment. This finding is not generalized to every x86 FP instruction or every SMIR/native path. x87, packed SIMD, EVEX SAE/rounding, and FMA have separate helpers and execution paths. [Scalar SSE dispatch](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/isa/x86_64/decode/dispatch/twobyte/sse.rs), [arithmetic helpers](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/isa/x86_64/execute/simd/arith.rs)

Here, **RAX and Unicorn agree on exception flags while both disagree with native execution.** Consequently, `RAX == Unicorn` is not a sufficient correctness criterion. QEMU's agreement in these three cases does not establish that QEMU is correct for all instructions.

### 5.2 A64: an eight-byte LDR across noncontiguous physical pages

With 4 KiB pages, an eight-byte load at VA `0x0ffc` spans the final four bytes of one page and the first four bytes of the next. The VA-to-PA mappings can be noncontiguous, so each page requires its own translation.

The reproduction's expected value was **`0x8877665544332211`**; RAX returned **`0xddccbbaa44332211`**. The first four bytes were correct, but the remaining bytes came from the physical range immediately following the first PA rather than from the next mapped page. Making the second page unmapped still produced the same successful result. The required behavior is a translation fault at VA `0x1000`. [A64 memory helpers](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/isa/arm/aarch64/cpu/memory.rs)

The implementation translates only the starting VA and then treats the entire access as a contiguous physical range. This is a **memory-boundary state-space** issue that expanding an arithmetic instruction count or decoder opcode corpus is unlikely to expose. The effect on other accesses sharing the helper must be checked separately for each read/write kind and CPU wrapper.

### 5.3 Distinguishing A32 FP failures from passing A64 controls

| Operation / setting | Expected FPSCR or result | Observed A32 behavior | A64 control under the same conditions |
|---|---|---|---|
| Infinity + 1 | No overflow; FPSCR=`0` | Sets OFC, producing `4` | Matches |
| Quiet NaN + 1 | Ordinary qNaN propagation; IOC=`0` | IOC=`1` | Matches |
| 1 / +0 | DZC only: `2` | DZC+OFC: `6` | Matches |
| +0 / +0 | IOC only: `1` | IOC+DZC: `3` | Matches |
| Toward +infinity, 1+2^-24 | Result=`3f800001`, IXC=`0x10` | Result=`3f800000`, IXC unset | Matches |
| FZ=1, smallest subnormal+0 | Result=`0`, IDC=`0x80` | Result=`1`, IDC unset | Matches |

Unicorn's A32 Cortex-A15 model and the repository's Arm ASL definitions support these expected results. All six equivalent controls executed through the original A64 FADD/FDIV CPU path matched their expected results. **It would be inaccurate to generalize the A32 VFP helper defects to all floating-point support in RAX ARM.** [A32 VFP](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/isa/arm/aarch32/vfp.rs), [A64 FP implementation](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/isa/arm/aarch64/cpu/math/fp.rs)

### 5.4 RISC-V: a correct fault address with an incorrect trap cause

For `AMOADD.W` encoding `0x0020a1af`, PC=`0x100`, x1=`0x2000`, and valid memory `[0,0x1000)`, RAX returned `cause=5`, `tval=8192`, and `mcause=5`. Because `8192 = 0x2000`, the fault address is correct, but the fault class is incorrect. The failed AMO access must produce **store/AMO access fault=7**. The cause is `exec_amo` mapping a failure in its read phase to an ordinary load error. [RV CPU](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/isa/riscv/cpu.rs), [RISC-V machine ISA](https://docs.riscv.org/reference/isa/v20260120/priv/machine.html)

A harness comparing only whether a trap occurred collapses both 5 and 7 to true. A register-only comparison observes even less state. Besides normal results and PC, comparisons must cover cause, EPC, tval, and destination/memory preservation around the trap.

### 5.5 Hexagon: the packet is the essential validation unit

Hexagon's packet semantics require separate checks for the combination of definitions, `.new` forwarding, slot constraints, packet-relative PC, and the commit boundary on a fault.

A packet writing false and true to the same p0 through compare instructions should produce false through auto-AND; RAX retained the final true value, `0xff`. In a packet containing two stores, with the second store faulting, the first store had already changed memory from `0x11223344` to `0xaabbccdd`. An earlier memory effect remained despite the packet failing to complete. Additional counterexamples concern packet-relative branch addressing and scalar alignment. The Hexagon appendix separately examines encodings, packet legality, and the specification basis for these conclusions. [Hexagon CPU](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/isa/hexagon/cpu.rs), [Qualcomm V68 manual](https://docs.qualcomm.com/doc/80-N2040-46/80-N2040-46_REV_B_Hexagon_V68_Programmers_Reference_Manual.pdf)

## 6. SMIR, optimization, and JIT by component

### 6.1 IR and lifting

SMIR represents guest state, temporary values, memory operations, flags, and traps/terminators. Its structure is `Module → Function → Block → Operation/Terminator`. For x86, it also retains original instruction bytes by block and guest PC; those bytes inform checks for forms that can be reused on the host. [IR](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/smir/ir/mod.rs)

The analysis separates these contracts:

| Stage | Required correctness | Frequently omitted checks |
|---|---|---|
| Decode → lift | Operand widths, prefixes, implicit registers, zero/sign extension | Reserved encodings, feature gates, high-byte-register restrictions |
| Lift → IR effects | Read/write ordering, fault PC, defined/undefined flags, partial registers | Destination aliasing; whether all sources are read before writes |
| IR → interpreter | Bitvector operations, FP state, memory/atomic contracts | Host signed shifts/overflow, NaNs, rounding, endianness |
| Optimize | Preservation of traps, memory effects, and instruction boundaries as well as values | Removing a faulting operation because its result is dead |
| Lower → native | Separation of guest/host registers, ABI, state materialization | Implicit clobbers, flags live-out, host FP state |
| Runtime | Correct guest boundaries for cancellation, budgets, hooks, SMC, and exceptions | Re-execution after some guest instructions have already committed |

### 6.2 Optimizer

O0 performs no transformations. O1/O2 recompute liveness and apply dead-flag elimination, constant/copy propagation, DCE, and related passes. O2 adds folding, strength reduction, branch folding, and block merging. Optimization is capped at eight rounds. [Optimizer](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/smir/optimize/mod.rs)

The eight-round limit is a convergence policy, not an architectural correctness proof. Each pass needs checks that it preserves trapping operations, observable reads, required lazy-flag bits, aliasing constraints, and guest execution boundaries. The executed eBPF tests include positive cases for retaining division traps with dead results, observing memory loads, and handling atomics.

### 6.3 Native admission and fallback

The current implementation does not send arbitrary IR directly to native code. It checks closure of temporary def-use relationships, supported flags live-out, source bytes and operand forms, guest/host register interference, and known helper memory boundaries. State-based trampolines exist for multiple ISAs. Function-wide temporary def-use information is aggregated once to avoid repeated full scans during admission. [Admission](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/smir/lower/runtime/trampolines/clobber.rs), [operation gates](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/smir/lower/runtime/trampolines/clobber/operation.rs)

The presence of a lowerer does not imply native execution if runtime admission rejects it. Interpreter fallback is not itself a correctness defect. Support should be reported at least as `decoded / lifted / interpreted / optimized / lowered / admitted / executed / independently validated`.

### 6.4 What `RAX_JIT_VERIFY` establishes

The verification path saves registers, FPU state, lazy flags, MXCSR, and system state before native execution. It records memory writes, undoes them, and replays execution in the interpreter. Overlapping stores are undone in reverse order. Special handling exists for cases such as partial VSIB lane prefixes. This is useful for detecting regressions in native lowering. [Verification implementation](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/isa/x86_64/cpu_jit_verify.rs)

The source also contains these limits:

- Regions using timestamps or I/O execute natively without replay because identical inputs are difficult to reproduce.
- A branch adopts the native result without verification when a store log is unavailable. Certain VSIB mismatch boundaries fail separately.
- Replay has a 50,000,000-step cap.
- The interpreter is not a hardware oracle. Shared helpers allow common semantic errors to survive; x87 helper sharing is one example.

Accordingly, `verify=1` is not a guarantee of conformance to the entire CPU specification. It means **comparison of native results against a selected interpreter implementation for regions that can be verified**.

## 7. Backends, virtual machines, checkpoints, and time

### 7.1 Separate conclusions for each backend

| Backend | Actual role | Assessment in this analysis |
|---|---|---|
| Software emulator | Executes RAX decoding/execution/SMIR | D-full counterexamples across several ISAs and selected P tests |
| KVM | Linux x86_64 host virtualization interface | Host CPU execution does not prove software-interpreter correctness; not executed here |
| HVF AArch64 | Apple Silicon Hypervisor.framework path | Intel Mac findings are not transferred to this path; not executed here |
| HVF x86_64 | Intel Mac VMX exit handling | Placeholders below established from source, without execution on that hardware |

The Intel Mac HVF EPT-violation handler supplies `vec![0; 4]` as write data and uses a read size of 4. CR-access exits advance RIP, and XSETBV exits also advance without updating the corresponding state. These exit handlers cannot generally reproduce the semantics of the actual device access or control-state change. [Relevant HVF path](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/backend/hvf/mod.rs#L586-L678)

### 7.2 State included in checkpoints

`Snapshot` stores configuration, one CPU state, extended emulator state, memory, elapsed time, and `DeviceState`. `DeviceState` contains only PIC, PIT, Serial16550, and LAPIC. Capture and restore also copy only these four devices. [State structure](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/vm/snapshot.rs#L160-L199), [capture](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/vm/runtime.rs#L1318-L1356), [restore](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/vm/runtime.rs#L1427-L1456)

PCI devices, IOAPIC/RTC, and the separate A64 PL011 attached to current machines are absent from this set. The schema therefore does not provide full-machine equivalence covering every active device and vCPU. End-to-end save/restore was not exercised for every device; this finding is specifically a **static omission from the serialized state set**.

The configuration path was executed directly. `VmConfig::from_sources(pci_devices=true) → to_checkpoint() → from_checkpoint(default CLI)` changes **true → false**. `CheckpointConfig` does not retain this field, and restore uses the CLI boolean again. Supplying the option again to reconnect devices would not automatically restore their omitted internal state. [Configuration](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/config/runtime.rs#L246-L335)

### 7.3 SMP and memory ordering

VMM construction creates the requested number of vCPU objects, but the main `run()` loop uses only `.vcpus.get_mut(0)`. Snapshots also save only CPU 0. A vCPU-count option consequently does not establish concurrent SMP execution or validation of AP startup, IPIs, and weak memory ordering. [Execution loop](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/vm/runtime.rs#L1064-L1073)

The Linux user-personality scheduler explicitly runs threads round-robin on one emulated CPU. A64/RV64 use instruction budgets, while x86 uses approximately 1 ms time slices; only one guest instruction stream runs at a time. This is a practical model for many programs, but it does not model physical multicore store buffers or every permitted interleaving. [Scheduler](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/user/linux/sched.rs#L1-L15)

### 7.4 Time and microarchitecture

The main x86 guest RDTSC path uses `elapsed_nanos * 3 + tsc_adjust`: three ticks per nanosecond, or a virtual 3 GHz clock. Legacy helpers or older comments referring to instruction-count-based TSC behavior were distinguished from this active path. [RDTSC source path](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/isa/x86_64/cpu.rs)

This is not a cycle model of a processor's cache hits/misses, speculative execution, reorder buffer, branch predictor, or memory-controller latency. Equality of instruction results and equality of cycle timing require separate claims. QEMU's official documentation likewise does not describe `icount` as cycle-accurate execution. [QEMU icount](https://www.qemu.org/docs/master/devel/tcg-icount.html)

## 8. Devices, machines, and support boundaries

The presence of a device file or register read/write handlers does not establish equivalence to a complete peripheral. This review examines wiring, explicit command subsets, serialized state, and substitute behavior.

| Class | Implemented files / machines | Additional dimensions required for equivalence |
|---|---|---|
| Interrupts | PIC, IOAPIC, LAPIC | Priority, masking, EOI, delivery modes, edge/level behavior, SMP targets |
| Timers/clocks | PIT, HPET, RTC, LAPIC timer | Frequency, latches, rollover, interrupt latency, pause/resume |
| Console/input | Serial16550, PL011, i8042, VGA | FIFOs, interrupt levels, register side effects, device timing |
| Storage | IDE, FDC, AHCI, NVMe, virtio-blk | DMA, queue ordering, errors, feature negotiation, persistence |
| Network/USB/audio | e1000, UHCI, AC97 | Actual external transport, rings, descriptor faults, interrupts |
| Interconnect | PCI, I/O/MMIO buses, maps, DMA, fw_cfg | BAR sizing, address conflicts, endianness, unaligned accesses |
| Embedded/SoC | S3C64xx, S5L8900, GSC, crypto/sysctl/debug | Chip revisions, board wiring, firmware handshakes, conditions enabling stubs |
| Machines | PC/ACPI, ARM virt/FDT, RISC-V virt, Hexagon bare metal, SoC boards | Boot, memory maps, and interrupt topology beyond CPU instruction semantics |

Specific explicit limits include:

- **NVMe:** Registers and admin/I/O state machines exist, but transfers use PRP1 only. Transfers requiring PRP2/lists fail, and SGLs are unsupported. The command subset includes Read/Write/Flush; Flush is a no-op in the memory-backed model. The orchestration layer must inject interrupts through `take_interrupt`. [NVMe](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/devices/nvme.rs#L1-L65)
- **virtio-blk:** Supports IN/OUT/GET_ID and no-op FLUSH. DISCARD/WRITE_ZEROES and indirect descriptors are outside the implementation scope. These limits must be interpreted together with feature negotiation; an unsupported optional command is not automatically an incorrect implementation. [virtio-blk](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/devices/virtio/blk.rs#L1-L26)
- **Optional PCI wiring:** `attach_pci_devices` attaches e1000/UHCI/NVMe/AHCI/AC97 and other devices, but this default path provides no disk image for NVMe and no populated AHCI port. Controller enumeration and actual disk-I/O validation are distinct stages. [Wiring](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/vm/runtime.rs#L223-L309)
- **Embedded bring-up:** S5L8900 includes USB/accelerometer stubs and a placeholder UID key. Explicit GSC environment options synthesize some firmware results or force success. These bring-up options default to off; their existence does not mean default execution always forces success. Booting with such options enabled does not establish cryptographic-peripheral accuracy. [S5L8900](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/devices/s5l8900.rs), [GSC configuration](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/machine/gsc/runtime.rs#L1-L45)

## 9. User-mode operating systems and the C API

### 9.1 Substantial implementation exists beyond the CPU

| Area | Components established from current source | Validation boundary |
|---|---|---|
| Shared image/memory support | ELF, PE, Mach-O, address spaces, VMAs, supplied files, clocks/consoles/readiness | Parser, loader, and CPU semantics are separate contracts |
| Linux | ELF loader, stack/auxv, syscall ABI, mmap, signals, clone/futex/fork/exec, ptrace, files/sockets/IPC, seccomp, AIO/io_uring families | Distinct from system-mode execution of an actual Linux kernel |
| Darwin | Mach-O/dyld/shared cache, Mach ports/messages/MIG, VM, commpage, codesign, kevent, workqueues, psynch, signals | Does not establish replication of the complete macOS kernel and drivers |
| Windows | PE32/PE32+, x86/x64/ARM64, imports/relocations/TLS/PEB/TEB, DLL lifecycle, HLE, NT/registry/object namespace, SEH, heaps, synchronization, fibers | Native equivalence across all Windows versions and APIs remains unverified |
| C API | Engine/decoding/analysis, registers/memory/hooks, SMIR, process embedding, FFI boundaries | ABI success does not prove underlying CPU correctness |

Entry points include [user modules](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/user/mod.rs), [Linux](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/user/linux/mod.rs), [Darwin](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/user/darwin/mod.rs), [Windows](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/user/windows/mod.rs), and the [C API](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/capi/src/lib.rs). The C API package manifest uses version `0.1.2`, while the runtime API string is `1.14.0`. These are separate version schemes.

### 9.2 Interpreting Linux program records

Checked-in fixture provenance identifies native AArch64, Linux 7.0.14 OrbStack, an Alpine image, Docker, and recording dates. Some programs for other architectures ran through binfmt translators; some architecture-generic syscall expectations came from native A64 or source-derived overrides. The fixtures therefore cannot all be described as observations from native hardware for their respective ISAs. [Fixture provenance](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/tests/fixtures/user/linux/expected/ORACLE)

Such corpora are useful for loader, ABI, and runtime integration. Matching stdout and exit status does not establish matching signal timing, fault addresses, scheduler interleavings, file metadata, thread state, or exception frames. A large number of normally completing programs does not refute a specific MMU-permission or MXCSR counterexample.

### 9.3 Interpreting the name `src/oracle`

`src/oracle` is not an independent execution facility querying an external CPU. It exports decoder/lifter results as JSON and evaluates seeded state with the SMIR interpreter to report side effects. Seed memory is limited to 16 MiB, and some modes emphasize instruction length/control-flow summaries rather than detailed execution. The 80 passing `isa_oracle` tests are evidence about that API contract. **An API named Oracle is not necessarily architectural ground truth.** [Oracle implementation](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/src/oracle/mod.rs)

## 10. What an oracle must establish

### 10.1 Define the observable state first

Inputs include more than instruction bytes: CPU model/features, privilege, control registers, FP modes, page tables, memory attributes, interrupt state, and OS/platform bindings also matter. A single destination register is insufficient as an output comparison.

A suitable observation tuple is:

`O = (normal/trap, PC/EPC, cause, fault_address, GPR, FP/SIMD, flags, control_state, memory_writes, access_trace, external_events)`

If the specification permits multiple outcomes, a single byte pattern must not be treated as the only answer. Let `R(s)` be the set of specification-permitted results, `E(s)` the emulator result, and `P` the projection onto state observable in the test. The correctness criterion is:

`P(E(s)) ∈ P(R(s))`

`UNDEFINED`, `UNPREDICTABLE`, implementation-defined fields, undefined x86 flags, NaN payloads, and asynchronous interrupt timing require condition-specific treatment. Masking every difference hides errors; requiring exact bits where the specification permits alternatives produces false positives. Normal completion and fault paths require different comparison tuples.

### 10.2 Oracle categories and interpretation

| Category | Questions it answers well | Principal limits |
|---|---|---|
| Official ISA/platform specification | Which results and exceptions are permitted? | Requires version, optional-feature, and interpretation choices; may not be directly executable |
| Native CPU | What happens on this model in this state? | Can reflect one permitted implementation choice or erratum; privileged setup needs a suitable environment |
| Independent executable specification | What does the specification compute for this input state? | The model implementation, coverage, and assumptions also need validation |
| Independent implementation such as QEMU/Unicorn | Does a differential mismatch exist? | Not the final authority on the specification; shared lineage and common bugs are possible |
| Compiler/assembler/decoder | What is the encoding, allocation status, or disassembly? | Does not prove execution, flags, faults, or memory semantics |
| Internal direct/SMIR/JIT comparison | Are transformations mutually consistent? | Shared semantic errors survive |
| Checked-in expected data | Has behavior regressed for the same inputs? | Requires provenance of generator, environment, postprocessing, and versions |
| Bounded formal proof | Does a property hold within an explicit model and assumptions? | Excludes state outside the harness; linkage to the real platform and the whole ISA remains separate |

Conflicts are better resolved through **the specification's permitted set → hardware/independent-model observations → implementation lineage → exact comparison projection** than through a universal ranking. One hardware result does not exclude other permitted results; agreement between QEMU and Unicorn may reflect a shared error.

### 10.3 Where independence weakens in this repository

The ARM generator defines `ORACLE_CPU` as RAX AArch64Cpu. `emulator_expected_a64` runs RAX to determine acceptance and expected behavior. `characterize_a64_execution` records RAX register/SIMD/SP/PC/NZCV/memory results as assertions, replacing expectations calculated from ASL. That generated corpus is a **characterization/regression suite**. Inclusion of original ASL files does not establish that the generated expected values came from independent ASL execution. [Generator](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/tools/asl-parser/asl-parser-rs/src/testgen/output/rust.rs#L17-L149)

The A32 differential runner has a narrower structural limitation: parts of the path copy FP-register/FPSCR input values instead of installing and retrieving them through RAX, and the comparator omits FPSCR. Passing that harness therefore cannot refute the VFP counterexamples above. A64 native differential tests, A32 QEMU differential tests, and generated corpora must be classified separately.

The examined x86 KVM comparator compares GPRs, selected RFLAGS, and optional XMM/scratch/I/O state, but does not compare RIP. Some QEMU EVEX records omit MXCSR and exception details. A RISC-V vector harness path reduces traps to a boolean, losing exact causes, and uses a fixed VLEN. Each ISA appendix details state projections and skip conditions.

### 10.4 Scope of eBPF formal verification

Some eBPF components define an independent reference and formal harness more explicitly than the larger ISAs. The README's discharged/default proofs must still be separated from SMIR and SBPF execution proofs; some of the latter are explicitly not yet discharged.

Some default harnesses use 16-byte code, 32-byte memory, PC=0, a fresh CPU, an empty call stack, and default platform state with symbolic inputs. Fetch and SBPF-admission proofs have separate assumptions and program shapes. Division/remainder use an abstraction checking consistent operations on matching inputs; they do not prove the host divider's implementation itself. The SBPF reference is pinned to `solana-sbpf 0.25.0`, commit `3e1510b1eac344af15c99dcdb4c3b3e6dc2b3d7b`.

Even a valid proof under those conditions does not establish arbitrary program lengths, arbitrary call depths, Linux helpers, the complete Solana loader/runtime, JIT execution, or concurrent shared memory. Proof counts, selection conditions, and limits are detailed in the eBPF appendix. Kani was not rerun in this analysis. [Formal project](https://github.com/HexRaysSA/rax/blob/2ca3e35c54bcf4b64be63f524505a1a3e6b69b8b/tools/ebpf-formal/README.md)

## 11. Comparison with QEMU and Unicorn

### 11.1 The products serve different roles

| Dimension | RAX | QEMU | Unicorn |
|---|---|---|---|
| Principal role | Multiple ISA cores + SMIR/JIT + system/user runtimes | System/user emulation through TCG and accelerators | Embeddable CPU-emulation engine |
| Instruction translation | Own direct interpreter, SMIR, and host lowering | Guest frontend → TCG → host backend | CPU/TCG lineage forked from QEMU, exposed through an API |
| System environment | Own machine/device subsets | Boards, devices, MMUs, and related facilities in system emulation | Generally not intended as a complete OS/board model |
| User-binary execution | Own Linux/Darwin/Windows personalities | Target syscalls, signals, and related user-mode handling | Caller generally supplies syscall/SVC, loader, and external environment |
| Host acceleration | Some KVM/HVF paths | Architecture/platform-specific accelerators | Not a general VM-acceleration product in the same sense |
| Conformance oracle | Mixture of internal tests, native execution, QEMU, corpora, and specifications | Substantial independent implementation, still capable of errors | Overlaps QEMU lineage; not a fully independent second vote |
| Cycle accuracy | Not that type of model | TCG/icount is not a cycle-accurate model | Not a cycle-accurate hardware simulator |

Primary references: [QEMU emulation](https://www.qemu.org/docs/master/about/emulation.html), [QEMU user mode](https://www.qemu.org/docs/master/user/main.html), [TCG](https://www.qemu.org/docs/master/devel/tcg.html), [Unicorn FAQ](https://raw.githubusercontent.com/unicorn-engine/unicorn/master/docs/FAQ.md), [Unicorn architectures](https://github.com/unicorn-engine/unicorn).

Unicorn 2 was rebuilt on a QEMU 5-based lineage. That does not give it the same features or bugs as QEMU 8.2.2 or current QEMU master. The MXCSR experiments above demonstrate an actual behavioral difference. ISAs unsupported by either product were not presented as though equivalent execution comparisons had been performed.

### 11.2 Executed comparisons versus source comparisons

| Comparison | Work actually performed | Claim not established |
|---|---|---|
| Native x86 ↔ RAX | Three scalar-SSE conditions and CPL3 privileged-instruction traps | Certification of the complete x86 ISA or microarchitecture |
| QEMU 8.2.2 ↔ native | Three scalar-SSE conditions using the same native ELF | Execution validation of QEMU system-mode MMUs |
| Unicorn 2.1.4 ↔ RAX/native | Three x86 SSE conditions and six A32 VFP conditions | Accuracy assessment of all Unicorn targets |
| Current QEMU source ↔ RAX | A64 APTable/execute permissions and Hexagon packet-commit structure | Building that source and executing a complete system test suite |

QEMU source comparison used separately pinned commit `b6c4b7e86dec12d07f5cac65265b986d38ee9002`. The executed binary was 8.2.2; these sources of evidence were kept separate. The Unicorn documentation/source revision was `7c5db94191defc1e04a4f66f4eb1220903cba837`, while the executed package version was 2.1.4.

QEMU's ARM page walker clears AP[1] for APTable[0] to prevent EL0 access and sets AP[2] for APTable[1] to impose read-only access. Its privileged execute restrictions also account for user-writable attributes. Hexagon probes stores before committing a packet store log. These provide independent corroboration of the causes of the RAX counterexamples; they do not assume that every QEMU implementation is correct. [QEMU ARM page walker](https://github.com/qemu/qemu/blob/b6c4b7e86dec12d07f5cac65265b986d38ee9002/target/arm/ptw.c), [QEMU Hexagon translation](https://github.com/qemu/qemu/blob/b6c4b7e86dec12d07f5cac65265b986d38ee9002/target/hexagon/translate.c)

### 11.3 Limits on product-selection conclusions

This analysis does not determine speed rankings, overall compatibility rankings, or a universally preferable product. No benchmark controlled for identical workloads, features, hosts, warm-up, and measurement procedures was performed. A use case requiring architectural accuracy needs a defined ISA/CPU profile and independent reproductions of relevant behavior. RAX's SMIR, JSON oracle API, and OS personalities are useful analysis facilities, but their presence does not guarantee hardware equivalence.

## 12. Priorities for correction and validation

The following is a technical sequence for addressing the identified causes; it does not indicate that implementation changes or patches were submitted.

### High priority: preserve both normal results and fault contracts

1. Consolidate x86 scalar FP into a semantic path that applies guest MXCSR rounding, DAZ/FTZ, exception masks, and sticky status. If host FP is used, save and restore prior host control/status and calculate guest state separately.
2. Apply the same x86 permission predicates to page walks and TLB hits. Handle CR0.WP, NX/NXE, CPL, SMAP/AC, PKRU, reserved bits, and A/D updates explicitly. Constrain boot-convenience fallback so it does not erase architectural faults.
3. Translate and check attributes/permissions for every page touched by an A64 access. Evaluate data alignment and SP alignment under their distinct SCTLR conditions. Correct APTable, L3-descriptor, and PA-width handling.
4. Separate Hexagon packet input snapshots, `.new` forwarding, predicate combination, store logging, fault determination, and commit. Sequentially committing every instruction does not generally preserve packet semantics.
5. Map RISC-V AMO failures to the store/AMO fault class even when a read helper encounters the failure.
6. Include PC, FP status, exception codes, fault addresses, and preserved state after faults in oracle comparisons. Report unavailable external oracles separately from the number of cases actually validated.

### Conceptual page-boundary procedure

The following pseudocode describes address splitting for an ordinary scalar load. Atomic accesses, device memory, ARM partial-fault rules, and vector fault-first behavior require ISA-specific contracts; this is not a proposal to replace every store with the same algorithm.

```text
remaining = width_bytes
va = start_va
while remaining > 0:
    mapping = translate(va, access_kind, privilege, controls)
    n = min(remaining, mapping.page_bytes - offset_in_page(va))
    check_attributes_and_permissions(mapping, n)
    read_exact_physical_range(mapping.pa, n)
    va += n
    remaining -= n
assemble_bytes_using_guest_endianness()
```

For page size P, starting offset o, and access width W, the number of pieces is `ceil((o + W) / P)`. With fixed-depth page tables, scalar access costs O(k) for k pieces; retaining the assembled result requires O(W) additional space. TLB behavior, huge pages, and memory-fault priorities are additional design dimensions beyond this simple expression.

### Medium priority: environment and reproducible state

Include all active device and vCPU state in the checkpoint schema, or explicitly reject combinations that cannot be saved. Configuration round trips must retain `pci_devices`. Generate backend-feature and native-admission tables from current source, and mechanically label generated expectations as independent, model-derived, or self-characterized.

### Low priority: clarity of documentation and measurement

Update stale support statements and historical status documents. Clarify the `Oracle` name and distinguish test-case counts from validated state space. Performance comparisons require a separate procedure with identical guest binaries, hosts, features, and JIT warm-up conditions.

## 13. Assumption register and falsification probes

| ID | Assumption / scope | Falsification or stress probe | Dependent conclusions |
|---|---|---|---|
| AS-01 | The target is the pinned commit; tracked source was not modified | Compare Git HEAD, index object IDs, and tracked diff | Every code finding in this report |
| AS-02 | Each counterexample starts from a legal state for the selected ISA/profile | Recheck reserved encodings, features, privilege, table formats, and packet slots against primary specifications | X/A/R/H counterexamples |
| AS-03 | Native x86 results describe architectural execution on this host | Repeat on other CPU vendors/models and bare-metal/KVM environments | Specific native comparisons; no claim over all CPUs |
| AS-04 | The selected specification rules apply to the selected profile | Check architecture revision, optional features, and errata | MMU, alignment, FP, and packet expectations |
| AS-05 | Direct-path counterexamples are not assumed to propagate unchanged to all native/SMIR paths | Execute the same seeds independently through each execution plane | Conclusions limited to individual planes |
| AS-06 | Equality under a projection does not establish equality of complete state | Add omitted RIP/FPSCR/cause/memory traces to comparators | Oracle-limit analysis |
| AS-07 | Checked-in expected data record the environment stated in their provenance | Recollect with original binary hashes and kernel/translator versions | Interpretation of corpus passes |
| AS-08 | Formal proofs are limited to harness models, bounds, and assumptions | Expand memory/code/call-depth/platform bounds and rerun the solver | Scope of eBPF proof claims |
| AS-09 | Static HVF/device/snapshot findings are not exhaustive hardware validation | Execute end-to-end on the relevant OS/backend/device combinations | C-HVF, C-STATE |
| AS-10 | Performance and cycle-timing equivalence were outside this validation | Run a common benchmark and separate timing/model experiments | Deferral of product performance rankings |

Incorrect candidates were also rejected. For example, a candidate treating every A64 EL0 instruction fetch with AP=00/UXN=0 as erroneous was removed after rechecking Arm's separate data- and execute-permission rules. RISC-V vector tests for vstart and overlap do exist; the report does not claim otherwise. Passing A64 FP controls were executed to prevent overgeneralization of the A32 defects.

## 14. Bounded additional risks and opportunities

| Impact | Inference from the observations | Evidence and remaining work |
|---|---|---|
| High | Shared helpers and self-generated expectations can allow incorrect behavior to pass in several execution planes | ARM generator, x87 helpers, and JIT replay structure examined; independent state comparison required |
| High | Small differences in MMUs, exceptions, or packet commit can change OS/firmware control flow | Explicit reproductions available; frequency in real programs not measured |
| High | Missing snapshot state can change behavior after resume | Configuration round trip reproduced and schema inspected; all devices not exercised end-to-end |
| Medium | Reading admission/coverage counts as actual execution support can overstate support | Separate stage gates and corpus provenance |
| Medium | Native/QEMU/Unicorn triangulation can expose shared errors | Actual SSE MXCSR example; expanding to all instructions has additional cost |
| Medium | Fixed validation profiles can keep regressions focused after corrections | Minimal harnesses and source pins supplied |
| Low | Stale comments/documentation can misdescribe current features | Current source takes precedence for RDTSC, RISC-V status, and user personalities |
| Low | Existing evidence cannot rank performance or hardware timing | Requires controlled benchmarks and a separate timing model |

## 15. Quality checks and reading guide

| Check | Result |
|---|---|
| Commit/source provenance | Pinned commit, file inventory, and Git object IDs included |
| Original source modifications | None to tracked source; external harnesses and outputs created |
| Strength of reproductions | D-full/D-module/S distinguished; executed host/QEMU/Unicorn evidence separated from source comparisons |
| Existing tests | Logs establish 399 passing test functions; no claim that the complete suite passed |
| Independent oracles versus internal parity | Discussed separately; ARM generated expectations shown to be self-referential |
| Prevention of overstatement | A64 FP controls, rejected candidate, and existing vector tests retained |
| Source revision versus executed binary | QEMU master source distinguished from the 8.2.2 binary |
| Numbers and units | Bit patterns/MXCSR, 4 KiB pages, eight-byte loads, three ticks/ns, and MiB distinguished |
| Unverified areas | Native ARM/Hexagon, KVM/HVF, complete OS/devices, and Kani reruns explicitly unverified |
| Reproduction materials | Source, stdout, test logs, manifests, versions, and execution procedures supplied |

The ISA appendices provide finer-grained examination by file, function, encoding, exception, and test harness. Use implementation tables to locate the review boundary, counterexample tables to assess actual mismatches, and oracle tables to interpret precisely what a passing result establishes.
