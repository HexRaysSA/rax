[← Documentation home](../../../README.md)

# x86-64 architecture

x86-64 is the broadest machine target in `rax`. It has a software interpreter, hardware-assisted backends, Linux boot paths, legacy real-mode/ISO boot, the most complete PC device model, differential tests against KVM and QEMU, and native SMIR execution on x86-64 and AArch64 hosts.

That breadth does not make every x86 instruction, machine configuration, or backend equally mature. Treat source and executable inventories as the authority for individual opcodes; treat this page as a map of the implemented surfaces and their validation boundaries.

## Public execution paths

| Path | Host requirement | Guest use | Observability |
|---|---|---|---|
| `--arch x86-64 --backend emulator` | supported 64-bit Unix host | direct ELF Linux boot, bare machine work, legacy ISO path | interpreter trace, GDB, profiling, instruction-count snapshots, optional JIT |
| `--arch x86-64 --backend kvm` | Linux/x86-64 with usable `/dev/kvm` | Linux and KVM-backed machine execution | hardware exits and device events; not per-instruction interpreter observation |
| `--arch x86-64 --backend hvf` | supported macOS/x86 host and HVF build | hardware-assisted x86 guest path | backend-dependent; not the software step loop |
| x86 guest through SMIR on x86-64 host | `smir-jit`, supported Unix host | eligible hot regions | promotion/fallback counters; optional live verification |
| x86 guest through SMIR on AArch64 host | `smir-jit`, AArch64 host | eligible register-only scalar hot regions | static admission plus dedicated cross-host tests |
| `rax-user PROGRAM` | Linux or macOS | Linux x86-64 ELF; partial ELF32 i386 compatibility | syscall logging and guest `ptrace`; compatibility code stays interpreted |

Only one virtual CPU executes in the machine runtime. `rax-user` schedules
guest threads on one emulated CPU per process and forks host processes for
guest child processes; it does not use KVM or HVF.

## Decoder surface

The decoder is structured to recognize the principal x86-64 encoding families:

- legacy prefixes, including address-size override;
- REX and REX2;
- opcode maps and escape bytes;
- ModR/M and SIB addressing;
- RIP-relative addressing;
- VEX2 and VEX3;
- EVEX, including extended maps used by newer vector and APX encodings;
- immediates, displacements, opmask controls, vector lengths, broadcast, rounding, and masking fields where the instruction family consumes them.

A decoder accepting an encoding is only the first layer. Reachable execution, exception behavior, memory effects, feature gating, and differential coverage are separate claims.

## Integer, control, and system execution

The current implementation inventory includes the ordinary integer ALU, carry and overflow chains, shifts and rotates, double shifts, bit test and bit scan/count families, moves and extensions, multiply and divide forms, stack operations, branches, calls, returns, condition-code operations, string operations, and selected BCD instructions.

Important semantic surfaces include:

- arithmetic flag production and lazy materialization;
- `#DE` behavior for divide-by-zero and quotient overflow;
- canonical-address checks;
- privilege checks for control, debug, descriptor-table, and model-specific register operations;
- injection of architectural faults such as `#UD` and `#GP`;
- control-register, debug-register, CPUID, MSR, descriptor-table, XSAVE/XRSTOR, and XCR0 state;
- segment and FS/GS-relative addressing;
- lock and read-modify-write boundaries;
- repeat-prefix string behavior, including bulk paths where applicable.

The interpreter uses lazy flags: arithmetic can retain the operation and operands until a later instruction consumes the relevant RFLAGS bits. Any optimization or native lowerer must preserve not merely the final numeric result but the flags actually observable at every exit and exception boundary.

## Floating point and vector execution

The checked-in high-level inventory covers:

| Family | Current documented surface |
|---|---|
| x87 | D8–DF escapes execute on raw 80-bit extended-precision registers through the data implementation shared by the direct engine and SMIR; precision/rounding control, exception flags, masked responses, and stack faults are modeled |
| SSE–SSE4 | scalar and packed moves, arithmetic, comparisons, shuffles, permutations, conversions, and integer SIMD families |
| AVX / AVX2 | VEX-encoded XMM/YMM forms, integer and floating-point arithmetic, data movement, shuffles, conversions, FMA, BMI-related scalar operations |
| AVX-512 | F, VL, BW, DQ, CD and additional families including FP16, VBMI/VBMI2, IFMA, VNNI, BITALG, VPOPCNTDQ, BF16, VP2INTERSECT, masked operations, opmask state, gather/scatter, and EVEX crypto forms |
| AVX10.1 / 10.2 | selected documented VNNI, IFMA, population-count, byte-manipulation, BF16, min/max, VMPSADBW, and saturating-conversion forms |
| Crypto | AES, SHA, GFNI, carry-less multiplication and newer vector crypto families where reachable |
| APX | REX2, extended GPRs, NDD/NF forms, conditional compare/test, SETZUcc, PUSH2, JMPABS, MOVBE, multiply/divide, and Map 4 work represented in source/tests |

Do not infer “all AVX-512” or “all APX” from a family label. The generated instruction corpus, unimplemented manifests, source inventory tests, and differential target results define the current finite claim.

The x87 direct wrapper owns availability checks, guest-memory faults,
environment/state images, and RFLAGS updates. Shared data semantics live in
`src/smir/interpret/x87/data.rs`; transcendental approximations live in
`src/smir/interpret/x87/transcendental.rs`. Raw 80-bit storage does not make
every transcendental result identical to every hardware implementation,
and direct-vs-SMIR agreement is not an independent oracle for their shared code.

## Linux user mode and compatibility tasks

The default-off user-mode engine path runs at CPL 3 and translates through
the process address space. `SYSCALL` reports a syscall exit; exceptions and
software interrupts are exported to the Linux personality for signal handling.
The engine supplies Linux-style user GDT entries, including TLS entries 12–14
and the CPU/node entry used by `LSL`.

ELF32 i386 programs run with `CS=0x23` in IA-32e compatibility mode. Their
`INT 0x80` calls reach a separate 32-bit conversion table; `INT 0x80` from
a 64-bit process is still refused with `ENOSYS` after seccomp inspection.
Compatibility code is interpreted, and the 32-bit syscall table remains
partial. Outside 64-bit mode, linear address formation wraps to 32 bits
after adding the segment base; this differs from merely truncating an
effective offset before segment-base addition. See
[Linux ABI and loading](../user-mode/linux-abi.md#i386-compatibility-tasks)
for the supported compatibility boundary;
[validation evidence](../../development/testing/user-mode.md#abi-and-loading)
lists its tests.

## Software MMU and interpreter loop

The direct software loop is conceptually:

```text
fetch → decode or decode-cache hit → execute → commit/fault → device/timer polling
```

The current design includes:

- a 4096-entry RIP-indexed decode cache with a mode-sensitive key;
- coherence handling for guest writes to executable code;
- a 256-entry direct-mapped translation cache over four-level page walks;
- support for 4 KiB, 2 MiB, and 1 GiB mappings in the documented x86 path;
- direct host-pointer access for ordinary RAM where safe;
- fast paths for common ModR/M memory forms;
- page-oriented string-operation acceleration;
- periodic LAPIC/device polling and host yielding;
- a dirty-page journal used to invalidate native regions after self-modifying code.

A decode-cache hit avoids repeating the guest-memory fetch only when the cached bytes and mode tag still match. Self-modifying code must invalidate both decode and native-region assumptions.

## Linux direct boot

The direct x86-64 Linux path supports an uncompressed ELF `vmlinux`; the hardware path also accepts the relevant Linux boot image form. The documented direct-load layout uses:

- kernel physical load near `0x01000000`;
- initrd placed below the top of guest RAM and constrained by image metadata where applicable;
- initial identity mappings for early execution;
- a higher-half kernel mapping near `0xffffffff80000000`;
- a direct-map base near `0xffff888000000000`;
- a minimal 64-bit GDT;
- `CR0.PG`, `CR4.PAE`, and `EFER.LME` configured before transfer to the 64-bit entry point.

The maintained software-boot path is narrower than arbitrary distro kernels. Use the repository’s `make linux` and `make run-linux` flow before diagnosing a custom kernel. CFI/FineIBT, mitigation-heavy configurations, boot-compressed entry, and unusual early-boot assumptions may expose unimplemented behavior.

See [Linux guests](../../getting-started/linux-guests.md) and [Machines and boot](../machines.md).

## Legacy real-mode and ISO boot

The legacy path contains a small real-mode firmware environment with handlers for selected BIOS services, El Torito catalog processing, and an ATAPI CD-ROM path. It starts a boot image at `0x7c00` and allows the guest to transition through real, protected, and long mode.

TempleOS V5.03 is the named integration workload for this path. That is an end-to-end milestone for the specific image and path, not a claim of complete PC BIOS compatibility.

## PC device environment

The x86 machine wires the baseline serial/interrupt/timer/storage platform and can attach an optional PCI set. The detailed distinction among “model exists,” “machine wires model,” and “guest driver exercised model” is documented in [Devices](../devices.md).

The current headline boundaries are:

- serial console is the primary display and input surface;
- VGA is not wired into the maintained machine path;
- only one vCPU executes;
- optional PCI interrupts are not documented as a complete production-quality interrupt-delivery model;
- a device enumerating is weaker evidence than sustained guest I/O correctness.

## Differential verification

Named x86 comparison targets include:

| Cargo target | Reference | Principal compared state |
|---|---|---|
| `differential` | KVM hardware | GPRs, RIP, selected RFLAGS, XMM state, scratch memory according to the case |
| `x86_64_avx512_kvm_diff` | KVM hardware with required features | ZMM/opmask state, flags, scratch memory |
| `x86_64_evex_qemu_diff` | `qemu-x86_64` | generated EVEX state projection |
| `x86_64_apx_map4_qemu_diff` | QEMU when it implements the required APX surface | generated APX Map 4 projection; may self-skip today |
| `x86_64_unimplemented_qemu_diff` | `qemu-x86_64` | rejection behavior for generated unimplemented cases |
| `diff_fuzz` | KVM plus interpreter/SMIR paths | randomized encodings and selected architectural state |

Additional direct-semantic, crypto known-answer, inventory, boot, and SMIR tests cover different layers. No one target establishes complete architecture equivalence. See [Verification model](../../development/verification.md) and [Test target map](../../development/testing/README.md).

## SMIR and native execution

On x86-64 hosts, the JIT admission surface includes a broad scalar integer core, control flow, eligible memory operations through runtime helpers, and a whitelist of vector/crypto operations gated by host features and guest MXCSR requirements. Calls can be handled through interpreter call-outs so a native region may resume after the callee; runtime environment variables can restore more conservative boundaries.

On AArch64 hosts, the production x86 path is intentionally narrower: register-only scalar regions over the ordinary x86 GPR set, with an explicit RFLAGS/PSTATE bridge. Memory, FP/SIMD, APX extended registers, unrepresentable flag contracts, and virtual-temporary requirements cause fallback.

Still-interpreted or specially constrained surfaces include locked/RMW operations and double-width divide where the IR or lowerer cannot model the exact contract. Native admission is a per-region decision, not an ISA-wide switch.

See [SMIR and native execution](../smir.md).

## Known limitations and non-claims

- The public project is not a complete PC hypervisor or hardware conformance suite.
- Software Linux boot is validated against a deliberately controlled configuration, not every modern distro kernel.
- A successful KVM test command can still mean the test self-skipped because `/dev/kvm` or a host feature was absent.
- QEMU comparison covers only the projected state and cases that executed.
- APX has no shipping-hardware oracle in this setup; encoding provenance, documentation-derived semantics, and staged QEMU cases must be described separately.
- JIT equality is tested over named cases and can be live-audited on the x86-64 host path; it is not a formal proof over every input state.
- Hardware backends do not expose the same instruction-by-instruction observation model as the software interpreter.
