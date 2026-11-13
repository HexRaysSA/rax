# x86 user checkpoint integration control

`user-v1.bin` is an actual pre-integration engine checkpoint, not bytes
constructed by the new decoder. It contains a pending user-mode SYSCALL,
return RIP `0x102`, instruction RIP `0x100`, and one retired instruction.
The source and target have one CPU and 65,536 bytes of RAM.

- Length: 3403 bytes.
- SHA-256: `c6fe57541c859b88b75789afcaf2a7377c81297fe5024a970f5d523b0ebcb0ca`.
- Producer engine SHA-256: `3a3ed9d1e5746f9fe9ef294102f21b4d338f691e95d3a368d5fd0178f0c978a4`.
- Producer source SHA-256: `03e8fd9291fdf6fe26bfa64a42f81bc290105768d8c6c0628c84abaf6bf6b655`.
- Engine artifact: `librax-8c318d01a9f74ad1.rlib`, retained from the preceding
  qualification before integration. Its hash differs from an earlier standalone
  writer probe because subsequent workspace gates rebuilt that artifact.
  Whole-engine commit identity is not asserted from an artifact filename.
- Compiler: Rust 1.99.1, native `aarch64-apple-darwin`.
- Reproducer: [producer.rs](producer.rs); compile against the pre-integration
  engine and its matching vm-memory dependency, then pass the output path.

The complete command, stdout, artifact hash, and initial regression-compilation
errors are retained in the task's `recovery/main-integration-2026-10-28` evidence.
The library test `pre_integration_user_context_retains_its_original_wire_layout`
imports these frozen bytes, verifies both PCs and retirement, consumes the
pending syscall once, and checks the absent legacy debug history defaults to zero.

## Version boundary

The frozen RAXX8601 user representation has only `trap` and `compat`.
RAXX8602 keeps that base representation and adds an optional consumed DR6
snapshot after it. The option must be present exactly when the base has a user
binding. Restore retains the target's memory and translation bindings.
The attempt-local MOV/POP SS trace suppression resets at the next instruction;
it is reconstructed as false at the synchronous checkpoint boundary.
The C API outer format and VM producer kind remain unchanged: the inner record
has its own explicit version tag. All versions use strict bounded decoding.
RAXX8603 wraps the unchanged version-2 representation with the represented
IA32_APIC_BASE value, preserving successful BSP-flag writes. Version-1 and
version-2 inputs remain accepted; their absent APIC state starts from the
configured CPU's boot identity. See [CPU identity](../x86-cpu-identity/README.md).

RAXX8605 additionally preserves a pending MOV/POP SS instruction-breakpoint
shadow. RAXX8606 carries the same envelope with I/O APIC MMIO enabled, matching
the policy represented by RAXX8604. These tags are emitted only while that user
shadow is pending; ordinary captures keep their existing RAXX8603/4 encoding.
The frozen base and all version-1 through version-4 inputs remain supported.
Unlike attempt-local TF suppression, the instruction-breakpoint shadow spans
an instruction boundary and must survive a save/restore at that boundary.

Instruction comparators use the linear CS:RIP address and raise fault-class
vector 1 before fetch/decode or retirement. DR7 local and global enables select
the four execution slots; matching slots set their DR6 bits. Incoming RF or the
MOV/POP SS shadow suppresses that check. Debug entry clears DR7.GD, and an
execution breakpoint preserves incoming RF rather than setting it as another
fault would. Enabled execution comparators keep both explicit JIT entry and
automatic promotion on the interpreter path, including when RF is temporarily
set. These rules follow Intel SDM revision 086, Vol. 3B, sections 19.2.4 and
19.3.1.1 in the [local manual](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf).

Windows CONTEXT capture and selected-group restoration include debug registers.
Its API and exception paths share register encoding and validation. For the
measured AMD64/ARM64 kernel overlay, native breakpoint registers project to the
x86 execution bank and x86 debug status returns to the native context bank.
Native exception-dispatch frame qualification remains a separate contract.
Paired-context validation copies retain both debug banks and configurable GDT
entries, so an unselected DEBUG group survives a native CONTROL/INTEGER/FP
restore. Ordinary new-thread cloning retains its separate initialization contract.

## Darwin instruction debug state

Both x86_DEBUG_STATE64 and the unified x86_DEBUG_STATE install their validated PCB comparator image in the x86 execution core. The trusted core accessor changes DR0-DR3, DR6 and DR7 only; it does not replace flags, counters, TLS, pending events, private shadows or consumed debug history. Native admission checks the current bank before another region executes.

Darwin return_to_user loads DR0-DR3 and DR7, with DR6 remaining independent live status. A requested PCB DR6 does not get loaded into hardware. user_trap captures and clears live DR6 on debug entry, then publishes that captured value to the existing PCB image. copy_debug_state64(..., FALSE) preserves the PCB's reserved DR4/DR5 fields rather than installing those input fields. General-context validation copies retain the interrupted thread's live bank, including a cleared DR6, and then reinstall its PCB comparators. New-thread initialization keeps its separate fresh-bank contract.

These rules follow the repository's primary XNU 12377.121.6 sources: osfmk/i386/pcb.c (dr7d_is_valid, set_debug_state64, copy_debug_state64), osfmk/x86_64/idt64.s (L_dr_restore_island), and osfmk/i386/trap.c (user_trap).

The process regressions exercise all four slots through both Mach flavors, faulting PC and no retirement, stale requested DR6, live-status clearing, rejected/global-enable and cleared updates, ignored DR4/DR5 inputs, and preservation through general-context writes. Four new regressions failed before installation was wired. The native control attempted through Rosetta produced no terminal success result; its precise blocking point is unknown. Later host reboots removed the original probe processes. No native completion is inferred from their absence, and physical Intel Mach debug-register execution remains unqualified.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| D1 | The PCB's requested DR6 is not loaded on return; DR0-DR3 and DR7 are loaded, and DR4/DR5 input fields are ignored. | The three primary XNU paths above. | Trusted bank installation and context-copy preservation. | Both Mach flavors, four slots, stale status, cleared/rejected state, general-context restore. | A primary return path loads DR6 or a controlled native Intel observation contradicts the distinction. | Confirmed in primary source and model regressions; physical Intel native control remains unqualified. |

Data watchpoint execution, Linux NT_ARM_HW_WATCH and AArch32 debug regsets, and complete same-host process qualification remain separate full-goal requirements. The ARM64 instruction-breakpoint regset is implemented in this group. Native Windows continuation and installed-library exception entry have separate runtime qualification; these component results do not establish ordinary Windows program completion. This component introduces no public C ABI layout/version or new serialized field.

## Linux ptrace instruction debug state

Linux keeps its ptrace comparator objects and requested DR7 in the thread. Both
native and i386 tracer word views dispatch the debug area before the general
register view. DR0-DR3 writes create or update validated objects; DR4/DR5 read
zero and reject every write. DR7 readback preserves the exact requested word,
including ignored reserved bits. Execution uses only enabled, validated
comparator fields, with Linux's global-enable encoding and architectural bit 10.
Updates follow ptrace_write_dr7's restoring pass: earlier newly allocated objects
remain allocated and disabled when a later comparator fails validation.

Virtual DR6 uses Linux's positive internal polarity and reads back with
DR6_RESERVED XORed. Arbitrary tracer writes affect that snapshot without writing
live hardware DR6 or injecting a trap. Each actual debug entry replaces it with
the current trace/comparator causes. Linux adds RF on instruction-breakpoint
entry, permitting one retry at the faulting PC; requested DR7 remains unchanged.
The general-context paths leave comparator objects intact. Fork/clone clear the
installed objects but retain virtual DR6/requested DR7; exec clears both.

Admission uses the existing four-level Linux user-address profile, not the
57-bit address width of the independent Linux control VM. Type/length validation
also covers data configurations, whose execution remains an open core requirement.
The adapter introduces no public ABI or CPU checkpoint field. Admission and
installation visit four slots: O(1) time and O(1) space.

The [own-child controls](../../specifications/linux/native-ptrace-debug/README.md)
record four precise instruction stops and successful continuations, virtual
readback, rejected writes and fork inheritance under a native Linux kernel in
QEMU TCG. The regression tests exercise both guest ABIs and tracer word views,
status isolation, RF, rollback, clone and exec lifecycle. Physical Intel hardware
and Windows-native execution remain unqualified by these controls.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| L1 | Requested DR7 and virtual DR6 are independent of installed comparator controls/status. | Pinned Linux v6.19 ptrace.c, traps.c and hw_breakpoint.c; own-child instruction control. | Thread-owned bank, requested readback, positive status and RF. | Both word views, reserved controls, arbitrary status, rejected updates, precise retry. | Native own-child observations contradict the split or current-cause replacement. | Confirmed in primary source and the native control; emulator regression gate recorded separately. |
| L2 | Fork/clone discard comparator objects while retaining virtual DR6/requested DR7; exec clears all. | v6.19 process.c copy_thread/flush_thread; own-child fork control. | Lifecycle wiring. | Active parent comparator, stale virtual status, clone and exec replacement. | A controlled child retains the comparator or loses its virtual snapshot before a debug exception. | Confirmed in primary source and fork control; clone/exec regression gate recorded separately. |

## Assumption register and limits

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
| --- | --- | --- | --- |
| I1 | The integration worktree is task-owned; main is committed input. | Compare primary HEAD/index/diff/untracked-name hashes before and after the group; reject unexpected task input. | Confirmed before merge and during qualification; recheck at commit. |
| I2 | Context capture occurs between synchronous CPU/native invocations. | Existing active-native checkpoint rejection and pending-exit continuation tests; concurrent raw memory aliases remain outside this boundary. | Retained; whole-VM quiescence remains open. |

High impact: whole-VM coordinated publication and other complete backend contexts
remain open audit requirements. This integration control establishes neither
physical Intel HVF execution nor complete SMP scheduling.

## Executed integration validation

The observed pre-fix owner run passed 12 tests and failed both new compatibility
controls. The corrected native library passed 11,157 tests, with two existing
ignored tests. The x86 ISA target passed 28,559 with three ignored tests; the
Rosetta x86 library selection passed 1,008. All 377 Darwin, 43 Linux, 544
portable Windows personality, eight Windows CLI, 208 C API, and 187 checkpoint
tests passed. The Linux Docker oracle remains ignored. Eighteen C/C++ consumers
and six strict ABI objects passed and their generated files were cleaned.
Workspace formatting, Clippy, and all-target compilation passed. Five existing
doctests were ignored; no doctests executed.

`realmode_boot` and `user_windows_memory` were cfg-empty on this host. The
independent x86 QEMU/file control did execute and emitted `S` uninterrupted and
after fresh restore with the original ISO path unavailable. The actual exported
C API preserved XCR0 and continuation in both 32-bit and 64-bit modes. These
results do not establish physical Intel HVF, native Windows, or a wasm build.

At integration qualification, the combined engine emitted `1` after restoring
the unchanged AArch64 exclusive-reservation guest, while QEMU and uninterrupted
RAX emitted `0`. That historical checkpoint had no backend context. The later
[AArch64 private-checkpoint implementation](../aarch64-checkpoints/README.md)
retests the identical guest and frontier: QEMU, uninterrupted RAX and fresh file
restore all emit `0`. Full C-STATE closure still requires the remaining native,
in-flight and whole-VM transaction work.
