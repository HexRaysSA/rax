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
has its own explicit version tag. Both versions use strict bounded decoding.

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
