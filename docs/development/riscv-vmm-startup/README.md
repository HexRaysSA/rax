# Generic RV64 VMM startup and ELF loading

A fresh generic RV64 VMM now starts every configured hart at the admitted image
entry. Each hart receives `a0 = mhartid` and a distinct, checked 4096-byte
bootstrap stack page. The execution coordinator initially marks these harts
online. The backend selects this convention using its explicit machine family;
GSC and other boards retain their own reset and power policies.

This is RAX's bare-metal boot convention. The RISC-V Privileged Architecture
20250508, sections 3.1.5 and 3.4, requires unique hart identities and specifies
M-mode reset with an implementation-defined PC. It leaves other integer reset
state unspecified. It does not prescribe RAX's stack allocation or `a0` convention.
Firmware owns any later stack sizing. The existing zero-based RAM mapping and
4 GiB guest-memory padding remain. This group does not qualify Linux, SBI, DTB,
CLINT, PLIC, common VM clocks, or full platform replay.

## Image admission

The loader honors ELF `e_entry`; it no longer guesses another entry from an
MRET byte pattern, `test_entry`, or `test_N` symbols. It scans ordinary defined
`tohost` symbols independently of test labels, retains a defined value of zero,
and rejects conflicting addresses.

The selected profile is little-endian ELF64 `EM_RISCV`, `ET_EXEC` or `ET_DYN`
without `PT_INTERP` or `PT_DYNAMIC`. Header versions/sizes, segment file bounds,
`p_filesz <= p_memsz`, alignment, checked physical ranges, Unix writable backing, and
an even entry within an executable loaded span are admitted before the first
image store. Placement retains `p_paddr` when nonzero, otherwise `p_vaddr`.
The reset PC is a bare physical entry; no ELF virtual-address translation or
dynamic linking is performed. These checks do not claim a general-purpose ELF
linker or admission of every symbol/relocation/ABI profile.

Every admitted `PT_LOAD` copies its file bytes and zero-fills its memory tail.
Writes use the shared RAM reservation domain, so a new image withdraws stale
exclusive rights. The caller quiesces CPUs during loading. Segment admission
precedes publication; publication is not one transaction against an uncoordinated
concurrent embedder.

For N harts, let E be the mapped RAM end rounded down to 16-byte alignment:

```text
reserved bytes = N * 4096
stack base     = E - reserved bytes
SP(hart h)     = E - 16 - h * 4096
```

Checked arithmetic rejects an invalid topology, overflow, insufficient RAM,
image overlap, mapping holes, and read-only stack backing. Stack pages are
reserved above the whole admitted image extent. ELF loading takes time
proportional to parsed metadata, visited mappings and published bytes; the
segment list uses O(P) auxiliary space for P loadable segments and zero fill
uses a fixed 65536-byte buffer. Per-hart stack admission visits the reserved mapping span. Across N harts it
makes O(N * R) region visits for R regions; time also includes memory-map lookup
and shared-reservation bookkeeping.

## Actual execution and restoration

The library tests and the registered public `riscv_boot` executable use the
53-instruction fixture in `tests/fixtures/riscv/vmm_startup.S`. LLVM 23 produces
its checked-in words. Each guest reads `mhartid`, checks its initial `a0`,
records its initial stack, and atomically publishes shared work. The BSP can
shut down successfully only after every configured hart contributes.

The source-free file test uses this sequence for one, two and four harts:

```text
Vmm::new -> every hart publishes READY and waits for GO
        -> capture at cursor 0 (one hart) / 1 (multiple harts); WORK still zero
        -> save .rxc -> load .rxc -> remove original kernel file
        -> Vmm::new_resume_bundle; compare online/cursor/private contexts
        -> set GO -> Vmm::run -> every hart publishes new WORK
        -> compare final coordinator and complete private hart contexts
```

Normal boot initialization is skipped on resume. Saved state controls the
runnable set, cursor, registers, and backend-private continuation. The test uses
actual coordinator turns and the public run loop, without manually running an
AP or manufacturing an online set.

The same normal-startup instruction bytes pass QEMU 11.1.2 with one, two and
four harts, TCG single-thread mode, and explicit `-icount
shift=10,align=off,sleep=off`. QEMU loads the code at `0x80000000`; RAX's ELF case
loads it at `0x1000`, with identical position-independent instruction bytes.
QEMU exits through its test finisher store; RAX treats that store as ordinary
RAM and continues to its successful ECALL. This comparison does not constrain
QEMU's unspecified initial stack or establish cycle accuracy.

One earlier untraced two-hart QEMU run timed out without icount; a traced run
without icount succeeded. The exact timeout cause is unknown. Both results are
retained. The passing oracle claim is limited to the explicit controlled
configuration, and does not erase the earlier failure.

## Validation and limits

The complete root library ran **12171 passed, 0 failed, 35 ignored**. The 44 independent executables ran **1194 passed, 0 failed, 8 ignored**; 4 host-gated executables were empty. All 19 C/C++ consumer programs and seven ABI translation units passed. Workspace formatting, build, check, Clippy, no-debug/no-JIT checks and doctests completed.

Final counts, exact commands, executable/source checksums, baseline failures,
assumptions, and requirements are recorded in [qualification.json](qualification.json).
The baseline records six real failures: inferred entry, missing BSS zero fill,
partial image publication, CPU0-only two/four-hart runs, and incomplete initial
hart state. A supplemental public-loader probe separately demonstrated admission
of an invalid ELF identification version and passes after the header checks.

Reproduce the owning cases with an isolated target directory:

```sh
CARGO_TARGET_DIR=/absolute/owned/rax-build cargo test --locked \
  --no-default-features --features x86_64-suite,smir-jit,hvf,debug --lib -- \
  machine::riscv_virt::tests:: vm::runtime::riscv_startup_tests:: \
  --test-threads=1 --nocapture
CARGO_TARGET_DIR=/absolute/owned/rax-build cargo test --locked \
  --no-default-features --features x86_64-suite,smir-jit,hvf,debug \
  --test riscv_boot -- --nocapture
```

The complete library and owning executables remain required beyond these
iteration filters. Host-gated zero-test binaries provide compile evidence only.

| Assumption | Stress test / falsification probe | Status |
| --- | --- | --- |
| Generic RV64 reset uses M-mode and a platform-defined PC | Primary reset rules; actual guest `mhartid`/entry execution | Confirmed in the selected profile |
| Bootstrap pages are a RAX convention | One/two/four harts; image overlap, holes, read-only backing, alignment and invalid topology | Checked locally |
| Existing execution/private sections retain all runnable generic harts | Source-free one/two/four-hart files, nonzero multi-hart cursor, equal contexts and fresh work | Checked locally |

| Impact | Remaining boundary |
| --- | --- |
| High | Full generic RISC-V CLINT/PLIC, clock/SBI/platform replay, other backend/private/in-flight profiles, A32 controls, native MMIO/IRQ and physical Intel qualification remain open. |
| Medium | The legacy RAM layout and fixed bootstrap pages are not a Linux/SBI boot ABI. |
| Medium | Uncontrolled QEMU scheduling remains unqualified after the retained timeout. |

A separate common-byte CLINT IPI probe passes under QEMU with two/four harts and
fails actual RAX VMM runs with both counts. That is a reproduced next requirement,
not a passing result of this startup group. All four original findings remain
`partially_validated`.

Primary ELF and QEMU chapters are retained under [references](references/), with
URLs, dates and checksums in [provenance.json](references/provenance.json). The
RISC-V primary is the existing retained
[`riscv-privileged.txt`](../../specifications/riscv/riscv/riscv-privileged.txt).

Upstream CI at the integration base also records a Linux x86 native JIT
verification divergence and a Windows fresh native registry replay mismatch.
Windows C API unit tests passed; the failing Windows step is the registry probe.
The Linux ARM64 job separately received a runner shutdown signal. Their root
causes remain unknown. These runs predate this startup group; their exact captured
logs are retained as deterministic gzip archives under `references/`, with
URLs and compressed/uncompressed hashes in `provenance.json`. Local passing
counts do not establish that those remote failures are resolved.

The fresh Windows registry corpus and its single-case derivative also fail on
this tested build at entry offset `0x8` (observed `0`, native expected `0x90`).
The fresh capture uses kernel build 20348; retained controls use build 29695.
The cause and the required version/profile behavior remain unresolved.
