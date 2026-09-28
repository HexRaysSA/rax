# x87 noncanonical stack-reference fault class

Semantic group against `0fb5543ec895c345805b67793f98c6fd4b7c14f1`
on `user-win`. The tracked worktree and index were clean at baseline;
pre-existing untracked material remains user-owned. The broader Windows
userland objective remains incomplete.

## Acceptance and primary contract

1. For direct x87 memory escapes `D8`–`DF`, a noncanonical linear-memory
   reference using the default SS segment raises `#SS(0)`; one using DS,
   ES, FS, GS, or CS raises `#GP(0)`. In 64-bit mode CS/DS/ES/SS override
   prefixes are ignored for this classification. An effective FS/GS override
   on an RSP/RBP-family base selects `#GP(0)`.
2. Check the entire memory operand at its actual width, including the final
   byte of binary80 data and x87 environment/state images. Neither a failed
   load nor a failed store may retire the instruction or commit x87 state.
3. Preserve decoded-invalid `#UD`, device-not-available `#NM`, and pending
   x87 `#MF` checks before operand-memory fault classification. Canonical
   unmapped or permission-denied references retain the existing guest-memory
   fault path.
4. Leave SMIR, native JIT admission, generic ModR/M decoding and memory/MMU
   fault behavior unchanged; this group fixes the direct x87 execution path.
5. Commit this semantic group with exact-path `git add` and
   `red -m --staged --run` on the same paths, without amendment, coauthor or
   Claude session-link metadata. Rebase the completed feature series onto
   current `origin/master`, integrate on `master`, push `origin/master`, and
   verify that remote ref, per the latest user direction.

The primary [Intel Software Developer's Manual, Vol. 1, §3.3.7.1](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf)
specifies `#SS` for default stack references, `#GP` for non-stack references
and effective FS/GS overrides, and says CS/DS/ES/SS overrides are ignored
for this fault classification in 64-bit mode. Its FLDCW instruction entry
specifies `#NM`, `#MF`, `#SS(0)`, `#GP(0)`, and `#PF` conditions. RAX's MMU
implements 48-bit canonical addresses with 4-level paging; this group
retains that project-defined implemented address width.

Pre-fix RED baseline: the focused filter ran five tests. Two failed:
`FLDCW [RBP]` reported `(vector=13, error_code=0)` instead of
`(vector=12, error_code=0)`, and a 2-byte memory operand ending in the
noncanonical hole also reported vector 13 rather than 12. Three controls
passed, including `#NM`/`#MF` priority and canonical unmapped-memory
behavior. These failures precede the source correction.

For a 2-byte operand at `0x0000_7FFF_FFFF_FFFF`, byte 0 is canonical and
byte 1 is `0x0000_8000_0000_0000`, noncanonical under 48-bit paging. For
a 10-byte operand beginning at `0x0000_7FFF_FFFF_FFF8`, the first 8 bytes
are canonical and byte 8 is noncanonical. A width-aware preflight computes
`last = start + (len - 1)` in bytes with checked `u64` arithmetic; with
positive lengths bounded by the x87 operand image, this is O(1) time and
O(1) auxiliary space. The preflight occurs after instruction-form and x87
availability checks but before guest-memory access or architectural commit.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | The direct x87 escape dispatcher is the sole production consumer of the FPU-specific ModR/M address decoder | Repository call-site search | The provenance-bearing FPU decoder result reaches every direct x87 memory form | D8–DF data and control forms; register-only forms remain unchanged | Find a second production caller that bypasses the new provenance result | Confirmed for current source |
| S2 | The existing MMU's 48-bit canonical predicate and IA-32e enable test are the implemented canonicality contract | `src/isa/x86_64/memory.rs` and the project's 4-level paging implementation | The local preflight matches existing MMU address width/mode | Boundary at `0x0000_7FFF_FFFF_FFFF`; compatibility-mode segment base | A supported LA57 mode or a MMU canonical predicate inconsistent with the preflight | Retained |
| S3 | A stack-class default is determined by the encoded memory base, not by a 64-bit-mode CS/DS/ES/SS override prefix | Intel Vol. 1 §3.3.7.1 | `#SS(0)` for `[RBP]` despite DS override and `#GP(0)` for SS:`[RAX]` | Both ignored overrides and effective FS override | A hardware oracle or revised primary specification gives a different fault class | Confirmed by primary contract; direct tests added |

## Change-surface map and bounded findings

Affected planes: direct x87 ModR/M decode, direct x87 data/control memory
execution, and source-level unit tests. The existing CPU state and MMU are
observed but not changed. Direct non-x87 decode/execute, SMIR lift, IR,
interpreter and optimizer, native lowerers/JIT admission, backend adapters,
machine/devices, static oracle, public Rust/C ABI and generated material
are unaffected. The source-level audit document is the only documentation
change. Host-native x86-64 KVM oracle tests cannot execute on this macOS
ARM64 host and are not counted as oracle verification.

| Impact | Evidence and boundary | Blocks this group? |
|---|---|---|
| High | The generic direct ModR/M provenance and MMU translation paths still classify some noncanonical stack references as `#GP(0)`; this change carries provenance only for x87 memory escapes | No; broader direct instruction families require separate call-site and fault-priority audit |
| High | Direct 16-bit-code x87 environment/save format selection uses raw `0x66` presence rather than the effective operand-size attribute; default 14/94-byte and overridden 28/108-byte selection is inverted | No; separate environment-image semantic group, not canonical fault classification |
| High | Complete Windows userland and arbitrary PE execution remain incomplete | No claim of full userland |
| Medium | Host-native x87 oracle execution is unavailable on this ARM64 host | No; direct semantic tests and primary ISA text are available |
| Medium | Simultaneous `REX.W` and `0x66` priority for x87 environment images remains unknown from the consulted instruction-specific text | No; no environment-width selector is changed here; probe the primary encoding rules or independent x86-64 hardware before the separate fix |
| Medium | Relative priority of an unmapped earlier canonical page (`#PF`) and a later noncanonical byte (`#SS`/`#GP`) is not established by this emulator's tests or the consulted fault-order text | No native-equivalence claim for this mixed-fault case; the boundary tests map the canonical portion before the noncanonical byte |
| Low | The unrelated `riscv64/locks --riscv-jit` Linux fixture produced a lock-acquisition timing mismatch under the integration harness's parallel test execution; it passed in isolation and the full target passed with one test thread | No; the changed source is direct x87-only and the deterministic serial gate passed; fixture timing under parallel load remains separate |

## Validation and self-red-team

The focused post-fix filter ran seven tests successfully, including the
previously failing `#SS(0)` cases, REX-extended R12/R13 stack bases, ignored
and effective segment overrides, 2-/10-byte data spans, 14-/28-byte
environment spans, 94-/108-byte saved-state spans, no partial store or x87
state commit, `#NM`/`#MF` priority, canonical unmapped access, and a retained
older x87 regression. The same seven tests passed with
`x86_64-suite,smir-jit` enabled. All executed Cargo gates used stable Rust
and `--locked`; test binaries ran serially as commands, while individual
tests within the library and x86-64 target used the test harness's normal
parallelism.

| Gate | Actual result |
|---|---|
| Portable library, `--no-default-features` | 6,834 passed, 2 explicitly ignored |
| Focused x87 library tests, `x86_64-suite,smir-jit` | 7 passed, 0 ignored |
| x86-64 integration target, `x86_64-suite,smir-jit` | 28,527 passed, 3 explicitly ignored |
| Portable Windows user-mode integration | 528 passed, 0 ignored |
| Portable Linux user-mode integration, serial test threads | 36 passed, 1 explicitly ignored |
| Workspace formatting, `cargo +stable fmt --all --check` | Passed |
| `git diff --check` | Passed |

The registered x86-64 integration target has host-gated KVM oracle tests;
its total is not evidence that those tests executed on macOS ARM64. The
full feature-enabled library suite was not rerun for this direct x87-only
change; the focused feature tests and registered x86-64 target ran. No
public C ABI changed, so the C/C++ ABI consumer test is outside this group.
The first parallel Linux integration run was not green: one RISC-V JIT lock
fixture failed a timing-sensitive busy-lock expectation while 35 tests passed
and one was ignored. The same fixture passed alone (1/1), and the complete
Linux target passed with `--test-threads=1` (36 passed, 1 ignored); the
parallel failure is recorded rather than counted as a pass.

QG1 requires no normative judgment. QG2 is the register above. QG3 is
audited against acceptance criteria 1–4 before commit; criterion 5 is a
postcommit delivery check. QG4 gives hexadecimal boundary arithmetic in
bytes and O(1) preflight complexity. QG5 tests prefix, base-register,
operand-width, exception-priority, and guest-memory frontiers; mixed
earlier-page `#PF` versus later-byte canonicality priority remains the
explicitly bounded unknown above, not an unsubstantiated parity claim.
QG6 uses Intel's primary manual and executable tests. QG7 records adjacent
findings separately and does not mutate them.
