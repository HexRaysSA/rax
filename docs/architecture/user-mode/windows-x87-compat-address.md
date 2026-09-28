# x87 compatibility-mode disp32 addressing

Semantic group against `3719cef35a19642570718ae7c3d5e040da2ee11d`
on `user-win`. The tracked worktree and index were clean at baseline; all
pre-existing untracked material remains user-owned. The broader Windows
userland objective remains incomplete.

## Acceptance and primary contract

1. For x87 memory escapes D8–DF with ModR/M `mod=00, r/m=101`, decode the
   32-bit displacement as an absolute offset in compatibility mode
   (`CS.L=0`), then apply address-size truncation and the selected segment
   base. Keep 64-bit-mode (`CS.L=1`) RIP-relative interpretation even with
   a `0x67` address-size override.
2. Preserve SIB `mod=00, base=101, index=100` no-base absolute encoding and
   16-bit ModR/M address forms. Test negative `disp32`, default DS and an
   explicit segment override.
3. Establish actual `FLDCW m16` read and `FNSTCW m16` write targets, plus
   a fault when the absolute target is unmapped but a RIP-relative decoy is
   mapped. The faulting instruction must not retire or commit x87 state.
4. Preserve current long-mode SMIR behavior: the x86-64 lifter has no
   compatibility-mode input and must not be changed to absolute addressing.
5. Commit only this semantic group using exact-path `git add` followed by
   `red -m --staged --run` on the same paths, without amendment, coauthor or
   Claude session-link metadata; push directly to `origin` and verify the
   remote ref.

Intel's primary [Software Developer's Manual, Vol. 2, §2.2.1.6,
Table 2-7](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf)
sets compatibility `mod=00/rm=101` to `Disp32` and 64-bit mode to
`RIP+Disp32`. It states that `0x67` in 64-bit mode truncates the computed
RIP-relative effective address to 32 bits, rather than selecting an absolute
form. The neighboring generic ModR/M decoder already branches on `CS.L`;
the FPU helper previously did not.

Pre-fix red baseline, using the same seven focused tests later retained:
five compatibility cases failed and the two long-mode/SIB controls passed.
For example, `FLDCW` loaded the mapped RIP-relative decoy control word
`0x037F` rather than the architecturally selected absolute operand
`0x027F`; the absolute-target fault case instead accessed its mapped decoy.
These failures precede the decoder correction and are not counted as
postcondition passes.

For `D9 2D 00 20 00 00` at `0x1000`, the six-byte instruction ends at
`0x1006`. Compatibility mode selects `0x0000_2000`; 64-bit mode selects
`0x1006 + 0x2000 = 0x3006`. With `0x67`, the seven-byte instruction at
`0x1_0000_1000` computes `0x1_0000_1007 + 0x2000 = 0x1_0000_3007`
and then truncates the 32-bit effective offset to `0x3007` before the
segment-base step. A negative `disp32` such as `0xFFFF_FFFC` becomes the
32-bit absolute offset `0xFFFF_FFFC` in compatibility mode. Arithmetic is
wrapping at the architectural effective-address width; decoding uses O(1)
time and O(1) auxiliary space.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| X1 | The direct FPU escape dispatcher is the only production caller of `decode_fpu_modrm_addr` | Repository call-site search | The one-branch helper fix covers direct x87 D8–DF memory forms | FLDCW and FNSTCW; other escape rows retain decoder helper | A second production caller bypasses the helper or requires different mode semantics | Confirmed for current source |
| X2 | `CS.L` in the direct CPU is the architectural 64-bit versus compatibility-mode selector | Intel Table 2-7 and neighboring generic decoder | Mode gate in FPU ModR/M helper | `CS.L=0` with `CS.DB=1`; `CS.L=0,CS.DB=0` with `0x67`; `CS.L=1` with `0x67` | An execution mode with `CS.L=0` is required to use RIP-relative data addressing | Confirmed |
| X3 | The current SMIR x86-64 lifter accepts long-mode machine code only, without a compatibility-mode input | Lifter interface and existing decode behavior | No SMIR edit for this direct compatibility fix | Compare long-mode `0x67` against direct decoder | A supported SMIR caller supplies compatibility-mode state and expects absolute disp32 | Retained; no such caller found |

## Change-surface map and bounded findings

Direct x86-64 FPU ModR/M address decode is affected. Direct execution,
segment-base application, x87 control-word state and memory fault reporting
observe the corrected address without changing their interfaces. CPU state
layout, MMU algorithm, non-x87 decode, SMIR lift/IR/interpreter/optimizer,
native lowerers/JIT admission, backends, machine/devices, oracle output and
public Rust/C ABI are unchanged. The source-specific unit tests and this
audit are the only planned artifacts. The registered x86-64-host KVM x87
oracle corpus is target-gated and cannot execute on this macOS ARM64 host;
its green compilation, if any, is not counted as oracle execution.

| Impact | Evidence and boundary | Blocks this group? |
|---|---|---|
| High | The same FPU helper returns only a linear address, losing default-SS provenance before noncanonical-address fault classification; [Intel Vol. 1 §3.3.7.1](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf) specifies `#SS(0)` for stack references rather than `#GP(0)`, and 64-bit CS/DS/ES/SS overrides do not change that classification | No; separate width-aware fault-class contract and API propagation, not the `mod=00/rm=101` offset decision |
| High | Direct 16-bit-code x87 ENV/FSAVE format selection passes raw `0x66` presence to `x87_form`, inverting the 14/94-byte default and 28/108-byte override layouts required by [Intel Vol. 1 §3.6 Table 3-3 and §8.1.10](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf) | No; separate x87 operand-size attribute contract, not address selection |
| High | Full Windows userland, language/runtime personality and arbitrary PE support remain incomplete | No claim of full userland |
| Medium | Host-native x87 compatibility oracle cannot run on this ARM64 host | No; focused direct tests and source/primary-standard comparison are available |
| Medium | The instruction-specific effect of simultaneous `REX.W` and `0x66` on x87 environment images remains unknown from the consulted primary text | No; no environment-image selector is changed here; probe primary encoding rules or an independent x86-64 hardware oracle before that separate fix |

## Validation and self-red-team

Focused source/test freeze: the seven red-baseline cases now pass, covering
both x87 read/write operations, three mode/address-size combinations,
SIB control, default and overridden segment bases, and unmapped-target
fault behavior. The same seven cases pass under the feature-enabled build.
All executed Cargo gates used stable Rust and `--locked`; test binaries ran
serially. The final-layout receipts are:

| Gate | Actual result |
|---|---|
| Portable library, `--no-default-features` | 6,828 passed, 2 explicitly ignored |
| Focused x87 library tests, `x86_64-suite,smir-jit` | 7 passed, 0 ignored |
| x86-64 integration target, `x86_64-suite,smir-jit` | 28,527 passed, 3 explicitly ignored |
| Portable Linux user-mode integration | 36 passed, 1 explicitly ignored |
| Portable Windows user-mode integration | 528 passed, 0 ignored |
| Feature-enabled Windows user-mode integration | 528 passed, 0 ignored |
| Portable and feature-enabled workspace all-target builds | Both passed; known engine/C API `librax.rlib` output-name collision warning |
| Feature-enabled and default-feature workspace all-target Clippy | Both passed; repository lint tables allow warnings |
| Workspace formatting | Passed |

The x86-64 integration test count is not evidence that Linux x86-64 KVM
oracle cases executed on this macOS ARM64 host. The full feature-enabled
library corpus was not rerun for this one-branch direct-address change; its
focused x87 tests and all-target compilation were executed. No public C ABI
was changed, so the C/C++ ABI consumer test is outside this group.

QG1
requires no normative judgment. QG2 is the register above. QG3 is audited
against acceptance criteria 1–4 before commit; criterion 5 is a postcommit
delivery check. QG4 has explicit 6-/7-byte instruction lengths, 32-bit
offset truncation, hexadecimal arithmetic and O(1) complexity above. QG5
tests mode, prefix, SIB, segment and memory/fault frontiers; the separate SS
fault-class issue is classified rather than silently conflated. QG6 uses
Intel's primary manual and executable source/tests. QG7 records the bounded
findings without unrelated mutation.
