[← Documentation home](../../README.md)

# Capability review — 26 September 2026

This review reconciles maintained capability documentation with the current
implementation, registered tests, and recorded-oracle metadata. It adds Linux
process execution to the project summary, updates the partial i386 ABI,
corrects the x87 representation description, and distinguishes machine,
process, and C-engine interfaces. It changes documentation and CLI help text;
it does not change execution semantics, Cargo features, dependencies, or ABI.

## Scope and worktree provenance

The initial HEAD was `239b6d638c0eab9d8a6ee7c3f06a1684941a9a18`.
During the review, concurrent work committed i386 file/directory
conversions at `27ca1ffdfcc2c4fac984650696976d456b8d70a8`, following the
`72e839c83020864cc262e22d86122acab6e20e3b` reference-source commit.
HEAD subsequently advanced to `2bf21f3f370551fbd8ee92260797aa6d1413e248`
(i386 time reference sources). Concurrent uncommitted work also added i386
time conversions and tests. The review includes that working-tree
implementation [A1]. Validation therefore describes the combined tree, not
an isolated documentation commit. Pre-existing and concurrent source,
reference, binary, and scratch files were preserved.

The owned documentation set is:

- root `README.md`, `src/README.md`, `tests/README.md`, `capi/README.md`,
  and `.github/workflows/README.md`;
- `docs/architecture/overview.md`, `user-mode.md`, `smir.md`, and the Arm,
  x86-64, and RISC-V architecture pages (including scope annotations on the
  RISC-V `STATUS.md` and `REMAINING.md` reports);
- `docs/getting-started/{overview,building,linux-programs}.md`;
- `docs/reference/{status-and-limitations,build-features,command-line,environment-variables,repository-layout}.md`;
- `docs/development/verification.md`, `testing/README.md`, and this report;
- `docs/operations/{observability,checkpoints}.md`;
- `docs/{embedding,troubleshooting,documentation-policy}.md`;
- the two Linux fixture/corpus READMEs under `tests/fixtures/user/linux/`;
- `src/bin/rax_user.rs` module documentation and Clap description strings.

Vendor specifications, binary fixtures, generated corpora, and dated research
results were not regenerated or rewritten [A2]. Existing feature/backend,
machine, device, and C API contracts remain the boundaries for their paths.

## Reconciled capabilities and evidence

| Capability | Primary implementation/test evidence | Documentation consequence |
|---|---|---|
| Linux process execution | [`user::linux`](../../src/user/linux/), [`rax-user`](../../src/bin/rax_user.rs), [`user_linux`](../../tests/suites/user/linux/main.rs) | Present in the root execution matrix, startup guide, build/CLI references, source map, and status page; independent of kernel boot and boards. |
| Three primary 64-bit ABIs | [`LinuxAbi::ALL`](../../src/user/linux/abi/mod.rs), [`GuestCpu`](../../src/user/linux/arch/mod.rs) | Signal, thread, IPC, and ptrace evidence is scoped to x86-64, AArch64, and RV64; “every ABI” no longer silently includes i386. |
| Partial i386 compatibility [A1] | [`compat` dispatcher](../../src/user/linux/syscall/compat/), [`i386 tests`](../../src/user/linux/tests/i386/), [`layout tests`](../../src/user/linux/abi/compat_tests.rs) | ELF32, TLS, mappings, file/path operations, paired offsets, status/statistics, directories, locks, exec vectors, and time32/time64 layouts are described separately from unsupported conversions and absent recorded i386 corpora. |
| User GDT and 32-bit linear addressing | [`user_gdt.rs`](../../src/isa/x86_64/user_gdt.rs), [`linear.rs`](../../src/isa/x86_64/linear.rs), their adjacent tests | CPL-3 selectors, TLS entries, and wrapping after segment-base addition are distinct from the 64-bit syscall path. |
| 64-bit `INT 0x80` boundary | [`dispatch_compat`](../../src/user/linux/syscall/mod.rs), [`x86 Linux adapter`](../../src/user/linux/arch/x86_64.rs) | A 64-bit task's compatibility entry remains `ENOSYS` after seccomp; an ELF32 task's own entry reaches the partial i386 table. |
| Processes, signals, threads, and waits | [`process`](../../src/user/linux/process.rs), [`sched`](../../src/user/linux/sched.rs), [`signal`](../../src/user/linux/signal/), [`child syscalls`](../../src/user/linux/syscall/child.rs) | Guest threads share one emulated CPU per process; forked processes use host processes. This is not VM SMP. Sharing, forwarding, timer, and wait limits remain explicit. |
| Networking, IPC, and inotify | [`net`](../../src/user/linux/net/), [`ipc`](../../src/user/linux/ipc/), [`fsnotify`](../../src/user/linux/fsnotify/), matching library tests and fixtures | Linux and macOS paths are distinguished; the old netlink/interface absence claim is removed. Namespace and external-event limits remain. |
| Guest ptrace and seccomp | [`ptrace`](../../src/user/linux/ptrace/), [`seccomp`](../../src/user/linux/seccomp/), matching syscall/test modules | Guest tracing, syscall editing, process/job-control events, and architecture-specific step support are described without implying a machine GDB server or arbitrary host-process access. |
| AIO, splicing, and memory controls | [`aio`](../../src/user/linux/syscall/aio.rs), [`splice`](../../src/user/linux/syscall/splice.rs), [`mlock`](../../src/user/linux/syscall/mlock.rs), [`mseal`](../../src/user/linux/syscall/mseal.rs), [`rseq`](../../src/user/linux/rseq.rs) | Current subsystem coverage is added to the program guide; host-pipe, scheduler-boundary, and supported-layout limitations are retained. Linux AIO is not an `io_uring` claim. |
| Shared x87 data execution | [`direct x87 wrapper`](../../src/isa/x86_64/execute/fpu/mod.rs), [`SMIR data semantics`](../../src/smir/interpret/x87/data.rs), [`X86X87State`](../../src/smir/ir/context.rs) | Raw 80-bit register storage replaces the obsolete binary64 description. Shared implementations are not independent oracles; transcendental approximations retain their own scope. |
| Public C engine boundary | [`rax.h`](../../capi/include/rax.h), [`C API implementation`](../../capi/src/) | Linux process loading, syscall servicing, scheduling, and ptrace are not exported through the C engine ABI. |
| Test registration and oracle scope | [`Cargo.toml`](../../Cargo.toml), [`CI`](../../.github/workflows/ci.yml), [`full suite`](../../.github/workflows/full-suite.yml), both corpus `expected/ORACLE` files | Both test maps list all 44 declared integration targets, including the formerly omitted AArch32/Thumb AArch64-host JIT targets. Recorded output comparisons and ignored live Docker execution are distinguished. |

The architectural/ABI source inputs are the vendored
[Linux 6.19 kernel sources](../specifications/linux/kernel-6.19.provenance.md),
[Linux 6.19 UAPI](../specifications/linux/uapi-6.19.provenance.md), and
[Intel SDM](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.provenance.md).
The maintained documentation explains implemented repository paths rather
than asserting universal conformance to those specifications.

## Evidence arithmetic and interpretation

The syscall case table contains 56 cases. The runner has five full execution
configurations: x86-64 default/no-JIT, AArch64, and RV64 default/JIT.
Thus `56 cases × 5 configurations = 280 case runs`; two cases on two ISAs
also run with 64-instruction slices, adding `2 × 2 = 4` runs. The morok
table contains 97 programs across five configurations, so
`97 programs × 5 configurations = 485 program runs`.

These are exact inventory counts, not throughput or statistical estimates.
They exclude separate CLI/host-signal tests and the ignored live Docker test.
Neither recorded matrix includes i386. A configuration requesting a JIT can
still interpret an unsupported region or host; no native-admission count was
measured in this review.

The personality's behavior reference is Linux 6.19. The checked-in
[fixture recording](../../tests/fixtures/user/linux/expected/ORACLE) and
[program recording](../../tests/fixtures/user/linux/programs/expected/ORACLE)
identify Linux 7.0.14 OrbStack on AArch64. Architecture/translator overrides
are explicit inputs. Program output uses declared noise filters; the current
known-divergence inventory has zero non-comment entries. That scope is
preserved in the verification and corpus documentation.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | “Updated capabilities” includes the current worktree's compatibility implementation, not only initial HEAD. | Source changes were already present and continued during the review; the task requests current capability documentation. | i386 file/time/layout descriptions and their test paths. | Concurrent changes remove an admitted conversion, change its rejection, or invalidate a test path. | Re-read `src/user/linux/syscall/compat/`, inspect `git status`, and run the `user::` library tests before delivery. | Retained; source snapshot and all 549 `user::` tests, including seven i386 time tests, checked. |
| A2 | Associated documents means maintained user/developer references; imported specifications and recorded historical results retain their provenance. | Root documentation ownership policy and the repository's reference/generated-material rules. | Scope annotations and current cross-links instead of regenerated corpora or rewritten historical results. | An archived report is mistaken for present exhaustive conformance or Linux syscall coverage. | Search tracked Markdown for old claims; require current-scope annotations and links on affected historical summaries. | Retained; current and historical scopes are explicit. |

## Change-surface map

| Plane | Status for this change |
|---|---|
| Direct decode / execute | No semantic edits; current x87, user-GDT, compatibility, and address-wrap behavior informs documentation. |
| CPU state / memory-MMU | No state or memory implementation edits; register widths, VMAs, faults, and process sharing limits are documented. |
| SMIR lift / IR / interpreter / optimizer | No implementation edits; shared x87 semantics and comparison independence are clarified. |
| Native lowering / JIT runtime | No admission changes; host gates, compatibility interpretation, fork invalidation, and fallback evidence are qualified. |
| Backend / machine-device | No implementation edits; guest-process scheduling is explicitly separate from VM SMP and hardware backends. |
| Oracle-analysis / C ABI | No API or layout changes; recorded-output and C-engine scopes are clarified. |
| Tests-docs / CLI metadata | Maintained pages, test maps, and `rax-user` help text updated; fixture/test code is preserved. |

## Validation

Host: macOS on AArch64. Toolchain: `rustc 1.98.1`, `cargo 1.98.1` (`+stable`).
Commands use `--locked`, `--no-default-features`, and `smir-jit`; they
validate the shared working tree [A1]. The integration run used the release
profile. Library checks use the dev profile, as the CI unit lane does.

| Check | Observed result |
|---|---|
| Complete `user_linux`, serial Rust test execution | 34 passed, 0 failed, 1 ignored, 0 filtered; 54.59 s. The ignored case is the opt-in live Docker oracle. |
| `user::` library tests, serial dev profile | 549 passed, 0 failed, 0 ignored, 7,787 filtered out; 4.80 s. The filter selects the entire `user::` subsystem. Includes seven i386 time-conversion tests. Compilation took 1 min 23 s. |
| `rax-user` build, help, and checked-in `hello` | Dev-profile build passed (33.42 s). Long and short help include partial i386; all 14 documented options matched compiled help. x86-64/AArch64/RV64 `hello` exited 41; AArch64 with `arg1 arg2` exited 43, as `40 + argc` specifies. |
| Relative paths/heading anchors and test-target registry | 229 relative links in 31 owned Markdown files passed path/heading checks. All 44 declared target source paths existed and both target maps contained them. |
| Owned-source formatting and whitespace | `rustfmt +stable --edition 2024 --check src/bin/rax_user.rs` and scoped `git diff --check` passed. |

The executed Cargo checks were:

```sh
cargo +stable test --release --locked --no-default-features --features smir-jit \
    --test user_linux -- --test-threads=1
cargo +stable test --locked --no-default-features --features smir-jit \
    --lib user:: -- --test-threads=1
cargo +stable build --locked --no-default-features --features smir-jit --bin rax-user
```

The initial release-profile library compilation was stopped before test
execution after prolonged fat-LTO optimization; it supplied no test result.
The replacement dev-profile build includes the concurrent time-conversion
work. The earlier integration run predates those edits and does not establish
i386 time-conversion execution; its recorded matrices remain 64-bit only.

The live Docker oracle, KVM, HVF, independent x86 hardware comparison,
whole-machine boot, and C ABI consumer tests were not rerun: their execution
contracts are unchanged, and this change adds no claims that those paths ran
on this host. Broad generated ISA suites are not required for a capability
documentation update. Complete cross-platform runtime conformance remains
unknown; the falsification probe is the relevant host-native CI/test target
with its actual oracle prerequisites and skip counts recorded.

## Bounded findings

| Impact | Finding and evidence | Blocks this documentation update? |
|---|---|---|
| High | External truncation of an already touched shared file mapping can fault the emulator rather than deliver guest `SIGBUS`; the existing [user-mode qualifications](../reference/status-and-limitations.md#required-user-mode-qualifications) record this execution limitation. | No; the limitation remains documented and no memory implementation was changed. |
| Medium | i386 has explicit conversions but no recorded whole-program matrix and lacks major signal/thread/socket/ptrace conversions; the dispatcher and corpus architecture arrays demonstrate the boundary. | No; it is labeled partial and its unit evidence is separate. |
| Medium | Output/exit-status agreement and internal shared-x87 comparisons leave unobserved state or correlated implementations; UTF-8 lossy decoding can equate different invalid-byte outputs, and program filters can mask output. Runners, filters, overrides, and shared helpers are named above. | No; the textual-output projection is stated and no formal or universal conformance claim is added. |
| Low | The C API, machine debugger, and guest ptrace are distinct integration surfaces for binary-analysis tooling. Combining them would require a separately scoped interface design. | No; this review updates their documented boundaries only. |

## Acceptance and quality-gate review

| Requested result | Evidence |
|---|---|
| Review updated capabilities | Source/test inventory above reconciles Linux process execution, compatibility mode, shared x87 semantics, and public-interface boundaries. |
| Update the root README | Execution summary, runnable-path matrix, documentation map, test command, and limitations include the process path. |
| Update associated documents | The owned set covers startup/build, architecture/status, CLI/environment, source/test maps, corpus evidence, observability/checkpoints, and embedding. Historical ISA reports carry current-scope annotations. |
| Preserve unrelated work | Edits are confined to the named documentation set and CLI metadata; concurrent implementation and references remain user-owned. |

| Gate | Result and scope |
|---|---|
| QG1 — No normative content required | Pass: implementation, evidence, and interface boundaries are described without ethical judgments. |
| QG2 — Assumptions and stress tests | Pass: A1/A2 include dependencies, stress cases, and concrete falsification probes; runtime results are attributed to the shared tree. |
| QG3 — Requirement coverage | Pass: root summary and affected maintained documents are reconciled; the acceptance table identifies coverage. |
| QG4 — Units and calculations | Pass: widths, byte layouts, hexadecimal fields/addresses, seconds, and exact case/configuration arithmetic are explicit. No throughput estimate is inferred. |
| QG5 — Contradictions and edge cases | Pass for documentation scope: 64-bit/i386, process/machine, C-engine/personality, interpreter/native, and current/historical boundaries are explicit. Runtime limitations remain recorded rather than removed. |
| QG6 — Provenance | Pass: claims link to owning source/tests, Cargo/workflows, Linux/Intel provenance, and actual recording metadata. Passed/ignored/filtered execution is distinguished. |
| QG7 — Bounded expansion | Pass: the findings table records impact and blocking status; unrelated implementations, corpora, references, and dependencies are preserved. |
