[← Documentation home](../README.md)

# Documentation policy

This page defines how the rax documentation is organized and what a technical claim must communicate. It exists to prevent the root README from becoming another capability ledger and to prevent detailed pages from turning test observations into universal guarantees.

## One entry point

The repository root [`README.md`](../README.md) is the only complete documentation index.

- Do not add `docs/README.md` or another full table of contents.
- Every maintained page below `docs/` begins with a link to the root README.
- A detailed page may link to related pages, source, tests, or specifications, but it should not reproduce the entire documentation map.
- The root README owns project identity, the first runnable command, the execution-path summary, the documentation map, and the top-level boundaries.
- Breakout pages own the detail required to build, operate, verify, modify, or embed one subsystem.

This arrangement gives a new reader one reliable starting point while allowing the technical detail to remain exhaustive.

## Claim classes

Use these terms deliberately:

| Label | Meaning |
|---|---|
| **Implemented** | Current source contains the path or behavior. This does not by itself say that the path was executed in the current environment. |
| **Unit-tested** | A repository test directly exercises the behavior without an external reference. |
| **Differential-tested** | A harness compares selected state with another engine or host CPU for the cases that execute. |
| **Inventory-checked** | Generated or handwritten tests assert coverage over a source/specification corpus. This does not prove semantic correctness. |
| **Boot-demonstrated** | A machine or integration test reaches a named boot milestone with a named image/configuration. |
| **Benchmarked** | A measurement was obtained under stated host, compiler, feature, workload, and run conditions. |
| **Advertised** | The claim appears in project prose but has not been independently reconciled with the current public interface or source for this documentation update. |
| **Unsupported** | The behavior is absent, intentionally excluded, or not yet demonstrated. |
| **Unknown** | Available evidence is insufficient. State the probe that would resolve it. |

Avoid `verified`, `proven`, `complete`, `full`, `every`, `bit-identical`, or `zero divergence` without an immediately stated scope. For example:

> The generated AArch64 register-state sweep reported no differences for the encodings and input states executed by the harness.

is defensible. This is not:

> AArch64 is proven correct.

## Truth hierarchy

When sources disagree, do not silently select the most convenient statement. Use this order:

1. The relevant architecture specification defines architectural behavior.
2. Build configuration and executable behavior define repository interfaces.
3. Current source and executable tests define implementation state.
4. Current CI workflows define what automation actually attempts.
5. Maintained documentation explains those facts.
6. Historical reports, issue prose, comments, and names are supporting context only.

Repository-specific consequences:

- `Cargo.toml` owns Cargo feature names and integration-test target names.
- `src/cli/mod.rs` owns public command-line options.
- `src/config/` owns configuration fields, defaults, detection, and precedence.
- `src/README.md` owns canonical source-directory responsibility.
- `tests/README.md` owns test-tree responsibility and target-to-source mapping.
- `.github/workflows/` owns the current CI command matrix.
- Source is authoritative over a dated SMIR design document when they diverge.
- A successful command is not evidence that a self-gating oracle ran; inspect test counts and skip output.

## Stable and volatile documentation

Stable pages explain boundaries and mechanisms:

- architecture ownership;
- boot flow;
- configuration precedence;
- state compared by a differential harness;
- how a JIT region is admitted or rejected;
- checkpoint semantics;
- thread-safety and ABI contracts.

Volatile pages record changing inventory:

- instruction families;
- generated corpus sizes;
- native-JIT operation coverage;
- machine boot milestones;
- known missing instructions or devices.

Keep volatile claims in their architecture, validation, or status page. Do not duplicate them in the root README, `AGENTS.md`, source comments, and several overview pages.

## Required qualifiers for evidence

A differential-test claim should identify:

1. the rax execution path;
2. the reference path;
3. the initial-state construction;
4. the state compared;
5. excluded or masked state;
6. host/tool prerequisites;
7. self-skip behavior;
8. the granularity: one instruction, short sequence, region, or whole-machine milestone.

A benchmark should identify:

1. repository commit;
2. host CPU and operating system;
3. Rust/toolchain version;
4. Cargo features and `RUSTFLAGS`;
5. guest workload and input size;
6. warm-up and run count;
7. distribution or variance, not only the best result;
8. whether the number is interpreter, JIT, KVM, or end-to-end throughput.

A support claim should distinguish:

- decoded;
- executed by the direct interpreter;
- lifted to SMIR;
- interpreted through SMIR;
- lowered natively on x86-64;
- lowered natively on AArch64;
- wired into a runnable machine;
- covered by a differential or generated test.

## Updating documentation with code

When a change affects public behavior:

1. Update the implementation and tests first.
2. Update the owning detailed page.
3. Update the root summary only when the project-level execution path or boundary changed.
4. Update the validation matrix when the reference, compared state, prerequisite, or test target changed.
5. Run a relative-link check.
6. Search for the old term or claim across `README.md`, `docs/`, `src/README.md`, `tests/README.md`, `capi/README.md`, and `AGENTS.md`.
7. Record unresolved conflicts explicitly rather than harmonizing prose around an assumption.

## Known conflict format

Use a compact block:

> **Documentation conflict (resolved in the September 2026 review):** The Linux-program guide listed `AF_NETLINK` as unsupported, while the socket dispatch and dedicated tests already implemented it. The corrected guide distinguishes Linux host sockets from macOS `NETLINK_ROUTE` emulation and retains the latter's route/notification limits. A shared family name is not evidence of identical host coverage.

A conflict is useful documentation. Hiding it is not.
