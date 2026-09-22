# C API release-platform expansion

Baseline: `4c4509e758dda748be1a95bd3089c2a6aab6afe1`, with the task's uncommitted
changes applied. Initial local validation date: 2026-09-10. At the completion
of that local validation, no commit, push, workflow dispatch, tag, or release
publication had been performed. Remote CI validation follows separately.

## Acceptance criteria and implementation

- Register twelve SDK targets: the existing five mandatory targets and seven
  experimental candidates. `tools/capi/targets.py` owns target configuration;
  the workflow/registry conformance test checks the matrix.
- Build the four new GNU/Linux targets with target GCC/G++ and Rust std; execute
  Rust tests, CTest consumers, and pkg-config executables through the same QEMU
  command and target sysroot. Debian cross jobs run on x86-64 runners because
  the big-endian PowerPC64 compiler package is not supplied for an ARM64 build
  host. Local RISC-V, PPC64LE and s390x validation used an ARM64 Debian build host.
- Build both musl targets in native Rust/Alpine containers, with dynamic musl
  CRT linkage so Cargo can produce both `cdylib` and `staticlib` outputs.
- Build Windows ARM64 with a native Rust host and CMake ARM64 generator platform.
- Require nonempty, unfiltered, unignored Rust test execution. Relocate the SDK
  into a path containing spaces, hide the original Cargo output during consumer
  execution, and restore that output even when consumer testing fails.
- Publish only after the mandatory artifact set is complete. Optional candidates
  must be absent or complete and checksum-valid; partial/corrupt candidates fail
  publication. Cancellation prevents publication. PR/dispatch runs do not publish.
- Preserve scalar values in the C++ wrapper on big-endian hosts while retaining
  the C API's existing little-endian raw register representation. No C layout,
  symbol, enum identifier, or guest ISA behavior changes.

## Change-surface map

| Plane | Status and reason |
|---|---|
| Direct decode and execute | Unaffected: no instruction implementation changes |
| CPU state and memory/MMU | Unaffected: no architectural state or memory contract changes |
| SMIR lift, IR, interpreter and optimizer | Unaffected: interpreter features remain the existing release default |
| Native lowering and JIT runtime | Unaffected: no JIT feature or host admission is added |
| Backend and machine/device | Unaffected: no backend/device implementation changes |
| Oracle/analysis | Unaffected: its existing ABI/layout checks remain in the SDK consumer build |
| C ABI and C++ wrapper | C ABI unchanged; C++ scalar representation corrected for host byte order |
| Tests/docs/tooling | Affected: platform registry, build/test routing, publication policy, provenance and consumer coverage |

Scalar conversion is O(w) time for a w-byte type. Reads reverse bytes in place
with O(1) auxiliary space; writes use an O(w)-byte temporary. Aggregate arguments
retain their raw byte representation. The existing precondition that the type
matches the register's natural byte width remains in force.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | The existing interpreter-only release feature set remains the requested product | Existing C API manifest/release contract and accepted expansion proposal | All new target builds | Accidental JIT/KVM/HVF feature activation | Inspect Cargo feature graph and build commands for new engine features | Confirmed by unchanged manifests and explicit package build commands |
| A2 | New targets may initially be experimental and may be absent from a release when qualification fails | Accepted expansion proposal | Optional-asset publication policy | Missing mandatory archive; partial/corrupt candidate; failed upload | Negative packaging/publication tests must reject each invalid case | Retained; negative tests pass |
| A3 | QEMU user-space execution is sufficient for initial experimental SDK qualification | New GNU/Linux targets have no native hosted runner in this workflow | Candidate runtime evidence | Host page-size, CPU-feature, floating-point, ABI and kernel differences on physical hardware | Run the same SDK consumers on physical target hardware and compare results | Retained; physical hardware remains untested |
| A4 | The Windows ARM64 runner provides compatible native Rust/MSVC tooling | Archived GitHub runner inventory and explicit native-host/generator selection | Windows ARM64 candidate | Runner image migration or an x86-64 toolchain selected accidentally | `rustc -vV` host mismatch or any SDK build/consumer failure rejects the lane | Retained; Windows SDK execution is untested locally |

## Regression evidence

- A minimal C++ scalar-read/write probe linked to fixed little-endian C ABI
  fixtures failed on s390x under QEMU before the wrapper correction:
  `FAIL: scalar read endian`. The same probe passed afterward.
- The original s390x Rust suite ran 56 tests: 55 passed and
  `register_widths_and_subregisters` failed. The fixture supplied host-endian
  `0x11223344` bytes, yielding `0x44332211`. Encoding the fixture with
  `to_le_bytes()` restored the C ABI contract; all 56 tests then passed.
  Exactly 32 bits / (8 bits per byte) = 4 bytes: `0x11223344` has little-endian
  bytes `44 33 22 11`; the big-endian native bytes `11 22 33 44` instead decode
  as `0x44332211` under the raw API. No rounding or truncation is involved.
- The new `cpp_registers.cpp` consumer compares 8/16/32/64-bit scalar access
  against raw little-endian bytes and the integer convenience API. It covers
  signed integers, enums, a 16-byte vector buffer, and bit-preserving float/double
  transfers including signed zero, subnormal/normal boundaries, infinities, and
  quiet/signaling NaN payloads. It executes with both shared and static linkage.

## Validation

Rust toolchain: `rustc 1.98.1 (48a229cea 2026-09-01)`. Linux builds use the
manifest-digest-pinned official Rust images in the workflow. The local host is
Apple Silicon; x86-64 container runs use host translation and are not evidence
of execution on physical x86-64 hardware. Local container network access used
a temporary host proxy; it is not part of the workflow or SDK.

| Check | Result |
|---|---|
| Packaging/publication/routing tests | 15 passed, 0 skipped |
| Workflow policy (`ci_actions_pinned`, release, no default features) | 7 passed, 0 ignored/filtered |
| `actionlint`, `shellcheck`, `cargo +stable fmt --all --check`, `git diff --check` | Passed |
| Produced local archives / primary reference snapshots | External and internal archive checksums passed for 6 archives; all reference checksums passed |
| macOS AArch64 SDK | 56 Rust tests passed; 6 relocated consumers passed; shared/static pkg-config consumers passed |
| Linux AArch64 musl SDK | 56 Rust tests passed; 6 relocated consumers passed; shared/static pkg-config consumers passed |
| Linux RISC-V GNU SDK | 56 Rust tests passed; 6 relocated consumers passed; shared/static pkg-config consumers passed |
| Linux PPC64LE GNU SDK | 56 Rust tests passed; 6 relocated consumers passed; shared/static pkg-config consumers passed |
| Linux s390x GNU SDK validation | 56 Rust tests passed; 6 relocated consumers passed; shared/static pkg-config consumers passed; validation resumed from the built SDK after correcting the fixture |
| Linux PPC64 GNU SDK | 56 Rust tests passed; 6 relocated consumers passed; shared/static pkg-config consumers passed |
| Linux x86-64 musl SDK | 56 Rust tests passed; 6 relocated consumers passed; shared/static pkg-config consumers passed |
| `make -C capi test` | 9 examples and the C ABI compile check passed; example/test output directories redirected to task-owned temporary directories to preserve pre-existing binaries |
| Windows ARM64 | Lane implemented; no local Windows execution environment |

Final C++ consumer checks were repeated after adding FP bit-pattern and enum
coverage. No Rust source restructuring, engine semantic change, new Cargo test
binary, dependency update, or default-feature change is involved. Full guest-ISA,
JIT, KVM and HVF suites were not run because those execution planes are unchanged.

## Bounded findings

Remote CI at `79c4d4470831ae2ab31da08a1cb5cae50001e9c6` exposed a
portability defect in the newly merged upstream ARM64 fault-retry test:
`arm64_faultin.rs` allocated its C error-message buffer as `i8`, while the
s390x and PPC64 target signatures require unsigned `c_char`. Both SDK jobs
failed with Rust E0308 before test execution. The buffer now uses
`std::ffi::c_char`, matching both `rax_engine_errmsg` and `CStr::from_ptr`.
This changes only the test fixture; its assertions and engine behavior remain
unchanged. The platform SDK lanes provide the cross-target falsification probe.

| Impact | Finding and evidence | Task effect |
|---|---|---|
| High | Pre-existing `rax_reg_read_u64` in `capi/src/reg.rs` calls `rax_reg_read` with an 8-byte buffer before checking whether the register width exceeds 8 bytes. The latter copies the natural register width. Passing an XMM register therefore exceeds that buffer before the later rejection. This is source-level evidence; no overflow execution was attempted. | Separate API defect, unchanged here. Valid scalar-register callers used by SDK tests do not trigger it; no new target qualification relies on wide-register use of this helper. |
| Medium | QEMU user-space tests do not establish physical target CPU/kernel behavior, including host page-size differences. | Candidates remain experimental; not a blocker for the explicitly described evidence. |
| Medium | 32-bit targets remain blocked by the pinned `vm-memory` compile-time 64-bit requirement. | Outside this expansion; no dependency fork or feature extraction attempted. |
| Low | Candidate promotion remains a deliberate registry/workflow change rather than automatic after one successful run. | Prevents the mandatory artifact contract from changing implicitly. |

## Worktree and source provenance

The staged whitespace check excludes the verbatim `references/` snapshots:
upstream CMake/Debian HTML contains trailing whitespace and the GitHub inventory
has a final blank line. Their original bytes and recorded hashes are preserved
under the repository reference-material contract. All authored changes pass
`git diff --cached --check -- . ":!docs/development/capi-platforms/references"`.


Owned changes are confined to `.github/workflows/{capi-release.yml,README.md}`,
`tools/capi/`, the C API README/header/test/consumer/example files, and this
report/reference directory. The pre-existing modified AVX10 PDF and all
unrelated untracked content remain untouched. Existing ignored C API example
binaries and the ABI object were preserved by redirecting Make's output paths.

Primary tooling documents are preserved under `references/`; `provenance.json`
records issuing organization, source URL, retrieval date, revision limitations,
and SHA-256 digest. C API byte-order provenance is `capi/include/rax.h`'s register
contract and `capi/src/reg.rs`; no ISA semantics were inferred from a test result.
