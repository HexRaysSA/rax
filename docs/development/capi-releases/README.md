# C API binary-release engineering record

Scope: native shared/static packaging and tag-triggered releases. Baseline:
`072c63a2472e8118cf48ebb973d73ccbecd94d9a`. Existing untracked content is not
owned by this change. See `capi/README.md` for the distribution contract.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | Release tags use `v<package-version>` | Conventional tag form; user did not prescribe one | Tag trigger and version guard | Prerelease, malformed tag, version mismatch | `python3 -m unittest discover -s tools/capi -p 'test_*.py' -v` | Retained; explicit contract |
| A2 | Initial SDKs use the C API's default interpreter feature set | `capi/Cargo.toml` defaults are empty | Five-platform release matrix | Host/guest ISA differ; optional JIT excluded | Inspect build metadata and release Cargo commands; run native consumers | Confirmed for configured feature set |
| A3 | SDK relocation must work without original build paths | Binary distribution can be extracted anywhere | Install names, CMake/pkg-config paths | Prefix containing spaces; original libraries hidden | `tools/capi/package.py` relocates and executes linked consumers | Enforced by every release lane |

## Change-surface map

C ABI packaging, linker identities, consumer tests, build tooling and workflow
documentation are affected. The exported C ABI layout, enum numbering, panic
containment and ownership contract are unchanged. Direct decode/execute, CPU
state, memory/MMU, SMIR lift/IR/interpreter/optimizer/lowerers/JIT runtime,
backend adapters, machine/devices and oracle semantics are unaffected: no edits
are made to those planes. JIT admission is not expanded by interpreter releases.

## Bounded findings

- High: x86-64-v3 development flags are unsuitable for an unqualified baseline
  x86-64 SDK. Release tooling explicitly overrides them; developer builds keep
  the existing setting.
- High: installed CMake paths and macOS install names previously referenced
  absent/build-local paths. Relocated consumer execution is the regression gate.
- Medium: Windows core CI comments contradicted the patched dependency graph.
  Documentation is corrected; Windows C API is covered separately from the full
  ISA/JIT suite. GNU/MinGW packaging is distinct from MSVC release artifacts.
- Medium: minimum OS/CRT compatibility cannot be established solely by linking.
  Build/runtime hosts and ELF version requirements are recorded; older runtimes
  and optional native backends remain outside this release certification.

## Primary tooling sources

Retrieved 2026-09-09; copies and SHA-256 provenance are in `references/`.

- Rust Project, *Cargo Book — Build Scripts*: `rustc-link-arg-cdylib` controls
  native shared-library linker arguments without changing static archive linkage.
- Kitware, *CMakePackageConfigHelpers*: `PATH_VARS` generates relocatable
  `PACKAGE_*` install paths.
- Kitware, *IMPORTED_IMPLIB*: Windows imported shared targets require the import
  library in addition to the DLL location.
- GitHub, *Workflow syntax for GitHub Actions*: tag filtering, job dependencies,
  permissions and matrix semantics govern the release workflow.

Source URLs, retrieval date, live revision description and content hashes are
recorded in `references/sources.json`. No architectural semantics are inferred
from these packaging sources.

## Local validation (2026-09-09)

- The pre-change generated CMake package fails the new consumer configuration:
  `Installed SDK is missing rax::rax`.
- Stable Rust 1.98.1, aarch64-apple-darwin: 56 C API tests passed with no
  ignored/filtered cases; four relocated C/C++ consumer tests passed; both
  pkg-config shared/static consumers passed. The original Cargo release
  directory was hidden during consumer execution.
- `make -C capi test` passed all eight examples and the strict C11 ABI compile.
- Windows GNU cross-build: CMake installed the DLL, import library and static
  archive; all four C/C++ consumers and the strict ABI source compiled/linked.
  These Windows executables were not run locally.
- Seven `ci_actions_pinned` tests passed. Five release-helper tests passed,
  including mismatched tags, missing/corrupt assets, upload failure, resuming a
  draft, and refusing to modify a published release. Actionlint, Rust formatting
  and whitespace checks passed.
- CMake rejected the invalid shared=OFF/static=OFF configuration. Custom lib64
  metadata retained relative prefix/include/library paths.
- Linux and native MSVC runtime validation are enforced by the new matrix but
  have not run from this workspace. No tag, commit, push or GitHub release was
  created during implementation.

SHA-256 processing is linear in total artifact bytes and uses bounded streaming
memory per file; the filename inventory is linear in SDK file count.
