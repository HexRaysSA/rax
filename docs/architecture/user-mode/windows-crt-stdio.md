# Windows CRT streams and descriptor implementation record

## Scope and acceptance criteria

Baseline: `9b73397628567e675f129ecf38896ee50f601576`, branch `user-win`.
The pre-change executable is `/tmp/rax-crt-stdio-baseline.rGYJRh/rax-user`,
SHA-256 `55a60784315e0e7eff45b5ba4b793f1f225424bb7583f1c95653135a70e89b93`.
No tracked/index changes existed before this group. Unrelated untracked
content remains user-owned. Final validation results are recorded below.

The requested end state remains complete Windows userland emulation for x86,
x64 and ARM64. This group implements a prerequisite, not that end state:
real CRT stream storage, descriptor ownership, buffering and bounded byte I/O.
Ordinary compiler-generated startup and termination must subsequently be
executed and verified; custom-entry fixtures do not establish that closure.

Acceptance criteria:

1. Admit only actual DLL exports, preserving legacy architecture-specific
   aliases and DATA versus function distinctions.
2. Transactionally establish separate MSVCRT/UCRT standard streams, mode
   cells and descriptor tables before DLL publication. Roll back unpublished
   storage and object references on failure.
3. Distinguish descriptor integers from HANDLEs and FILE pointers; retain
   exact object identity and granted access until documented close ownership
   is discharged. A successful descriptor-to-stream association transfers
   descriptor ownership, without creating or truncating the file.
4. Implement actual caller buffers and owned automatic buffers, flush pending
   output, retain documented read buffers on `fflush`, and never free caller
   buffers. Stream flags are sticky until clear or close.
5. Process byte I/O in bounded chunks with checked guest access before host
   effects, explicit partial progress, and captured continuations on faults.
   Do not replay completed host effects after guest fault repair.
6. Derive ANSI text/binary behavior from the retained contracts; do not
   misrepresent Unicode translation, pipes or overlapped I/O as implemented.
7. Verify all three guest ABIs, exact final fixture bytes against baseline,
   registered integration tests, loader rollback and resource lifetime.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | Initial stdin/stdout buffers use 4096 B, stderr is unbuffered; UCRT FILE shell stride is pointer size. These are explicit private profiles, not measured native layouts. | Public fread default-size contract; UCRT header exposes only an opaque placeholder; native Windows oracle unknown. | Private storage and fixture access restricted to documented accessors. | Three ABIs, caller buffers, allocation exhaustion, repeated accessors. | Compare with an identified native CRT build; test dependence on undocumented UCRT stride. | retained |
| S2 | The caller does not externally CloseHandle a transferred CRT-owned HANDLE. | open_osfhandle/get_osfhandle/fdopen/fclose expressly prohibit that ownership violation. Objects has no HANDLE generation. | Exact ObjId+grant validation and close; same-object/same-grant recycled-HANDLE ABA remains unknown. | Recycle handle to different object and reduced grant. | Close and reopen the same numeric handle to the same ObjId with equal grant. | retained |
| S3 | Private CRT VM storage is not externally freed/reallocated. | Opaque owned storage contract; VM allocation metadata has no generation identity. | Exact allocation validation and host-owned cleanup; identical-address/size ABA unknown. | Free without reuse; reuse with different metadata; caller buffers never released. | Raw-free/reallocate identical metadata at the same address. | retained |
| S4 | Guest threads use one scheduler host thread; no guest protection change occurs between a successful preflight and synchronous guest copy. | Current scheduler/AddressSpace execution model. | Preflight-before-effect guarantees, not host filesystem atomicity. | Fault at next chunk, callback changes protection, abandoned continuation. | Introduce parallel guest execution or mutate VM from another host thread. | retained |
| S5 | Direct `_fmode` zero means the producer's default ANSI-text profile, distinct from invalid `_set_fmode(0)`. | Retained compiler startup initializes its local mode cell to zero before copying through the genuine accessor. | Ordinary-startup mode-cell interoperability. | Direct values 0/0x4000/0x8000 and setter zero. | Native producer trace disproving zero-as-default behavior. | retained |
| S6 | `_open_osfhandle` access bits 0/1/2 select read/write/read-write and actual HANDLE grants additionally restrict every transfer. | Retained producer fcntl header; publisher lists selected flags but does not establish every accepted-bit combination. | Descriptor adoption and fixtures using explicit O_RDWR/O_WRONLY. | Reduced append-only and denied read/write grants; illegal access bits. | Identified native CRT flag-combination matrix differs. | retained; native complete flag acceptance unknown |
| S7 | Text output CTRL+Z is excluded, terminates only the current request, and the return counts the preceding logical bytes/full items. | Publisher write contract says logical EOF/output terminator but does not specify marker inclusion or exact native count. | No false progress or later-chunk leakage; output bytes are scanned before enqueueing. | Marker first, at 255/256 B, partial 2-byte item, fresh subsequent request. | Native versioned marker/count probe disagrees. | retained; native marker inclusion unknown |
| S8 | A trailing CR uses a one-byte lookahead; consumed LF is charged to the whole raw request, non-LF is cached without duplication. | Required CRLF translation; public source does not specify private lookahead/fault order. | Chunk boundary conservation and exact raw-budget tests. | CR at 255 B of a 768 B request; LF/non-LF, final CR and EOF. | Native private cursor/lookahead trace differs. | retained; native final-lookahead behavior unknown |

## Change-surface map

| Plane | Disposition |
|---|---|
| Direct decode/execute; architectural CPU state | Unaffected: guest ISA instructions and architectural register semantics unchanged. HLE argument/return marshalling exercises existing ABI machinery. |
| Memory/MMU | Affected Windows process VM allocation/protection/fault consumers; no architectural MMU changes. |
| SMIR lift/IR/interpreter/optimizer/native lowering/JIT admission | Unaffected: no new instruction or IR operation; built-in traps remain existing execution frontiers. |
| JIT runtime/backend/machine/device/oracle/C ABI | Unaffected: no backend contract, device, static analysis or C layout change. |
| Windows loader/runtime/HLE | Affected transactional data preparation, runtime-owned stream lifecycle, checked continuations and real host I/O. |
| Tests/docs | Affected storage/backend/unit tests, registered Windows integration runner, three-ABI compiled fixture group and archived primary inputs. |

Root owns `crt.rs`, `dll/mod.rs`, new `crt/stdio/{mod.rs,exports.rs,api.rs,
io.rs,backend.rs,backend_tests.rs,tests.rs}`, any necessary scheduler cleanup
call sites, test registration and this audit. Storage delegate owns only new
`stdio/{storage.rs,storage_tests.rs}`. Fixture delegate owns only new
`tests/fixtures/user/windows/crt_stdio/` and `tests/suites/user/windows/crt_stdio.rs`.
Reference delegate owns only new `docs/specifications/windows/crt-stdio/`.
No dependency, feature-default, toolchain, unrelated source or Git remote edit
is authorized incidentally.

## Bounds and provenance

Host scratch I/O is bounded independently of caller count. A byte-transfer
loop uses at most 256 B raw scratch and 512 B translated output scratch. The
worst-case physical output width is `256 B × 2 = 512 B` for all-LF ANSI text;
returned counts remain logical bytes or complete items. For fixed chunk width
K = 256 B, a byte loop costs O(ceil(n/K) * (K+F+B)) time when including linear
stream/block registry checks, and O(K) host scratch space, independent of n.
Persistent guest buffers and the registry itself are separate storage. A
flush-all captures O(F) identities, then incurs the corresponding per-stream
lookup and bounded-transfer costs; it is not claimed to be O(F) overall.
Legacy FILE is 32 B for x86 and 48 B for x64/ARM64 under retained
8-byte packing: 20 slots require 640 B or 960 B respectively. Public UCRT
headers do not specify the runtime's private native FILE size.

Primary contracts, exact producer/import inventories, licenses and checksums
are retained under `docs/specifications/windows/crt-stdio/`; the archive
manifest, not a secondary API list, identifies the inputs actually used.
Microsoft cpp-docs and MinGW-w64 revision pins are recorded there.

The independently replayed archive has 78 hash/size-verified inputs, 33 available
installed/fixture input hashes, 15 extraction/copy replays, 24 command replays,
and no unavailable inputs/tools. Its manifest SHA-256 is
`f790ef92e0a908038a66f0dc6aff59f6f7565b2ab22a802917aa43dd95bd9ed1`.

## Explicit profiles and failure frontiers

Read-only/input-last `fflush` retains its buffer and read direction; a valid
read-to-write update transition is admitted at EOF, not manufactured by an
input flush. Output flush supplies the write-to-read barrier. `setvbuf` gives
IONBF's documented ignore-buffer/size rule priority over generic size checks;
IOLBF is full buffering, and buffered size is rounded down to an even byte
count. Public legacy fields are synchronized for admitted API operations;
arbitrary legacy inline-macro/private-field mutation is not implemented here.

Captured ABI formals and accepted I/O prefixes survive checked guest faults.
Storage lifecycle generations and mutation revisions reject same-stream or
same-descriptor reconfiguration during fault repair before the old continuation
can overwrite newer state. This is a fail-closed reentry profile, not an inferred
native locking/SEH behavior. Error-store repair returns the captured failure
without repeating the invalid-parameter callback or host effects.

Normal process teardown attempts host-owned cleanup and reports unexpected
failure after handle draining. Forced termination preserves its supplied exit
status for CRT-discard failures and retains those failures as trace diagnostics.
The pre-existing final handle-drain failure policy can still produce `Internal`.
At this historical stream-group baseline, neither path implemented CRT
normal-exit flushing. The subsequent [dynamic UCRT termination group](windows-crt-exit.md)
adds terminating UCRT DLL-detach flushing, including raw normal OS exit;
dynamic `_cexit` itself does not flush in the inspected SDK source profile.
Host I/O errors may have partial effects; actual host ENOSPC atomicity is not
established. A failing flush discards remaining buffered data as permitted by
the public contract. Mandatory full-buffer flush failure subtracts the current
call's unaccepted tail before reporting fwrite's complete-item count.

## Bounded findings

| Impact | Evidence and disposition | Blocks this group? |
|---|---|---|
| High | Ordinary compiler startup also requires actual CRT termination and structured-exception personality support. This stream group is not proof of ordinary main/wmain execution. | No; blocks full goal completion. |
| High | Unicode modes require UTF-16 byte-count validation and actual UTF-8/UTF-16 translation; successful ANSI substitution would be incorrect. | Unsupported before effects in this byte foundation; remains required for full goal. |
| High | The publisher's `_write` ENOSPC no-flush statement is not established for the host filesystem's partially accepted writes. The backend retains accepted-prefix accounting instead of claiming atomic disk rollback. | No under the explicit partial-effect profile; blocks a native ENOSPC-equivalence claim. |
| Medium | Same-object HANDLE ABA and identical-allocation VM ABA are undetectable without generation metadata when callers violate ownership (S2/S3). | No under explicit ownership preconditions. |
| Medium | Win32 synchronous I/O currently allocates O(count) scratch and does not expose write_all's accepted-prefix count. CRT engine must not inherit that implementation. | No; separate bounded engine. |

## Validation status

Host: `aarch64-apple-darwin`; stable Rust 1.98.1
(`48a229ceaefd4985c50990b14116b6d856af0985`, LLVM 22.1.8).
Commands ran against the combined owned tree; the seven modified tracked files
were clean at baseline. All Cargo commands used `+stable` and `--locked` except
the non-building format check. Logs are retained locally under
`/tmp/rax-crt-stdio-gates.3jpO59/`; elapsed times are test-run observations, not
throughput measurements.

| Gate | Observed result |
|---|---|
| `test --no-default-features --lib -- --test-threads=4` | 6695 passed, 0 failed, 2 ignored, 0 filtered; 128.00 s. Includes all 47 new stdio unit functions. |
| `test --no-default-features --features x86_64-suite,smir-jit --lib -- --test-threads=1` | 8867 passed, 0 failed, 2 ignored, 0 filtered; 1078.63 s. |
| `test --no-default-features --test user_windows --test ci_actions_pinned -- --test-threads=1` | Windows 291 passed, 0 failed/ignored/filtered, 32.11 s; CI 10 passed. |
| Same integration command with `--features x86_64-suite,smir-jit` | Windows 291 passed, 0 failed/ignored/filtered, 32.70 s; CI 10 passed. |
| `CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true test --no-default-features --lib user::windows:: -- --test-threads=1` | 423 passed, 0 failed/ignored, 6274 filtered; 3.32 s. Explicit debug-checked supplemental run, not a substitute for the unfiltered library gates. |
| `build --workspace --all-targets --no-default-features` | Passed; existing root/C API `librax.rlib` filename-collision warning retained. |
| Same all-target build with `--features x86_64-suite,smir-jit` | Passed with the same existing collision warning. |
| `clippy --workspace --all-targets --features x86_64-suite` | Passed; warning-tolerant repository policy is not used as semantic evidence. |
| `test --no-default-features --doc`, with and without `--features x86_64-suite,smir-jit` | Each: 0 passed, 0 failed, 5 ignored, 0 filtered; no doctest execution coverage. |
| `fmt --all --check`; `git diff --check` | Passed for Rust formatting and tracked unstaged changes; the final staged check has four raw-producer whitespace diagnostics documented below. No repository-wide formatting mutation. |

The library ignores are the existing full-microkernel lift/lower and exact-byte
roundtrip tests. No new stdio unit or Windows integration test is ignored or
self-skipped. The 62 new integration functions contain 60 semantic cases,
each unconditionally executing slices 1 and 4096 with `RAX_NO_JIT=1`, plus two
integrity tests. Feature-enabled Windows execution establishes compilation and
runtime compatibility of that configuration, not Windows native-JIT coverage.

The frozen fixture inventory is 66 PEs (297472 B): 60 custom-entry PEs and six
genuine ordinary main/wmain observations. Two final productions reproduced all
73 manifest/artifact/IAT hashes. The preserved pre-feature CLI produced 120
custom export failures (exit 125); ordinary observations produced 10 export
failures and two ARM64 slice-1 watchdog expiries (30 s, cause unknown).
These are failure observations, not ordinary-startup acceptance. Goldens are
literal byte arrays or the fixed `(7*i+3) mod 256` pattern, never computed by the
CRT under test. Twenty-three source hashes, all 66 artifacts, all six actual IAT
receipts, and all 78 archived primary input hashes/sizes are checked by the
registered runner. Native Windows execution remains unknown.

Frozen SHA-256 values:

- Fixture manifest: `7ab3619a57d3860d90c9a91570af695afbffc9685f5f1867d5fe051827cf96b6`.
- Baseline observations: `9913c3b29a4c3e6d41de8835c956f4782af943af973d240e2ce90f85fe05cf5e`.
- Integration runner: `a344d0a883ebc3fb7e44a3578b74f1db3d19f9a0a7be6c2d586217c11421e685`.
- Storage implementation: `10284ba1c7f9eee4e6dfc9f264216bbde13b39b172bb61e02c6b8854bedc2fc9`.
- Storage tests: `ca604a7f6e62cb55d09578cba812c01848db1234637c8ae601f529a212ca0592`.

S1–S8 remain retained profile/ownership assumptions; boundary tests exercise
their admitted consequences without turning unknown native behavior into a
confirmed fact. Independent runtime, storage/lifetime and fixture reviews found
no additional confirmed blocker after the recorded fixes.

## Acceptance-criterion audit

| Criterion | Implementation and direct evidence |
|---|---|
| 1: genuine bindings | `stdio/exports.rs` and the retained DEF/alias inputs; exact IAT assertions for all 60 custom PEs, actual data/stride unit tests and six ordinary import receipts. |
| 2: transactional storage | `PreparedDataExports` pairs startup/stdio preparation, commit and abort; storage tests cover source faults, late DATA faults, missing/invalid metadata, allocation/commit exhaustion and unpublished rollback. Existing complete loader/lifecycle suite passed. |
| 3: HANDLE/FD/FILE identity | `attach_descriptor`, `attach_stream`, `validate_descriptor`, `close_fd`; direct tests cover rights, flags, protected handles, different-object reuse, transfer versus duplication, no truncate and final host-close error. Compiled descriptor probes run all ABIs/bindings. |
| 4: buffers/status/flush/close | `replace_buffer`, `ensure_buffer`, `read_step`, `flush_pending`, `walk_flush`; direct caller-buffer, allocation/swap, input-retention, EOF/update, sticky-error and mandatory-flush-failure tests. Compiled bytes/buffering/text probes verify literal host outputs and handle closure. |
| 5: bounded precise continuations | Captured `decode`, `live`, revisioned publication and backend accepted-prefix results; bounded/Interrupted/short-write/WriteZero backend tests, separate read/write repair tests, invalid-handler errno-store repair, stale-stream rejection and actual compiled VEH repair with consumed-prefix/formal mutation. |
| 6: explicit byte foundation | `_read` raw-budget/CRLF boundary tests, CTRL+Z logical-frontier tests, append-only grant and intptr-width tests; Unicode even-byte unsupported-before-buffer/effects and odd-byte validation tests. Pipes/overlapped/private mutation remain explicit frontiers, not admitted substitutes. |
| 7: registered three-ABI evidence | Existing `user_windows` target registers 62 new functions, including 120 unconditional semantic CLI invocations; 47 new unit functions run in the unfiltered library suite. Source/artifact/baseline/provenance integrity tests pass without native-oracle substitution. |

Owned scope is 176 exact files: seven pre-existing tracked files, this audit,
nine new stdio Rust files, 64 new reference/archive files, 94 new fixture files
and the new registered runner. The seven tracked paths are the Windows
architecture record, CRT root and shared test helper, DLL root, scheduler,
test README and Windows aggregate. Unrelated untracked content, Git remotes,
Cargo/dependency state and all adjacent packages remain untouched. The existing
scheduler reaches 1506 lines, slightly above the 1500-line soft ceiling but below
the 2000-line/150 kB hard split trigger; no unrelated restructuring is included.

## Final quality-gate audit

No ethical judgment is required. The requested assumption, requirement,
unit/calculation, contradiction, provenance and bounded-scope gates are covered
by the registers, source archive, acceptance table and observed results above.
The repository-specific gates are reconciled as follows:

| Gate | Evidence and limits |
|---|---|
| QG1: assumptions | S1–S8 revisited after the three-ABI boundary/fault/ownership tests; retained private and ownership profiles remain explicit, not fabricated native facts. |
| QG2: coverage | All seven group acceptance criteria map to implementations and direct evidence above; complete Windows userland remains a separate unfinished goal. |
| QG3: reproducibility | Exact baseline/executable/artifact/source hashes, toolchain, 1/4096-instruction slices, seed 1, 67108864 B arena, 30 s watchdog, byte-width arithmetic and commands retained. Two final fixture builds reproduced every declared artifact/IAT hash. No performance estimate is inferred from test duration. |
| QG4: contradictions/edges | IONBF size priority, WTEXT setter discrepancy, attachment/direction rules, CTRL+Z/count and CR lookahead profiles are visible. Partial host effects and the existing final handle-drain failure policy are not hidden behind broader claims. |
| QG5: provenance | Final archive replay: 78 retained hash/size checks, 33 available input hashes, 15 extraction/copy replays, 24 derived command replays, zero unavailable inputs/tools. Forty-four authored local links across the selected architecture/reference/fixture records resolve. |
| QG6: bounded scope | High/medium findings are listed above; no adjacent ISA/JIT/C ABI, dependency, feature-default, remote, kernel or unrelated source mutation. |
| QG7: worktree | Baseline HEAD stayed unchanged and index empty through validation; 176 exact owned paths are enumerated for staging. Unrelated untracked trees are excluded. No destructive Git command or broad-format mutation. |
| QG8: behavioral evidence | Both complete library configurations and both complete Windows/CI binaries passed; supplemental checked arithmetic run passed. The 120 custom pre-feature failures and 120 successful per-configuration semantic runs use identical final PE bytes. No new test skips, ignored cases or native-oracle substitution. |
| QG9: consistency | Existing Cargo target and CI reachability preserved; source categories and file sizes within hard triggers; genuine DLL/ABI bindings, manifests, fixtures and architecture/test documentation agree. Rust formatting passed; staged whitespace checks exclude only the four byte-exact producer observations described below. |

The complete staged `git diff --cached --check` reports exactly four trailing
spaces: line 8 of `producer/gcc-{x86,x64}-{main,wmain}-dryrun.txt`, each after
the producer's `gcc version 16.2.0 (GCC)` text. These are retained raw command
outputs, not authored Rust/document formatting. Trimming them would invalidate
the exact replay/hash provenance and conflict with the primary-preservation
contract. All other 172 owned paths pass the staged check; the four observation
hashes and replays pass unchanged. This is an explicit provenance exception,
not an undisclosed clean-whitespace claim.

Unrun evidence: native Windows differential execution (oracle unavailable),
full ordinary compiler-startup acceptance (retained missing dependencies), and
Windows native-JIT execution (probes deliberately select `RAX_NO_JIT=1`).
KVM/HVF, ISA-native differential, microkernel, ASL-parser and C ABI runtime gates
do not intersect this group's unchanged surfaces; all-target workspace builds
provide compilation, not execution, evidence for those packages. The two
existing ignored microkernel library tests and five ignored doctests in each
configuration are not claimed as coverage.

Commit workflow: stage only the enumerated owned paths; use
`red -m --staged --run` with the same exact paths; push the current `user-win`
branch directly to `origin` after committing. No amendments, session links,
coauthor trailers or unrelated staged content are part of this group.
