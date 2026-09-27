# Windows handle/service integration

Baseline: 4312bb48ec169c48c67ea8ab55bbacda702e5e93, branch user-win.
The baseline tracked tree/index was clean. Unrelated pre-existing untracked
content is excluded. Owned source: dll/{files,handles,locks,threading}, registry/
kernel migration, objects.rs, sync.rs, process/{mod,sched,start,thread}.rs and
hle/dispatch.rs. Owned evidence: feature documents, retained service sources,
this/master document, separate services PE fixtures and user_windows runner.
No dependencies, default features, toolchains, native admission or C ABI change.

## Acceptance and scope

The group exposes thread creation/control/APCs, named events/mutexes/semaphores,
single/multiple/alertable waits, critical sections, SRW locks, condition/address
waits, same-process handle duplication/flags and synchronous file services.
Each architecture has ABI tests and a compiled guest PE program. These establish
implemented conformance, not complete Windows/native-kernel equivalence.

Object names compare exactly; Local aliases the single modeled default session
and Global is distinct. Wait sets pin objects transactionally and release pins
once on completion/cancellation. Per-handle grants survive same-access duplication.
Reduced file grants cannot regain FileObj permissions. ReadFile/WriteFile/
CloseHandle move from kernel into file services without shadowed exports.
Cross-process duplication, protected close-source duplication, non-file access
escalation and custom security descriptors remain explicit rejected branches.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | Guest mappings remain stable through HLE preflight/copy | Serialized scheduler/AddressSpace contract | Lock/file publication | Cross-page read-only output | Concurrent embedding clone mutation falsifies contract | Retained |
| S2 | One client session and process-local objects are admitted | Proc owns Objects | Exact-case Local/default alias and distinct Global | Prefix/case/type collisions | Name tests; separate processes cannot share Objects | Confirmed profile |
| S3 | Non-file access escalation needs unmodeled tokens/ACLs | Microsoft DuplicateHandle permits object-dependent escalation | Explicit unsupported branch | Request rights absent from source | Verified token/access-check implementation; native comparison | Retained |
| S4 | Stacks commit usable reservation above a terminal guard | Existing fixed-stack/no demand-growth contract | CreateThread size adaptation | Rounding/overflow/invalid ID output | Stack/rollback tests; native VirtualQuery unknown | Retained |
| S5 | Unix device/inode identity distinguishes live files | Host metadata | Sharing/deferred deletion | Hard links, replacement, symlinks | Concurrent replacement between final check/unlink falsifies atomicity | Retained; atomic namespace not claimed |
| S6 | Expected guest results are specification-based | Retained Microsoft contracts; no native recording | Conformance conclusions | Execute same PE on Windows builds | Native run may falsify expectation | Retained; native result unknown |
| S7 | Fixtures reach guest behavior, not just imports | Exit checks, import counts, deadline, scheduling variation | Integration coverage | Slices 1/4096 and failure codes | Run whole user_windows binary and inspect counts/results | Confirmed: all 30 tests passed; six service executions cover three ISAs and both slices |
| S8 | Guest programs do not free/recycle personality-owned TLS system allocations | Standard APIs do not transfer ownership of these allocations | Address-based TLS teardown tracking | Forged guest TLS pointer must not redirect teardown | Explicit HeapFree/reuse of genuine system allocation exceeds profile; no allocation-generation model exists | Retained |

## Change-surface map

| Plane | Status |
|---|---|
| Direct decode/execute | Unchanged semantics; all three compiled guest ISAs exercise existing cores |
| CPU state | Existing ABI/callback/TLS/TEB marshalling reused |
| Memory/MMU | Checked storage and stack allocation affected; no MMU contract change |
| SMIR lift/IR/interpreter/optimizer/native lowering/JIT runtime | Unaffected; direct interpreter-only Windows execution |
| Backend/machine/device | Unaffected; services are inside process personality |
| Oracle/analysis | Unaffected; no instruction/stateless output changes |
| C ABI | Unaffected; new internal services are not exposed by capi |
| Tests/docs/CI | Existing explicit user_windows target gains reachable tests; no matrix/target change |

## Complexity and bounded findings

Handle allocation: O(H) time, O(1) extra space for H handles. Transactional wait
pinning: expected O(N) time, O(U) space for N IDs and U distinct objects; admitted
N <= 64. I/O uses O(B) buffer space for B <= 16,777,216 bytes.

High, non-blocking for admitted profile: host check/unlink is not atomic against
external filesystem mutation; identity revalidation detects replacement but
does not implement Windows namespace transactions. High: demand stack growth,
thread/process detach and FLS cleanup remain incomplete. High: host console
reads can block the sole scheduler thread; asynchronous console/pipe dispatch
is not claimed. Medium: native private lock-word encodings/fairness and full
ANSI/Unicode conversion are unknown. Low: slice-1 performance is unmeasured.
High, pre-existing and non-blocking for normally mapped system TLS storage:
TlsFree clears its slot bitmap before fallible slot writes across threads.
A protected/forged TLS pointer can fault after partial cleanup. Native behavior
for corrupted private TLS state is unknown; no atomic fault rollback is claimed.
Guest freeing/recycling system-owned TLS blocks violates S8; tracked addresses
are not allocation-generation identities.

## Verification and Quality Gates

Host: AArch64 macOS; Rust stable 1.98.1. The frozen combined tree passed:

- cargo +stable test --locked --no-default-features --lib --test user_windows --test ci_actions_pinned -- --test-threads=4 --quiet:
  6,454 library tests passed, two ignored; all 30 Windows integration tests and
  all 10 CI contract tests passed, with none ignored or filtered in either
  integration target. The ignored library tests are the two explicitly ignored
  optional microkernel lowerer fixtures, not Windows tests. The library registry
  lists 182 Windows unit tests. The Windows runner verifies the service fixtures
  at scheduler slices of 1 and 4,096 instructions for each guest architecture.
- cargo +stable test --locked --no-default-features --test user_windows -- --test-threads=1 --quiet:
  all 30 tests passed again, with none ignored or filtered.
- cargo +stable check --workspace --locked --no-default-features --all-targets:
  passed, including rax-capi compilation.
- cargo +stable check --workspace --locked --no-default-features --features x86_64-suite,smir-jit --all-targets:
  passed. Feature compilation does not establish native JIT/KVM/HVF execution.
- cargo fmt --all --check: passed. The staged whitespace check passes for all
  owned hand-maintained source, fixtures, documentation and provenance records.
  A full-index git diff --cached --check reports upstream trailing whitespace
  only in manifest-declared retained primary snapshots/licenses; those bytes
  remain preserved rather than silently changing their provenance hashes.
- All 58 retained service-reference entries matched their declared SHA-256
  hashes: 32 thread/synchronization, nine lock, and 17 file references. Separate
  license hashes also matched. All four service fixture source/script hashes
  and all three compiled PE hashes/sizes passed the integration provenance test.
- Public lock-layout compile probes passed nine assertions per guest ABI
  (27 total), using the recorded MinGW-w64 headers, not a native Windows SDK.

QG1: no ethical judgment is required. QG2: S1-S8 and the service-specific
registers identify dependencies and falsification probes. QG3: acceptance is
covered by reachable unit and compiled-guest tests within the stated profile.
QG4: fixed-width ABI/layout arithmetic, checked allocation rounding and bounded
buffer calculations remain explicit in source and service documents. QG5:
unsupported branches fail explicitly; native unknowns and non-blocking profile
limits are recorded above. QG6: primary references and artifact hashes verify;
native Windows differential results remain unknown. QG7: high/medium/low
out-of-scope findings are recorded without expanding implementation authority.
These gates establish this service group, not completion of Windows emulation.
