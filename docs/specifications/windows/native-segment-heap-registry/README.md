# Native loader Segment Heap metadata

Baseline: RAX 98359e32f8643b371bcf496769521a4a651ec026 and Assist
3322ffd7aab6824e63f848fac39e16d899304b2f; both worktrees clean and all authorized
remotes verified. Previous current owning-archive saved-context/cleared-PEB-heap
trace opens IFEO, then at turn 4,462 stops opening fixed
\Registry\Machine\SYSTEM\CurrentControlSet\Control\Session Manager\Segment Heap,
NtOpenKey service 0x12, PC 0x180001130, access 1, as unselected.

Acceptance: add fixed optional Segment Heap value capture; preserve actual absence
as NAME_NOT_FOUND, acquisition errors as failures, raw present-key metadata/values,
relative parent-handle lifetime, shared ordinal case/aggregate budgets, and
explicit unsupported status for unselected namespaces/subkeys. No guest string
may reach the host registry, no fabricated empty key/defaults, no permission,
ABI/layout, persisted schema, package, dependency/default, or ISA/JIT change.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| S1 | Installed optional Segment Heap absence is native error 2/NAME_NOT_FOUND | Original fixed-path native probe on build 29683, all three ABIs/views | Guest negative selection | Root absent versus other acquisition errors | Nine paired NtOpenKey/RegOpenKeyExW results, controlled error classification | confirmed for current profile; other releases unknown |
| S2 | Configured present values can use the existing bounded raw snapshot contract | Fixed descendant of Session Manager; query-only metadata/value APIs | Present-key support | Count/data/name/case collisions and aggregate exhaustion | Native present profile remains unavailable; controlled model/NT tests plus native acquisition API | retained; actual configured present profile unverified |
| S3 | Known optional child must survive through a parent handle without claiming unknown siblings absent | Existing immutable Arc-owned key/IFEO model; native next dependency | Absolute/relative lookup and lifetime | Namespace drop, old namespace clones, partial-versus-complete children | Shared ownership/collation/partial lookup tests | confirmed by model/all-ABI NT/native leaf tests |
| S4 | Per-key sampling can represent observed stable loader metadata | Existing bounded double-sampling capture | Cross-key consistency | Parent/child concurrent change and restored mutation | Enforce obvious count contradictions; restored/cross-key atomicity unverified | retained, no transaction or ABA exclusion |

Affected planes: native Windows selection, shared registry model/NT lookup/tests,
installed NTDLL leaves, owning archives, protected description/generated discovery,
pin/engineering evidence. Unaffected contracts require final source/consumer checks.
Windows/macOS/Linux shared semantics/build/native adapter gates remain mandatory.

High: native production Ldr/RTL heap/CRT and wider NT/POSIX/application/package/IDA
matrices still block the overall full-process goal. Medium: concurrent restored
mutation and configured-present/other-platform profiles are unverified limits.
Low: no additional blocking item identified. No adjacent non-blocking change is included.


## Implemented contract and resource accounting

The Session Manager key owns one selected optional child: None means the child
is known absent, Some(key) means captured immutable values/child count. The
complete IFEO child map remains separate. Other Session Manager siblings retain
existing unsnapshotted behavior; they are not inferred absent. Exact Segment Heap
absolute paths and descendants resolve through that same parent-owned record,
with a separator boundary; lookalike prefixes remain outside selection. Relative
opens through an already-open parent survive namespace drop. Prior namespace
clones/parent handles keep their original scope, not a retroactively mutated tree.

Value maps are immutable Arc-owned BTreeMaps. A replacement Session Manager
record shares its old value map and case table, copying only the fixed path and
one folded child name. No public Rust Clone trait, C ABI layout/version, option,
permission, schema, default, engine/lowerer or package contract changes. The
optional child is not also inserted into the namespace root map: shared value
budget traversal charges it exactly once. A present child with a parent snapshot
child count of zero is rejected as a detectable cross-key contradiction.

Only the fixed native optional root reaches RegOpenKeyExW with KEY_QUERY_VALUE=1.
Its open error 2 records absence; other open errors and every later metadata/value
error fail acquisition. The existing per-key metadata/two matching sorted value
samples/metadata check retries at most three times on enumeration 234/259.
Metadata count and raw byte samples obey the remaining 4,096-value/16 MiB budget
before retention. HKEY ownership ends before selected records return to the guest.
No child-name callback, host handle, mutation API or guest path is retained.

For existing raw payload P, existing folded names F<=P, and one optional sample
S<=16 MiB-P, optional capture raw-plus-folded payload is
P+F+2S <=32 MiB+F-P <=32 MiB, plus the existing bounded 1,081,344-byte value
scratch and finite metadata. The earlier fixed-two-key phase's maximum 48 MiB raw
payload remains the larger acquisition bound. Final raw values across all roots
remain <=16 MiB and folded value names <=16 MiB. The new optional key has a
79-unit UTF-16 fixed full path (158 bytes), and its folded child component has
12 units (24 bytes); parent replacement copies the 66-unit path (132 bytes),
shares the value map, and adds finite scalar/Arc/container overhead. This is not
a byte-exact allocator/RSS claim. IFEO's 1,024-key/path/depth budget is unchanged;
there are at most three fixed key records outside that complete subtree.

Existing U=65,536 table initialization, bounded raw value sampling/folding and
map construction retain O(U+B+N*L*log(N+1)) work for raw bytes B, values N and
maximum name length L, plus IFEO key/path work already documented. Attaching the
optional parent record adds a fixed-size path/name copy and bounded child-value
construction, without O(Bparent) raw copying. Registry budget traversal charges
every selected value once; guest partial-child lookup adds one bounded component
comparison before the existing known/unknown-child decision. All code uses the
same shared model on Windows/macOS/Linux; only native acquisition is cfg(windows).

## Native and controlled evidence

Original native ARM64/compatibility x86/x64 with view0/0x100/0x200 produce nine
paired opens, 18 native operations: NtOpenKey=0xC0000034 and RegOpenKeyExW=2 for
all. The independent replay checks each raw record without host access. Actual
configured-present Segment Heap remains unobserved. A controlled native opener
supplies a real query-only Session Manager HKEY to exercise positive acquisition
without changing the host registry; each captured raw value is independently
queried via RegQueryValueExW. This is controlled adapter evidence, not a claim
that the host has Segment Heap settings. The actual fixed-root presence test
compares all three native Win32 views, and was observed failing before the fix
(0 pass/1 fail/6,926 filtered), then passing in the initial focused selection.
Two portable ownership/scope/budget cases and two all-guest-ABI NT cases pass;
three native acquisition cases distinguish root absence/error/controlled present
values, and the actual installed ARM64/x86 NTDLL leaf case now opens this key.

## Change surfaces

| Plane | Status/evidence |
|---|---|
| Plugin lifecycle | Existing opt-in runtime selection only; no load/teardown/IDA profile change |
| UI | Protected description/discovery only; no widgets/Qt lifetime change |
| Conversation/lanes | No session/history/lane consumer changed |
| Agent backend | Existing common tool metadata; no native/ACP request policy change |
| Prompt/context | No prompt/context source changed |
| Tool schema | Compiled manifest differs only in emulate_process.description |
| Permission/mutation | Existing read_files_outside and guest explicit read-only grant preserved |
| Main-thread dispatch | No IDA/Qt calls introduced |
| Mesh/MCP | Generated description only; no identity/routing/protocol change |
| Transport/crypto | No framing/authentication/crypto input change |
| Persistence | Selected in-process immutable data only; no migration |
| SDK/ABI | Private Rust ownership only; C API1.11.0/layout unchanged; separate full C API/owning checks |
| Optional engines | RAX only; no Z3/Frida/debugger/Hex-Rays gate change |
| Update/release | Pin and engineering evidence only; no release/package/default changes |
| Targets/platforms | Shared model/NT tests on all three; native Windows adapter and owning archives/C++ checks |
| Tests/docs | Model/NT/native raw acquisition and installed NTDLL cases; original/pinned provenance |

## Final validation

| Host/configuration | Unfiltered library pass/fail/ignore/filter | Selected | C API | All targets | Registered integration |
|---|---|---|---|---|---|
| macOS ARM64 Rust1.95 | 7,539/0/2/0 | 7,541 | 168 pass | compile pass | Unix 544 pass; Windows memory cfg-excluded |
| Linux x86-64 Rust1.95 bullseye container on ARM64 host | 7,531/2/2/0 | 7,535 | 168 pass | compile pass | Unix 544 pass; Windows memory cfg-excluded |
| Windows29683 ARM64 Rust1.95 | 6,926/5/2/0 | 6,933 | 168 pass | compile pass | Unix cfg-excluded; native memory 4 pass |

Linux failures are a_multishot_timeout_reports_each_expiry and
a_timeout_is_removed_or_updated; Windows retains the four previously observed
BZHI lowering assertions and lowers_vector_fp16_arithmetic_runtime. Historical
readiness/strict-clock evidence remains unresolved. No unrelated lowerer, timer,
assertion, selection or skip changed. Container translation is not physical
native x86-64 hardware proof.

The full suites and owning builds precede only a Windows-native test assertion
strengthening: replacing a second shared enumerator comparison with independent
RegQueryValueExW reads. Production/shared source remains identical. Final Windows
source hashes, seven focused cases (6,926 filtered) and one installed NTDLL case
(6,932 filtered) pass. Earlier initial tests selected six cases before the third
native case was added; initial compile/import mistakes are excluded from final
passing proof. Full and final source-hash registers preserve this distinction.

Locked owning assist-rs archives and five production C++ checks pass on every
host, including RAX-disabled refusal, ABI drift and static archive linkage. The
macOS owning CLI regenerates the cold manifest exactly; only the process tool
description changes. Seven relevant CTests include both manifest checks and pass;
CLI/MCP protected-text scans pass. No plugin/Qt/real IDB/full package matrix was
run by this group. Original Windows log bytes are fetched with Base64 and native
SHA256 verification; transport wrapper text and text-mode retrieval are excluded
from the retained native evidence. Full-log hashes and sizes are retained.

The current owning-archive diagnostic and remaining native boundary are below.


## Current owning-archive loader boundary

The private saved-context/cleared-PEB.ProcessHeap diagnostic uses the current
locked owning Assist archive's RAX rlib selected from Cargo JSON artifact output.
It is not production native process entry. At turn4,462 the Segment Heap open
returns observed NAME_NOT_FOUND; initialization reaches turn11,206, PC0x1800013a0,
NtQuerySystemInformation service0x36, class62, output0xabf450 and supplied64 bytes,
then terminates with the explicit unsupported-class diagnostic. Delta
11,206-4,462=6,744 is scheduler calls, not instructions [S1-S4]. No meaning/layout
for class62 is assumed by this group. Four ordinary Windows smoke/msvcrt/ucrt/
whoami programs still terminate with STATUS_ACCESS_VIOLATION. The overall native
Ldr/RTL heap/CRT, wider NT/POSIX and native application/package/IDA goal remains
incomplete. Original diagnostic source/log and hashes are retained; no DLL binary
is redistributed.

Self-review: optional absence differs from failed acquisition and unknown scope;
parent raw payload is shared and child payload charged once; constructor/table/
count/size/case/old-handle boundaries are exercised. Primary/source/raw/gate hashes
verify provenance and phase selection. This semantic group adds no ABI, schema,
permission, dependency/default, package or lowerer change. Unknown configured
present profiles and cross-key/ABA consistency are explicit limits [S2,S4].
