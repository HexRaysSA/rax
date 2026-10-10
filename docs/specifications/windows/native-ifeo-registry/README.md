# Native loader Image File Execution Options metadata

Baseline: RAX 67b5dcdfec481e71e0622c91378101e826efe8b5 and Assist
d261ec90ce8554a587afe363ce7f0876c6035f24; both worktrees clean. The prior
current owning-archive diagnostic stopped at scheduler turn 3,405 opening fixed
Image File Execution Options (IFEO), NtOpenKey service 0x12, PC 0x180001130,
access 9. Its source/trace is retained in ../native-session-manager. This is a
saved-context/cleared-PEB-heap diagnostic, not the production startup path.

## Contract and acquisition

Native selection keeps the two fixed SYSTEM value captures (NLS CodePage and
Session Manager) and adds exactly one fixed HKLM IFEO subtree. Only that fixed
root and validated native-enumerated descendants reach RegOpenKeyExW. Access 9
is KEY_QUERY_VALUE(1) | KEY_ENUMERATE_SUB_KEYS(8), with no create/set/delete calls.
Native parent HKEYs close before any descendant opens, including error paths.
The selected namespace retains raw UTF-16 names, DWORD types and byte strings,
sharing the installed 65,536-entry ordinal case table. No host handle or callback
survives selection. Typed guest ancestor/descendant handles own immutable keys
and remain usable after the process registry namespace drops.

Each native key uses metadata-before, two identical sorted value/name samples,
and metadata-after, with at most three attempts. ERROR_MORE_DATA(234) and
ERROR_NO_MORE_ITEMS(259) during enumeration retry that key; other errors abort.
Only ERROR_FILE_NOT_FOUND(2) while opening the fixed optional root records known
root absence. A missing enumerated descendant aborts acquisition. Neither a
partial tree nor an invented empty tree is selected after failure. Sampling is
per key: it is not atomic across keys, excludes neither restored mutations nor
parent replacement races, and makes no registry transaction claim.

Known absent roots/descendants return STATUS_OBJECT_NAME_NOT_FOUND(0xC0000034).
Namespaces outside selection still fail explicitly as unsupported. Native opens
ignore repeated/trailing backslashes; dot names and '/' are literal registry
components. Root-relative leading backslashes fail STATUS_OBJECT_PATH_SYNTAX_BAD
(0xC000003B) through the existing OBJECT_ATTRIBUTES validation. Ordinal case
folding occurs once per component, including supplied non-idempotent test tables.
Guest access remains governed by the existing explicit read-only grant.
NtQueryValueKey raw serialization/fault ordering is unchanged. This increment
does not implement guest NtQueryKey or NtEnumerateKey.

## Finite resource contract

All three roots share at most 4,096 values and 16,777,216 raw name/data bytes
(16 MiB), per-value data <=1,048,576 bytes, and name <=16,383 UTF-16 units.
IFEO separately admits at most 1,024 keys including root, depth <=32 with root
at depth zero, child components 1..255 UTF-16 units, full paths <=32,767 units,
and aggregate full-path bytes <=1,048,576 bytes. Empty/NUL/backslash child names,
ordinal collisions, duplicate root attachment and every exhausted bound fail.
Pending native sibling lists reserve the shared key count before enumeration,
so recursion cannot multiply it by the depth limit. Exact returned name/data
buffers avoid retaining maximum native scratch capacity for each value.

The fixed-key phase retains its previously established maximum 48 MiB transient
raw payload. During IFEO capture, with previous raw charge P and current sample
charge S <=16 MiB-P, raw payload is P+2S <=32 MiB-P. Existing folded names F<=P
therefore give raw-plus-folded payload <=32 MiB. Value-enumeration scratch is at
most 2*(16,383+1)+1,048,576 =1,081,344 bytes. Child-name scratch is at most
2*(255+1)=512 bytes and follows value capture. Native child name lists, key paths
and folded child names have finite O(K+Ppath) metadata, rather than per-frame
copies of the entire tree. Final raw values <=16 MiB, folded value names <=16
MiB, ordinal table 2*65,536=131,072 bytes, aggregate raw full paths <=1 MiB;
allocator/container overhead is additional, finite O(N+K), not a byte-exact RSS
claim. Native path grammar and depth also imply a smaller maximum per-path
length: 91+32*(1+255)=8,283 UTF-16 units for this fixed root.

For U=65,536 case entries, N values, K keys, B raw value bytes, Ppath full-path
units, maximum value-name length L and component length C, capture/validation
work is O(U+B+Ppath+N*L*log(N+1)+K*C*log(K+1)) plus native calls and bounded
resampling; storage O(U+B+Ppath+N+K). Guest lookup is bounded by descriptor/path
length plus per-component map lookups, with recursion depth <=32 for captured
keys. The internal constructor accepts already-owned Rust data; these acquisition
bounds do not bound allocations made independently by an internal test caller.

## Native observations and regressions

The two original read-only C++ programs and six raw CRLF output files contain
1,395 inventory observations plus 1,494 relative-path observations, total 2,889:

| Operation per ABI/view | Inventory | Path probe |
|---|---:|---:|
| Fixed root open | 1 | 1 |
| Full/name root query | 2 | 2 |
| 49 child enumerate/open/full-query triplets | 147 | 147 |
| End enumeration | 1 | 1 |
| Relative image/path opens | 4 | 15 |
| Total per view | 155 | 166 |
| Three views and three ABIs | 1,395 | 1,494 |

On Windows 10.0.29683.1000 ARM64, native ARM64 and compatibility x86/x64 with
view flags 0/0x100/0x200 expose identical 49 first-level raw child names and
metadata. Root MaxNameLen is 70 bytes, NameLength is 182 bytes; notepad.exe has
four nested filter keys. The first-level oracle checks child metadata, not all
nested values. `check_native_ifeo.py` independently checks every retained record,
raw headers/names, cross-view/ABI equality, exact end status and all 15 path
statuses. Its output is retained and reproducible without Windows access.
The hypothesized PATH_NOT_FOUND for a missing intermediate component was
falsified by native NAME_NOT_FOUND. No host configuration is fabricated from
these machine-specific observations.

The separate native acquisition regression failed before subtree attachment
(0 passed/1 failed/6,921 filtered), then passed (1/0/6,923 filtered). The final
native case independently walks the complete installed tree and compares every
captured count, name, value type and byte string via fresh read-only HKEYs. It
also injects error 2 at an enumerated child without mutating the registry. A
separate controlled native-adapter case establishes root error 2 as absence and
errors 5/234/259 as acquisition failures. Actual installed ARM64/x86 NTDLL
leaves open/query/close the root and captured child with PC/return/stack cleanup
checks; this is distinct from portable direct-dispatch tests.

## Assumption Register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| I1 | IFEO is shared between modern native/WoW views | Retained Microsoft shared-key table and all nine current ABI/view inventories | View-bit policy | Older OS, differing children/raw metadata | Original native probes and independent checker | confirmed on current build; other native profiles unknown |
| I2 | Fixed loader metadata fits a complete bounded tree | Existing immutable ownership plus complete native acquisition regression | Selection/relative handles | Nested keys, case collisions, depth/key/path/value exhaustion, namespace drop | Shared boundary/lifetime tests and independent whole-tree raw queries | confirmed for current installed profile; oversized trees intentionally refused |
| I3 | Per-key double sampling suffices for the observed stable profile | Matching bounded samples/metadata in acquisition | Snapshot consistency | Restored mutation, parent replacement, cross-key changes | Controlled disappearing-child injection; concurrent restored mutation not exercised | retained; no transaction or ABA exclusion |
| I4 | Optional root absence is distinct from incomplete capture | Root-only error classification and child failure propagation | Known missing NT result | Root absent versus access denied versus child disappearance | Controlled native-adapter tests, direct guest all-ABI absence test | confirmed classification; actual absent host root unverified |

## Change surfaces and bounded scope

| Plane | Status and evidence |
|---|---|
| Plugin lifecycle | Unchanged; acquisition remains in existing opt-in runtime selection |
| UI | Description only through existing protected metadata; no Qt/widget change |
| Conversation/lanes | Unchanged; no session/history/lane consumers changed |
| Agent backend | Shared existing registry/tool metadata path; no native/ACP request policy change |
| Prompt/context | Unchanged; no embedded prompt or context source change |
| Tool schema | Description/discovery updated; compiled dump differs only in emulate_process.description |
| Permission/mutation | Existing read_files_outside and explicit read-only guest grants retained; no mutation API |
| Main-thread dispatch | Unchanged; no IDA/Qt call introduced |
| Mesh/MCP | Generated description updated; method/routing/identity contracts unchanged |
| Transport/crypto | Unchanged; no framing/authentication/key material change |
| Persistence | Unchanged; immutable selected in-process data only, no schema migration |
| SDK/ABI | C API 1.11.0/layouts unchanged; complete C API and owning archive checks separate |
| Optional engines | Embedded RAX path changed; Z3/Frida/debugger/Hex-Rays gates untouched |
| Update/release | Pin/engineering records only; no release, packaging/default or update contract change |
| Targets/platforms | Common tree/NT code compiles and executes shared tests on all three; native adapter cfg(windows), locked owning archives and C++ consumers checked on each host |
| Tests/docs | Four portable model tests, three all-guest-ABI NT tests, two native acquisition cases and extended installed NTDLL case; retained primary/original provenance |

High: production native loader/RTL heap/CRT, wider native NT services and complete
native application/package/IDA matrices remain blockers for the overall goal.
Medium: restored/cross-key mutation and other native OS/hardware profiles remain
unverified limits; non-blocking for this bounded immutable selection increment.
Low: sharing captures between processes could reduce startup work; no cache or
adjacent policy change is introduced. Linux/Darwin broader POSIX process/symlink
semantics remain within the overall unfinished goal, outside this Windows group.

Final gate results and the next owning-archive diagnostic are recorded below.

## Validation and next boundary

| Gate | macOS ARM64 | Linux x86-64 container on ARM64 host | Native Windows ARM64 |
|---|---|---|---|
| Unfiltered library | 7,535 pass/0 fail/2 ignore/0 filter | 7,528/1/2/0 | 6,919/5/2/0 |
| Complete C API | 168 pass/0 fail/0 ignore/0 filter | 168/0/0/0 | 168/0/0/0 |
| Final formatted IFEO selection | 7 pass, 7,530 filtered | 7 pass, 7,524 filtered | 9 pass, 6,917 filtered |
| Final actual installed NTDLL leaves | Windows cfg exclusion | Windows cfg exclusion | 1 pass, 6,925 filtered |
| All-target build | pass | pass | pass |
| Registered user_windows | 544 pass | 544 pass | Unix cfg exclusion, 0 selected |
| Registered user_windows_memory | Windows cfg exclusion, 0 selected | Windows cfg exclusion, 0 selected | 4 pass |
| Current locked Assist archive and five production C++ checks | pass | pass | pass |
| Current compiled CLI/manifest and both manifest checks | pass, seven relevant CTests total | Production adapter/factory checks pass; no native IDA/CLI run | Production adapter/factory checks pass; no native IDA/CLI run |

Unfiltered selections are 7,537/7,531/6,926. The complete suites preceded final
formatting and a Windows-only injection-test change isolating the acquisition
budget from the already-selected IFEO snapshot. Final source hashes and final
focused/all-target/C API/owning-archive checks are retained separately; these
are not a claim that a later entire suite reran. Native whole-tree validation
checks 54 keys, 106 values and 4,756 raw name/data bytes. The error injection
reaches two opens and produces acquisition error 2. Actual host root absence
was not observed; its adapter classification is controlled coverage.

The Linux failure is a_multishot_timeout_reports_each_expiry, observed two
completion tuples versus the expected one. The earlier pre-absence-source run
also fails a_timeout_is_removed_or_updated, retaining its extra timeout tuple;
absence in the later run does not establish remediation. Five Windows failures
remain the four existing BZHI assertions and host-unavailable FP16. Earlier
Linux readiness/Windows strict clock failures remain historical unresolved
limits. No lowerer, timing assertion, skip or unrelated implementation changed.
Initial Windows test compilation failed on a test-only unwrap_err Debug bound;
it was corrected and excluded. One mistaken CMake target named a CTest rather
than a build target; the actual targets and all seven selected CTests pass.
VM log retrieval and log naming failures were corrected after process completion;
final native log bytes are fetched as base64 with matching native SHA-256.
Unintended recursive formatter changes in existing registry tests were removed;
only owned paths remain. Provenance distinguishes failed/filtered/final checks.
Current CLI/MCP protected-plaintext scans pass; existing macOS IDA deployment
version warnings persist and are not addressed by this group.

The private saved-context/cleared-PEB-heap loader diagnostic, linked against the
current owning archive's validated RAX rlib, opens IFEO at turn 3,405 (success),
then opens relative probe.exe and receives 0xC0000034. It proceeds to turn 4,462,
NtOpenKey service 0x12, PC 0x180001130, access 1, attempting fixed
\Registry\Machine\SYSTEM\CurrentControlSet\Control\Session Manager\Segment Heap
outside the selected namespace. 4,462-3,405=1,057 scheduler calls, not retired
instructions. No restored native Ldr/RTL heap/CRT startup is established. All
four ordinary Windows probes still return STATUS_ACCESS_VIOLATION(0xC0000005).
The newly observed Segment Heap metadata is the next in-scope investigation;
it is not silently defaulted or implemented as part of this IFEO group.

Self-review: localized acceptance has direct implementation, boundary/lifetime,
actual native, discovery, owning-consumer and primary provenance evidence;
resource arithmetic is reproducible. Known larger-goal blockers and sampling/
platform limits are explicit. The overall full-process goal remains incomplete.
