# Guest virtual-memory queries and native ABI profile

`NtQueryVirtualMemory` uses six arguments, including pointer-width `SIZE_T`
buffer length and `PSIZE_T` return length. The appended export preserves prior
export indices. Classes 0 (`MemoryBasicInformation`) and 6
(`MemoryImageInformation`) query the authoritative guest virtual-memory manager.
No guest argument is forwarded to a host syscall, no queried bytes are read
from the target address, and no host image address or code-integrity trust is
copied into guest output.

| Class | x86 converted record | Native x64/ARM64 record | Guest source |
|---|---|---|---|
| 0 | 28 bytes | 48 bytes | Existing `RegionInfo` serializer: page/state/protection run |
| 6 | 12 bytes | 24 bytes | Image allocation base/size; zero record for other allocated memory |

Class 6 returns `STATUS_INVALID_ADDRESS` for free memory. Reserved and committed
private/mapped allocations return a zero image record. Addresses at or above
the guest's exclusive upper bound return `STATUS_INVALID_PARAMETER`. Class 0
retains the manager's page-rounded base, forward run length, allocation origin,
state, protection and type; free memory has `PAGE_NOACCESS`, as measured in the
native oracle. Querying a guarded/noaccess target does not touch its pages.

The current loader maps complete executable `SEC_IMAGE`-style PE images. It
does not create partial or `SEC_IMAGE_NO_EXECUTE` image mappings, perform a
guest code-integrity decision, or map kernel CFG/SCP image extensions. Thus
`ImagePartialMap`, `ImageNotExecutable`, and `ImageExtensionPresent` are clear,
and `ImageSigningLevel` is `UNCHECKED` (0). This is guest state, not the actual
Windows kernel's result for the same installed DLL. Native NTDLL in this
installation reports signing level 12 and a 64-bit CFG/SCP extension; the
unsigned original oracle executables report flags zero. Those host trust and
extension flags are not inherited. New image mapping types must extend this
model when introduced; full native CFG/SCP behavior remains incomplete.

Original observations use Windows 10.0.29683.1000 on an ARM64 kernel, native
ARM64 and compatibility x64/x86. Private behavior on other Windows builds and
physical Intel kernels is unknown. Public Microsoft documentation owns the API
signature/basic region contract; pinned PHNT declarations identify private
class 6 layout and enum bounds. Native observations own the admitted private
copy/fault profile and are not recast as public SDK guarantees.

For classes 0/6, native entry checks minimum length and address bounds before
output alignment/probing. It requires 8-byte output alignment, probes the full
supplied extent, then the optional pointer-width return length, then validates
the process handle. Only the defined record is written. Return length is
published after output, so aliases overwrite its low pointer field. Class or
short-length errors leave both destinations untouched. Native destination
faults are returned as NT statuses, consuming one-shot guards without SEH.

WoW64 first probes the optional 4-byte return-length destination. Its fault
consumes a guard and disables later length publication without replacing the
query status. It then checks class/length/address and process state before
copying the converted record. Output alignment is unrestricted; null output
skips copying while retaining the kernel result. Only 28/12 output bytes are
touched, irrespective of a larger supplied length. If the length destination
shares the output guard page, the first probe consumes that guard, disables
length publication and allows the output copy to succeed. A valid length
alias is published last; a faulted shared-page length alias retains the output
field instead. Separate output/length guards are both consumed and return the
output guard status. Original byte captures distinguish these cases.

Defined lengths are 28/12 on kernel success, handle errors and a class-6
free-address error, provided the preliminary optional probe succeeded. Early
class, short length, upper-bound and output-copy error length bytes are outside
defined-field fidelity; the implementation preserves them. The earlier
first-output-guard assumption is falsified by the native shared-page captures;
`discarded-guard-expectation.log` records that abandoned expectation and is
excluded as regression proof. `guard-shared-page-before.log` uses the observed
WoW64 success/data contract and is the actual regression capture.

The current-process pseudo-handle or typed current-process handles with
`PROCESS_QUERY_INFORMATION` (0x400) or `PROCESS_QUERY_LIMITED_INFORMATION`
(0x1000) are admitted. `PROCESS_VM_READ` (0x10) alone is insufficient. Invalid,
closed, wrong-type and denied handles return explicit NT statuses. Other
processes and other declared information classes remain explicit unsupported
frontiers. Enum values at or above pinned `MaxMemoryInfoClass` (15) return
`STATUS_INVALID_INFO_CLASS`; implementing classes 0/6 does not imply support
for the other private classes.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| V1 | The guest VM owns queried address/region/image state | Existing allocation/page-run ownership and whole PE mappings | Class 0/6 output; no target read | Guarded/noaccess target, free/reserved/mapped/image, image interior, changed page protections | Compare query fields with actual allocation transitions and native unsigned image oracle | Confirmed current mapping model; new partial/noexecute mappings require extension |
| V2 | Build29683 observations define the private ABI profile being implemented | Independent original ARM64/x86/x64 experiments and pinned declarations | Alignment, length, pointer/fault/guard/alias order | Two guards, shared-page aliases, null output, cross-page prefix/extent, huge SIZE_T | Run retained original oracles on another kernel/build and compare defined fields | Revised: optional length preprobe and shared-guard success confirmed; other builds/physical Intel unknown |
| V3 | Unverified guest images must report UNCHECKED with no uncreated extension | Current loader has no guest integrity decision or kernel CFG/SCP extension owner | ImageFlags zero for current complete executable mappings | Signed installed DLL versus unsigned original image; unmodified trust field | Find a guest trust-verification or image-extension mapping owner, or introduce partial/noexecute mapping | Confirmed current owners; wider native integrity/CFG remains incomplete |
| V4 | A query admits only the caller's process and effective query rights | Existing object table, PID and native rights oracle | Typed/access-checked handles; explicit remote frontier | Query-limited, VM-read-only, wrong type, closed and other PID | Native rights matrix plus guest object-lifetime/rights tests | Retained bounded process model |

| Plane | Effect or unchanged ownership evidence |
|---|---|
| Runtime/kernel/memory/objects | Appended service delegates to existing VM/RegionInfo/object table; no second map or host query adapter |
| ISA/direct/SMIR/JIT/backend | No decoder, executor, architectural CPU state, IR, optimizer or lowering source change; existing service boundary/argument transport is exercised |
| C ABI/dependencies/defaults/persistence | No stable C layout/status/feature/schema/lock/pin change; ordinary Rust module source membership |
| Assist tool/UI/context/agent/history | Internal NT service; existing process option/result/worker paths and discovery schema/copy unchanged |
| Permission/MCP/mesh/transport/crypto | Existing installed-runtime selection gate; no host forwarding, new capabilities or transport behavior |
| Windows/macOS/Linux/products/tests | Shared kernel model compiled and run on all three hosts; actual installed Windows NTDLL leaves tested separately; owning Assist Rust archive and production C++ adapter/factory/ABI/link checks required on each host |
| Release/package/optional engines | No package scripts/resources/native names/Z3/JIT defaults changed; complete native IDA/application/package matrix remains overall-goal work |

For A allocations, R state runs within an allocation, and P supplied output
pages, basic query costs O(log A + log R + R) time in the existing run scan;
image lookup costs O(log A). Native extent probing costs O(P) until its first
fault and allocates no buffer proportional to guest `SIZE_T`. Serialization
uses O(1) space (at most 48 bytes). WoW64 touches a fixed output prefix and
optional 4-byte return length.

Original probes, raw CRLF logs, primary source notices, independent checker and
red/green records are identified by SHA-256 in `sources.json`. Native leaf,
complete library/C API and current owning-archive results are recorded in
`src/user/windows/native-runtime.md`. No DLL/PDB/binary dump is redistributed.

High-impact blocking work remains production native loader/RTL heap/CRT entry,
wider NT section/security/registry/query services, guest CFG/SCP/integrity
model, broader POSIX/process behavior and the full application/package/native
IDA matrix. Medium: private WoW64 error length bytes and other Windows builds
are outside the defined profile. Low: additional valid memory information
classes offer later diagnostics; no unrelated class is silently stubbed.
