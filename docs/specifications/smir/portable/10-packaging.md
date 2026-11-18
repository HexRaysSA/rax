# Containers, launch and embedding

Status: candidate compiler/runtime contract. Exact container discovery and host
C23/C++23 declarations have independent witnesses. Installed/embedded launch and
production C API exports remain subsequent implementation gates.

Candidate ordered records: [runtime schema](schema/runtime/candidate.json).
Legacy local discovery fixtures retain [package](schema/runtime/package.schema.json)
and [carrier](schema/runtime/carrier.schema.json) schemas; these are not executable
profile-0.2 payload roots or semantic admission.
Reference extraction is file-based and never maps host executable memory.

## Carrier discovery and locator

PACK-001: `.smo` and `.smi` are format-independent SMIR payloads. Native wrappers
have truthful x86-64/AArch64 bootstrap machine headers. Link portable objects
first; stock native linkers do not resolve SMIR relocations. The payload digest
covers exact linked payload bytes, independent of native addresses/signatures.

Every native carrier has exactly one project locator. Its private draft revision
is 1; it does not make legacy envelope revision 0.1 executable or allocate opcode IDs.
All locator integers are unsigned little-endian with no host alignment.

| Offset (B) | Size (B) | Field | Required value |
|---|---|---|---|
| 0 | 8 | magic | ASCII RAXSMIR followed by one zero byte |
| 8 | 2 | revision | 1 |
| 10 | 2 | flags | 0 |
| 12 | 4 | reserved | 0 |
| 16 | 8 | file_offset | absolute payload byte offset in complete file |
| 24 | 8 | byte_length | nonzero exact payload length |
| 32 | 32 | sha256 | SHA-256 of payload bytes |

Size: `8+2+2+4+8+8+32 = 64 B`. Compute offset+length in mathematical integers,
require endpoint <= file length, and forbid overlap with the locator. No virtual
address, RVA or section-relative offset is accepted as file_offset. Validate
carrier bounds/permissions and unique candidate, then locator size/version/
reserved/range, then digest, then envelope framing, semantic verification and
execution admission. A correct digest of invalid SMIR remains invalid. A digest
identifies bytes and does not authenticate a publisher or grant capabilities.

| Carrier | Exact authoritative discovery |
|---|---|
| ELF64 LE | PT_NOTE entry, owner bytes RAXSMIR NUL (namesz=8), vendor-local proposed type=1, descsz=64 locator; payload in a PF_R-only PT_LOAD; .smir section optional after stripping |
| thin Mach-O64 LE | LC_SEGMENT_64 named __SMIR, section __module, regular type/flags=0, first 64 section bytes locator; segment maxprot=initprot=VM_PROT_READ; payload inside a read-only file segment |
| PE32+ LE | .smir section, IMAGE_SCN_CNT_INITIALIZED_DATA + MEM_READ, no MEM_EXECUTE/MEM_WRITE/MEM_DISCARDABLE; first 64 raw section bytes locator; payload in read-only raw section storage |

ELF note name/descriptor ends align to 4 B with zero padding. Program-header
entry size is 56 B, ELF header 64 B; extended PN_XNUM and non-little-endian/ELF32
wrappers reject in this draft. Section headers may be absent, so stripping them
does not destroy discovery. Mach-O header is 32 B; LC_SEGMENT_64 is 72 B followed
by 80 B per section, load command sizes multiples of 8 B. Fat/universal Mach-O
requires selecting a unique native slice in a separate declared packaging
profile; the present thin profile rejects it. PE uses DOS e_lfanew, PE signature,
PE32+ optional header and 40 B section records; long COFF string-table section
aliases are not a discovery substitute for the literal .smir name.

Machine values checked are ELF EM_X86_64=62/EM_AARCH64=183, Mach-O CPU_TYPE_X86_64=
0x01000007/CPU_TYPE_ARM64=0x0100000c, and PE AMD64=0x8664/ARM64=0xaa64. A carrier
extractor may inspect either bootstrap architecture regardless of host. Native
launch additionally requires matching host machine/OS and OS loader acceptance.
The primary structure definitions are archived LLVM
[ELF.h](references/llvm-project/llvm/include/llvm/BinaryFormat/ELF.h),
[MachO.h](references/llvm-project/llvm/include/llvm/BinaryFormat/MachO.h) and
[COFF.h](references/llvm-project/llvm/include/llvm/BinaryFormat/COFF.h).
The locator and vendor-local ELF note type are project proposals, not values
prescribed by those headers.

Check every offset/count/product before slicing, reject duplicate candidates
including identical duplicate locators, reject overlapping writable/executable
load aliases covering payload bytes, and never scan arbitrary file bytes for
magic as a discovery fallback. Native metadata must be well-formed for the
supported discovery slice; full native-loader validity is a separate check.
The synthetic fixtures test discovery, not signed/loadable native bootstraps.
The reference scanner caps program/load/section counts at 4096 and accepts only
the above profiles. Carrier extraction is O(headers + note bytes + payload hash)
time and O(payload bytes) copy space; no guest/native execution follows.

## Launch forms and runtime selection

PACK-002: The exact revision-1 `runtime_launch` sidecar is separate from the ten
executable sections: launch/carrier/bootstrap architecture, explicit personality/
foreign ISA, canonical artifact, actual self-entry, optional locator, runtime
selection tuple, required capabilities and embedded module list. Accepted R036
ordered fields are in runtime schema; launch.py verifies actual identity/runtime
facts, and candidate witnesses exercise acceptance/rejection boundaries.
Raw explicit payload has no native locator. A native carrier's locator hashes the
exact envelope bytes; this payload SHA-256 differs from the domain-separated
artifact identity whose manifest identity field is zeroed. Both are checked.

| Launch form | Entry sequence | Host condition |
|---|---|---|
| explicit RAX | supplied immutable bytes -> discovery -> all-root verification -> admission -> CRT | selected RAX host; wrapper/foreign ISA need not equal host |
| installed launcher | OS loads truthful bootstrap -> installed runtime selection -> negotiation -> verified admission -> CRT | bootstrap architecture and OS match host |
| embedded executable | OS loads included runtime -> exact runtime/deployment identity -> all-root verification -> CRT | included runtime matches bootstrap/host |

An object has no launch entry. An image's entry exactly matches admitted manifest
self-entry and the CRT signature in [06-linking-runtime.md](06-linking-runtime.md).
Personality and foreign ISA agree in launch/module/process; host OS never chooses
guest personality implicitly. A process may contain portable SMIR and one foreign
ISA, with multiple qualified native ABI domains of that ISA.

PACK-003: Installed discovery order is explicit caller absolute path, bootstrap-relative
installed location, administrator absolute installation record. The first
configured candidate is authoritative: missing/incompatible/malformed selection
fails without opportunistic fallback. There is no cwd, PATH, environment-library-
path or network lookup. Canonicalize path and retain an immutable open/loaded image
through verification and use, preventing path replacement after identity checking.

Runtime selection checks host OS/architecture, ABI major equality, minimum minor/
implementation revision, optional exact implementation identity, executable profile
2, exact helper/service catalog identities and pinned compiler/library baseline
identity. Required capabilities must all be independently configured/granted and
supported. Embedded launch requires exact implementation identity and the complete
ordered unique admitted deployment module list. A host file cannot register its
own capability, helper or native ABI certificate. Failure returns structured
stage/identity/version information before constructors. Successful framing or
SHA-256 equality cannot replace semantic admission.

The pinned compiler/library baseline and known upstream C23/C++23 gaps are defined
in [09-llvm.md](09-llvm.md). Runtime/profile compatibility is explicit; a version
number alone cannot certify a different helper, personality or library contract.

Native linking retains read-only nonexecutable payload/locator content under dead
stripping. Native linkers do not resolve portable relocations: portable linking and
verification precede wrapping. Strip/debug processing cannot remove authoritative
discovery headers. Finalize locator/hash before native codesign/Authenticode;
rediscover and compare exact payload after every native tool mutation. Signing
checks native publisher/loader policy and does not authorize malformed SMIR.
The synthetic carrier witnesses do not establish loadable/signed executables.

## Exact host C ABI declarations

PACK-004: [rax_portable_contract_v1.h](../../../../tools/smir-runtime-contract/include/rax_portable_contract_v1.h)
contains the 21 candidate exported declarations and callback typedefs. It defines
an additive host ABI, not changes to existing rax.h layouts/enums. Fixed-width
integers, 64-bit host pointers, `extern "C"` and C++ noexcept govern this interface;
host data model is not the portable guest source ABI. All statuses are 0 success
or positive portable errno. Runtime exports contain their own panics internally
before C/JIT boundaries; guest C++ exceptions retain their own typed ownership.

| Host structure | Size B | Important layout |
|---|---|---|
| RaxPortableHandleV1 | 24 | instance,slot,generation u64 at 0,8,16 |
| RaxPortableBytesV1 | 16 | data pointer at 0, length u64 at 8 |
| RaxPortableBufferV1 | 24 | data pointer,capacity,written at 0,8,16 |
| RaxPortablePollV1 | 56 | size/version at 0/4, state at 8, result at 24, error/reserved at 48/52 |
| RaxPortableHostImportV1 | 64 | size/version,name,descriptor,call,release,user |
| RaxPortableConfigV1 | 112 | size/version, five u64 worker/quotas, profile/personality, grants/count, imports/count |

Structures have alignment 8 B. Size/version are exact `sizeof` and 1; reserved
fields are zero. Unknown version/size rejects before accessing later fields.
Config includes explicit worker/memory/stack/atomic/code quotas, counted profile/
personality, sorted unique recognized capability grants and independently admitted
host imports. Empty grants means none, not an implicit default. Input lengths and
capacities are byte counts; null buffer is valid only for length/capacity zero.
Caller input bytes are borrowed only for the call, then copied/owned internally.
Poll output state is a borrowed immutable token while its request/API image is
retained. Owned output handles require release. A returned error leaves output
fields unchanged, except the documented buffer-size query/ERANGE written field.

| Operation | Exact purpose |
|---|---|
| context_create | validate/copy immutable config, grants and host descriptors |
| module_verify | copy immutable bytes and all-root verify; no guest execution |
| process_create | bind module/deployment/spawn and process personality; no main yet |
| process_run | one image CRT/main request, exactly once |
| symbol | module export lookup -> unbound verified code locator |
| value_bits | exact concrete scalar bits of actual module type; no pointer factory |
| value_aggregate | exact aggregate type/elements, one coherent process binding |
| value_pointer | checked nonnegative offset from an existing issued data_ptr VALUE |
| start | bind code locator/value to process and start a fresh logical guest thread |
| poll | nonblocking pending/returned/raised/exited/failed observation |
| cancel | report won-before-effect u32=1 or deferred/terminal u32=0 |
| call_result_bits | private call-bound scalar result factory for a registered host callback |
| call_return | validate full typed callback result vector, prepare private completion |
| host_complete | consume one pending callback completion, no duplicate publication |
| result_count / result_at | inspect retained typed result vector; result_at owns new value handle |
| value_read_bits | read concrete scalar/raw origin-free bits; no guest memory access |
| process_join | close/drain library process or observe image main/process exit |
| record_read | canonical diagnostic/exit JSON, never authority or restore data |
| retain / release | generation-checked owned reference operations |

`value_bits` validates exact bit width/high unused bits and only int/float/raw
origin-free concrete values. Opaque handles, data/code pointers and aggregate types
reject. Aggregate factory validates actual execution shape, element types and one
process binding for pointer-containing components; it never rebinds foreign source
object identity. `value_pointer` requires a live existing data_ptr value from a
guest/service, preserves object/generation/range, checks offset/one-past without
wrap and returns EBADF for stale/dead authority. Null permits only offset 0.
A numeric or host-pointer value cannot create guest provenance.

`symbol` returns an unbound locator to the actual verified artifact/export/source
ABI. `start` resolves it through the process's admitted generation, dependency and
selected function map. A returned guest code_ptr is already process/generation
bound and can enter only that process. Context-owned scalar values are unbound;
pointer-containing aggregates retain the appropriate single process. Immutable
module handles may be shared by processes with distinct object/token registries.

Buffer read operations set required `written` size. Capacity 0 is a size query;
insufficient capacity returns ERANGE with required size and no partial payload.
`record_read` emits canonical ASCII JSON: version,reason,code,thread,trap option;
reason normal/signal/abort/trap/failed/exception, code full guest i32 for exit or
positive errno for failure. Text is diagnostic only. Raised exception results are
owning process owner-proxy values, not expired throw-thread opaque E handles.

## Ownership, callbacks and process lifecycle

A handle is a registry token `(runtime instance,slot,generation)`, never a host
pointer. Wrong instance/kind/generation or stale/double release returns EBADF.
Counters never wrap. Parent release drops its host reference; child/process/
request/TLS/object/code/exception/callback leases retain the actual resources.
Finalization that cannot complete returns EBUSY without consuming the caller's
handle. Shutdown closes admission, drains work and reclaims only unreferenced
module/code/storage generations.

Each `start` creates a fresh logical guest thread, independent of calling host
thread/worker: errno 0, default fenv and explicit process diagnostic policy. For a
library, the first entry claims once-only initialization on that same thread;
concurrent first entries wait publication. An image's generic start returns EBUSY
until CRT begins; process_run creates its sole main once. Root request return/
raise runs that guest thread's TLS cleanup before terminal request publication.
Module statics remain until process shutdown. Returned TLS pointers may tombstone.

Custom host imports are scalar-only application primitives with immutable
`runtime_host_descriptor`: actual canonical execution graph, signature and
namespace/name/version, domain-separated SHA-256. Signature contains only scalar
int/float/origin-free raw; it cannot override smir.* runtime services, transfer
guest buffers/pointers/opaque values or bypass foreign descriptors. Noundef input
poison/undef traps; otherwise only unknown bits refine to zero, retaining known
bits. Callback result factories validate exact call/index/type/arity before one
publication. Unknown or malformed statuses reject. Native callback providers must
contain exceptions/panics INSIDE their no-unwind callback shim and return EIO.
A C++ throw crossing this noexcept callback terminates before an outer runtime
catch; a Rust extern-C panic can likewise abort. The Python reference's catch
models a valid containing shim, not recovery from invalid native unwinding.

During synchronous callback dynamic extent, same-context start/process_run/join
or any waiting guest-entry operation returns EDEADLK before guest code. Poll,
cancel, scalar result factories, host_complete and nonblocking retain/release are
allowed. After returning pending, external host control may start another fresh
guest thread, never reenter the suspended original activation. Borrowed argument
handles last through callback; explicit retain extends lifetime. Callback entry
marks its ticket irreversible; later cancel is deferred. No runtime lock is held
across callback code. A host release callback runs once when registration's last
lease drains, outside registry locks, and cannot throw across C. For example a
C++ callback uses `try { ... } catch (...) { return 5; }` inside its noexcept body;
a Rust callback uses catch_unwind inside extern-C before returning status.

A raised request may be terminal while process shutdown remains pending. Its
HostOwnerLease retains the process-owned payload/destructor/type/module/code after
the throwing guest thread ends. Last release queues a derivative guest cleanup
activation; it never invokes guest code on the host release stack or during a
forbidden callback reentry. Public process EXIT waits for owner-dependent cleanup.
Closing/finalize remains pending/EBUSY while host owners exist; there are no guest
destructor effects after public EXIT. Library join closes starts and drains active
requests, TLS and owners; image join observes main exit. Pending host completions
after closing drain private buffers without late guest copyout. R026 revision 7
records this accepted lifecycle; current combined witnesses precede freeze.

## As implemented

`crates/smir-portable` finds the payload of a carrier as PACK-001 says
(`carrier::find`): one locator where the format puts it, the checks of the
native headers that the reference scanner makes, a payload inside what the
loader maps for reading only and inside nothing it maps otherwise, and the
digest. The fourteen fixtures of `conformance/runtime/carriers` are found
or refused as they say, with the codes they name. Nothing is mapped or run
by this, and a file that begins like a carrier is never taken for a payload.

| Question | As implemented |
|---|---|
| Explicit launch | `smir-run` takes an object or a carrier of one. A carrier's payload goes through framing, verification and lowering like an object handed over directly; the carrier's machine is not compared with the host, since nothing native is run from it. |
| Wrapping | `smir-pack PAYLOAD --carrier elf\|macho\|pe --machine x86-64\|aarch64 -o FILE` writes a carrier that holds the payload and no code: the headers discovery needs, and for the rest zeros. The payload is verified and lowered first, so only an object this runtime can run is wrapped. `--extract` and `--show` are the reverse. Such a file is what the fixtures are, a payload in the dress of a native file; the system's loader has nothing to run in it. |
| Carriers a native linker makes | `smir-pack PAYLOAD --section` writes what the linker is given as the payload's section: the payload behind a locator that has its length and digest and not yet its place. `smir-pack --seal FILE` writes the place into the locator of the linked file and checks that the payload is then found. This is PACK-001's order: the locator is final before the file is signed. |
| Embedded launch | An executable with the runtime and one module in it is the launcher of `crates/smir-portable-capi`, that crate's static library and the module's section, linked by the system's linker (`tools/smir-clang/smirpack.py`). Started, it reads its own file and hands it to the runtime, which finds the module as in any carrier, verifies it and runs it as an image. It is made for Mach-O so far: the section is `__SMIR,__module` in a segment of its own that is mapped for reading only, and the file is signed ad hoc after sealing. The runtime identity and the deployment module list that PACK-002 asks of an embedded launch are not checked: the module is the one in the file, and the runtime the one linked with it. A program that depends on other modules has each of them in the executable as well, as it is, in a section beside the program's (`__SMIR,__needs0`, `__needs1`, and so on), which the launcher reads from its own mapped image, verifies and links with the program before the process is made (chapter 06, "Linking as implemented"). Only the program is behind the locator; `smir-pack --section --library` refuses, before anything is linked, a program that does not link with the modules it is to be packed with. |
| Installed launch | Not implemented. |
| The host C interface | `crates/smir-portable-capi` exports the 21 functions of PACK-004 from a static library. Sixteen of them work. Those of an image's life: `context_create`, `module_verify`, `process_create`, `process_run`, `poll`, `cancel`, `process_join`, `record_read`, `retain`, `release`. And those of a library's: `symbol`, `value_bits`, `start`, `result_count`, `result_at`, `value_read_bits`; a process that is called lasts from its first call, which runs the module's initializers, to `process_join`, which runs its finalizers. Values are integers and floats; `value_aggregate` and `value_pointer` return `ENOSYS`, as do the three functions that answer host imports, of which none is accepted. The calls of one process run one after another on its first guest thread, where the specification gives each a fresh one. A handle is a slot of the runtime's table and the generation of its use; `EBADF` for any other. The spawn record may name its module by 32 zero bytes, the host having no way to learn a module's identity from this interface; it may ask for no environment, working directory or inherited handles. A context's processes get files by an extension function, `rax_portable_x1_context_files`. Modules are linked into one program by another, `rax_portable_x1_module_link`, whose result is a module like any other; a module that depends on others is verified by `module_verify` and refused by `process_create` with `ENOEXEC` until it is linked. The `runtime_deployment` record is not read. |

## Evidence boundary

`candidate/capi_probe.py` checks declarations and static layouts for Linux/macOS/
Windows x86-64/AArch64, each in C23 and C++23 mode. These 12 compile-only probes
are not linked consumer ABI, exported implementation, callbacks, native launch or
host qualification. Carrier tests cover authoritative file discovery, duplicate/
corrupt locator rejection and byte equality, not real strip/sign/load pipelines.
Production packaging, runtime C exports, six-host bootstraps and full qualification
are subsequent explicit implementation gates.

Assumptions: carrier bytes and selected runtime remain immutable after identity
checking; stress by duplicate, writable alias and path-replacement tests. Actual
host registrations independently supply support/grants; stress mismatched profile/
catalog/baseline and stale handles. High impact: a locator cannot admit executable
semantics. Medium opportunity: immutable modules can serve many isolated processes.
Low limit: cross-target syntax/layout witnesses do not establish OS-loader success.
