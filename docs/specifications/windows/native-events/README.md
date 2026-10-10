# Native NT event prerequisite, 2026-10-10

This record supports the installed-NTDLL `NtCreateEvent`, `NtSetEvent` and
`NtResetEvent` kernel implementations. All guest requests manipulate RAX's
process-local object table; no request invokes a host NT event service.
The selected ordinary Windows DLL startup remains incomplete.

## Provenance and experimental scope

[sources.json](sources.json) identifies exact retained bytes, SHA-256, source
URLs, retrieval dates and redistribution notices. Microsoft `ZwCreateEvent`
and `ZwSetEvent` document the user-mode `Nt` names. Their parameter meanings
and event reset semantics are public contracts. The native results below are
observations of Windows ARM64 10.0.29683.1000, with native ARM64 and x86/x64
compatibility executables built by VS2026 18.7.1; other kernel versions are
unknown. Each complete original probe/output is retained without reformatting.

`native-event-probe.cpp` deliberately declares the last creation parameter as
ULONG rather than BOOLEAN to probe its unspecified upper argument bits using
the same Windows ABI integer registers/stack slots. The kernel retains only
the low byte. It uses the SDK `PUBLIC_OBJECT_BASIC_INFORMATION` size for
`NtQueryObject` class 0; a preliminary 128-byte request was rejected with
`STATUS_INFO_LENGTH_MISMATCH` and was not used as a granted-access oracle.
The captured final query succeeds and reports `GrantedAccess` at byte offset 4.
The original `NtQueryEvent` calls are an independent observational oracle;
this group does not add an emulated `NtQueryEvent` implementation.

The private oracle account can obtain `ACCESS_SYSTEM_SECURITY`; its token and
privileges are not assumed to describe an emulated guest. RAX explicitly
rejects that privilege request, nonnull security descriptors, security quality
of service, and named NT object directories. No DACL, SACL, impersonation,
interprocess namespace or privilege result is manufactured.

## Recorded semantics

| Item | ARM64/x64 native entry | x86 WoW64 conversion |
|---|---|---|
| Handle output width/alignment | 8 bytes, byte alignment accepted | 4 bytes, byte alignment accepted |
| Output probe | Before event type and attributes | After attribute conversion |
| Invalid event type | `STATUS_INVALID_PARAMETER`, output unchanged | Same status; zero handle copied after successful conversion/output probe |
| Attribute layout | 48 bytes, 8-byte alignment required | 24 bytes, unaligned reads accepted |
| Invalid attribute Length | Status after output probe; full native structure probed | Status during conversion; no output probe/publication |
| Attribute guards with invalid type | Type rejected without consuming attribute guard | Conversion consumes guard first |
| Invalid flags or root with null ObjectName | Invalid parameter / object name invalid; output unchanged | Same status; zero handle copied |
| Guard pages | Consumed once, `STATUS_GUARD_PAGE_VIOLATION` | Same, subject to conversion order |
| State PreviousState | Optional unaligned 4-byte output probed before handle/type/access | Same |
| Wrong object type | `STATUS_OBJECT_TYPE_MISMATCH` before event access check | Same |
| State output fault | No event mutation | Same |

The Microsoft `ZwCreateEvent` page lists `STATUS_INVALID_PARAMETER_4` for an
invalid event type. The recorded user-mode build returns
`STATUS_INVALID_PARAMETER` (`0xC000000D`) on all three ABIs instead. RAX uses
this explicit recorded profile; it does not claim the private error priority
is a stable guarantee of every Windows version.

| Creation access request | Granted mask in the admitted one-principal model |
|---|---|
| Explicit standard/type rights | Request AND `0x001F0003` |
| `GENERIC_READ` | `0x00020001` |
| `GENERIC_WRITE` | `0x00020002` |
| `GENERIC_EXECUTE` | `0x00120000` |
| `GENERIC_ALL` | `0x001F0003` |
| `MAXIMUM_ALLOWED` | `0x001F0003` |
| `ACCESS_SYSTEM_SECURITY` | Explicit unsupported privilege model |

Generic mappings apply to creation of a new unnamed process-local event,
with null security inputs. They do not implement access checks for an existing
named event. The existing Win32 named-open security limitations remain.
`OBJ_INHERIT` sets the shared handle flag; other admitted flags are ignored
only where the recorded unnamed user-mode creation gives them no additional
object behavior. `OBJ_OPENLINK` and invalid flag bits return invalid parameter.

The signal state is a signed 32-bit LONG. Creation stores
`state = zero_extend_u8(InitialState)`; values 2 and 255 are preserved for the
previous-state output instead of collapsed to 1. Wait readiness is `state != 0`.
A synchronization event resets to 0 after one successful wait; a notification
event retains its state. Setting stores 1; resetting stores 0. Existing Win32
BOOLEAN callers still create states 0/1. The Rust-visible
`Object::Event.signaled` field consequently changes from `bool` to `i32`;
all in-tree constructors, consumers and patterns are updated. The stable C
ABI 1.11.0 and Assist process ABI do not change.

Attribute capture and grant mapping are O(1) time/space; opening a shared
handle is O(H) time and O(1) extra space for H open handles. Guest pointer
serialization is 4/8 bytes and PreviousState serialization is 4 bytes,
independent of the host pointer width. Failed publication closes the created
handle; allocation/validation failures leave no live event or handle.

## Assumption register

| ID | Assumption and basis | Dependent result | Stress / falsification | Status |
|---|---|---|---|---|
| E1 | Native and Win32 event APIs must share existing reference-counted objects and scheduler | Creation/state/close and waits | Native-created object through Win32 waits/state/close; any separate state or leaked object falsifies | Confirmed seven shared tests and installed ARM64/x86 leaves |
| E2 | Native BOOLEAN retains its low byte as LONG state | `signaled: i32`, readiness nonzero | 0/1/2/255/256/257/all-ones, manual/auto consumption, previous-state output; oracle disagreement falsifies | Confirmed all three oracle ABIs and shared tests |
| E3 | Recorded native64 and WoW64 fault/conversion order owns this private profile | Kernel probes and output publication | Null/unaligned/readonly/guard/alias, invalid Length/type/flags/root; differing recorded output falsifies | Confirmed supported unnamed/null-security partitions; other versions unknown |
| E4 | Existing object model has one principal and no token/ACL implementation | Bounded creation grants and explicit unsupported security paths | Privilege/named/descriptor/QoS requests cannot publish an object; an existing token adapter would falsify limitation | Retained source contract; security-path tests pass |

## Bounded findings

| Impact | Finding | Blocks full process goal? |
|---|---|---|
| High | Native NTDLL process initialization and RTL heap bootstrap remain absent; ordinary installed-DLL programs still fault | Yes |
| High | Named NT directory objects, security descriptors, tokens and privilege checks remain unimplemented | Yes for programs requiring them |
| Medium | `Object::Event.signaled` is a Rust source-level model change; external Rust consumers require 0/1 or LONG comparisons | Unknown external consumers; C ABI consumers unaffected |
| Medium | Linux full-suite host timeout/signal interference and Windows BZHI/FP16 failures are retained as failed evidence | Full test matrix is not green |
| Low | Existing scheduler source exceeds the 1,500-line soft ceiling; this change replaces one constructor field without crossing the hard threshold | No |

The original diagnostics label their zero-based run-slice index as `turn`.
Older ledger descriptions of 36/141 instructions refer to those indices,
not an independently measured retired-instruction counter. Each slice has a
one-instruction budget; the failing service attempt at turn 141 is the
142nd run-slice call. Complete validation and the new isolated loader stop
are recorded below after capture. A native leaf executing successfully is evidence of that leaf,
not evidence of complete `LdrInitializeThunk` or ordinary CRT startup.

## Complete validation and current frontier

| Surface | Result | Evidence |
|---|---|---|
| Regression | One native-create test fails before, passes after | `/tmp/assist-native-events-{before,after}-macos.log` |
| Seven shared event tests | Pass on all three host configurations; Windows adds installed ARM64/x86 leaf execution | Final full library logs below; `/tmp/assist-native-events-expanded-macos.log` |
| macOS full library | 7,478 passed, 0 failed, 2 ignored, 0 filtered | `/tmp/assist-native-events-complete-macos.log` |
| Linux full library | Final: 7,472 passed, 0 failed, 2 ignored, 0 filtered; earlier parallel run: 7,469 passed, 2 failed, 2 ignored, 0 filtered | `/tmp/assist-native-root-cpp-linux/native-events-{complete-full,full}.log` |
| Windows full library | 6,852 passed, 5 failed, 2 ignored, 0 filtered | `/tmp/assist-native-windows-29683/native-events-complete-final-full.log` |
| C API package | 168 passed, 0 failed, 0 ignored, 0 filtered on each OS | `/tmp/assist-native-events-capi-macos.log`; `/tmp/assist-native-root-cpp-linux/native-events-capi.log`; `/tmp/assist-native-windows-29683/native-events-complete-capi.log` |
| macOS owning Assist archive | Five production CTests pass | `/tmp/assist-native-events-root-macos-{build,ctest}.log` |
| Linux owning Assist archive | Tool 184 / adapter 162 / disabled factory / ABI 2/2 / archive linkage pass | `/tmp/assist-native-root-cpp-linux/native-events-{shipping,cpp}.log` |
| Windows owning Assist static-CRT archive | Tool 182 / adapter 162 / disabled factory / ABI 2/2 / archive linkage pass | `/tmp/assist-native-windows-29683/assist-native-events-complete-{shipping,cpp}.log` |
| Four ordinary installed-DLL startups | Smoke, MSVCRT streams, UCRT streams and system whoami still exit `0xC0000005`; no complete CRT startup proof | `/tmp/assist-native-windows-29683/native-events-complete-archive-output.log` |
| Formatting and source whitespace | Complete workspace formatting and owned source checks pass | `/tmp/assist-native-events-format.log` |

The earlier Linux failures were
`user::linux::tests::uring::timeout::a_multishot_timeout_reports_each_expiry`
(two completions when one was asserted) and
`user::readiness::tests::finite_empty_and_expired_waits` (host `EINTR`).
The subsequent complete run contains one additional interoperability test.
No Linux timing/signal implementation was changed, and the subsequent pass
is not evidence that those failures were fixed. Windows retains the same
four BZHI lowerer byte assertions and host FP16 execution failure.

The isolated native loader diagnostic now executes the `NtCreateEvent` SVC
at zero-based turn 141, observes success in X0 at turn 142, and returns to
NTDLL code. It next stops at turn 160 on unimplemented `NtManageHotPatch`
service `0x119`, guest PC `0x1800021D0`, with class 9, an 8-byte information
buffer and ReturnLength pointer. The recorded delta is 160 - 141 = 19
run-slice calls, each configured with a one-instruction budget; it is not a
retired-instruction or complete loader-initialization claim.
The before/after traces and exact original driver are retained here.

That driver clears only guest `PEB.ProcessHeap`, calls the selected native
`LdrInitializeThunk` with a saved modeled context, and retains the existing
thread-start continuation. It does not install native bootstrap into the
production lifecycle, demonstrate a valid RTL heap, or prove the exact
kernel-created initial-thread entry contract. Native DLL/PDB binaries are
not included. The initial ordinary-startup heap fault remains separately
recorded under `../native-processor-features/`.
