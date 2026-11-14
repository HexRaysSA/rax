# Guest instruction-cache synchronization

At the published `ae14f89b` runtime, the independent AMD64 thread program exits
zero natively and exits 125 in emulation at installed `NtFlushInstructionCache`
(`0xf0`). The native entry has three pointer-width arguments: process handle,
base address and byte length. The x86 entry ends with `RET 12`. The appended
synthetic export preserves earlier ordinals and trap addresses. Built-in
`KERNEL32` and `KERNELBASE` retain their existing Win32 export slots and share
the NT implementation's measured policy.

## Independent observations

`native-oracle-v1.c` calls the installed NT and Win32 APIs against its own
process and private allocations. Its matrix covers pseudo, invalid, closed,
event, thread and real process handles; individual process access bits;
tagged handles and a high carrier; null, mapped, reserved, unmapped, protected,
guarded and noncanonical addresses; exact user-probe boundaries; and fifteen
byte lengths. Three separately restored guards distinguish the first reached
guard from later guards. No generated native code is executed.

The retained campaign runs on Windows `10.0.29698.0` ARM64:

| Caller | Handles | Addresses | Lengths | APIs | Calls |
| --- | ---: | ---: | ---: | ---: | ---: |
| ARM64 | 32 | 24 | 15 | 2 | 23,040 |
| AMD64 translated | 32 | 24 | 15 | 2 | 23,040 |
| x86 translated | 31 | 24 | 15 | 2 | 22,320 |

`23,040 + 23,040 + 22,320 = 68,400` calls. All three producer processes exit
zero without stderr or a handle-count change. Installed libraries and producer
images retain their identities. The corpus records raw-output hashes, source
hashes, executable identities and the native entry bytes. A bounded palette
encodes each pair of NT/Win32 outputs without losing status, DOS error,
last-error or guard-mask information. The native matrix is independent of the
guest implementation.

The measured native64 order is:

1. A nonnull base with zero length succeeds without checking the handle or
   touching pages, including noncanonical bases.
2. For a nonnull, nonempty range, checked addition and the exclusive user-probe
   limit `0x7fffffff0000` precede handle checks. An end equal to that limit is
   admitted; overflow or a greater end returns `STATUS_ACCESS_VIOLATION`.
3. The current-process pseudo-handle is admitted. A real process handle requires
   `PROCESS_VM_WRITE` (`0x20`); other object types and invalid handles retain
   their native error classes. Low two handle tag bits are accepted; unrelated
   high carrier bits are not.
4. A null base ignores its length and requests whole-process synchronization,
   including length zero. It still validates the handle and visits no guarded
   data pages.
5. A valid nonempty range succeeds for inaccessible or absent mappings. At most
   its first reached armed guard is consumed, while the call still succeeds.
   Later guards remain armed. NT calls preserve last-error; Win32 failures
   publish the corresponding DOS error and successes preserve last-error.

The captured x86 path ignores all three arguments and succeeds without consuming
any guard, including invalid handles and overflowing ranges. This is measured
behavior, not an inferred consequence of cache coherence.

## Native AMD64 build 20348

The independent Windows 2022 CI campaign captures native AMD64 kernel
`10.0.20348`, with 23,040 x64 calls and 22,320 x86 calls:
`32 * 24 * 15 * 2 + 31 * 24 * 15 * 2 = 45,360` calls. Every NT result is
`STATUS_SUCCESS`; every Win32 result is true and preserves the initial
last-error. All three guards remain armed, including invalid handles,
noncanonical addresses, overflowing lengths and null-base requests. This differs
from the ARM64 host's native64 validation order above.

[The immutable corpus](observations-amd64-20348-v1.json) preserves every result
palette and case selection. [Its provenance](amd64-20348-v1.json) binds the raw
reports, producer inputs, executable identities and
[primary CI artifact](https://github.com/HexRaysSA/rax/actions/runs/43403677135/artifacts/14026812098).
Native producer PID and birth information is unknown: the collector does not
emit it. Successful producer exits follow from its checked subprocess calls
completing before the corpus is written; this is a control-flow inference.
The unchanged before/after handle counts and empty stderr are retained directly.

The new x64 policy selects only native `(10, 0, 20348, AMD64)`, independently of
guest-visible version spoofing. It ignores the three arguments and publishes a
bounded whole-guest code-change epoch. Two thread CPUs must observe untracked
code updates even when the request has an invalid handle and noncanonical base
with zero length. No guest handle or pointer reaches a host API. The existing
x86 path and other native64 reference behavior remain unchanged. This corpus
does not qualify build 26100 or other unmeasured native kernels.

Replay binds fresh corpus identities to `NativeRuntime` before dispatch, rather
than applying every host's observations to the portable ARM64 reference fixture.
The historical ARM64 corpus predates `native_machine` metadata and retains its
existing portable reference personality. Every default replay also checks all
45,360 AMD64 cases, in addition to the 68,400 retained ARM64-host cases.

Verify both the retained AMD64 projection and every raw row in the downloaded
primary artifact on any host:

```text
python docs/specifications/windows/native-instruction-cache/check-amd64-20348.py
python docs/specifications/windows/native-instruction-cache/check-amd64-20348.py --archive PATH_TO_ARTIFACT_ZIP
```

## Guest implementation

Guest handles and addresses never reach a host cache or process API. Successful
requests publish an explicit `AddressSpace` code-change epoch. Cached x86 CPUs
apply those invalidations before their next user entry; interpreted ARM64 CPUs
fetch current bytes. Full-process requests use the existing bounded full-cache
fallback instead of walking the numeric address range. A nonnull zero-size
request changes neither guards nor epochs on native64.

Actual allocation/state runs locate the first guard; reported protection does
not authorize or suppress its consumption. The search takes O(A log R + Rv)
time and O(1) scratch for A visited allocations, R state runs per allocation and
Rv visited boundaries. It neither populates private frames nor allocates memory
proportional to caller length. Cache-log storage retains its existing fixed
bound. The service changes no guest bytes, handle ownership or commitment.

The replay tests execute every recorded NT case through native-service dispatch
and every Win32 case through the shipping export implementation. Additional
tests check ordinal stability, unused x86 argument slots, explicit unsupported
peer-process handling, actual versus reported guards, huge sparse spans and
whole-cache guard preservation. Two thread CPUs execute independently specified
instructions before and after an untracked physical code update and explicit
range or whole-process synchronization.

## Reproduction and evidence limits

Verify the retained producer identities on any host:

```text
python tools/ci/windows_instruction_cache.py --verify-corpus
```

On native Windows with CMake and Visual Studio, acquire fresh controls and replay
them with the current guest implementation:

```text
python tools/ci/windows_instruction_cache.py
```

The runner creates its output and temporary files inside the checkout. ARM64
hosts run all three caller views; AMD64 hosts run their native and x86 views.
Fresh outputs and executable identities are retained, while completed native
build trees are removed. Existing CI verifies retained inputs on every host
and runs the acquisition/replay campaign on Windows. Source verification alone
does not prove native behavior or guest execution.

Fresh acquisition builds `producer-v2/`. Its error helper explicitly never
returns, and its invalid-address branch has no statement after that helper.
This avoids MSVC Release warning C4702 under the unchanged `/W4 /WX` policy.
The native case matrix and output schema are unchanged. The original
`native-oracle-v1.c`, `CMakeLists.txt`, and retained observations remain frozen
because the retained campaign records their exact identities. Fresh corpora
record version-two normalized and raw producer hashes, and keep the retained
producer hashes separately in `retained_source_hashes`.

Assumptions: the three-argument service and x86 cleanup are confirmed by native
entries and controls. Cache synchronization is checked by guest execution rather
than inferred from a successful scalar return. Native observations cover the
recorded ARM64 kernel and translated callers, plus the separately identified
native AMD64 build 20348 corpus above. Other kernels require their own native
results. These results do not establish complete
ordinary-process support. For profiles that validate process handles, a writable
handle to another modeled process retains an explicit unsupported result until
guest process supervision provides its address-space owner; denial paths and
unrelated current-process behavior remain
implemented.

The public C ABI, persisted layouts, host permission model and Assist private
ABI are unchanged. [Microsoft's Win32 API contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache)
owns the documented null-base and byte-length interface.
[PHNT's native declaration](https://github.com/winsiderss/phnt/blob/master/ntmmapi.h)
supplies the native signature. Observations above own status, guard and ordering
claims; neither documentation nor another implementation substitutes for them.
