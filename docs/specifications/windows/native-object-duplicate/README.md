# Same-process `NtDuplicateObject` on Windows ARM64 build 29704

The original AMD64 startup reached the installed NTDLL service with current-process
pseudo handles as both process arguments, the current-thread pseudo handle,
desired access `0x4a`, attributes `0`, and options `0`. Native Windows returned
an independent handle to the calling thread with grant `0x184a`. The service
now models that contract in the guest object table.

The admission predicate is native machine `0xaa64` and kernel `10.0.29704`.
ARM64, AMD64 and WoW64 x86 callers use the same policy. The source can be the
current thread/process pseudo handle or a concrete handle to a guest-owned
thread, current process or event. Real process arguments require
`PROCESS_DUP_HANDLE`. The prior same-access path remains available for other
objects and builds. No code calls the host kernel for duplication or transfers
native handle numbers, host privileges or kernel object identities.

The selected non-closing options are `0`, `2` (same access), `4` (same
attributes), `6`, and `0x10` (same result as `0` in this capture). Attributes
`0x1` and `0x2` set protection and inheritance respectively; `0x200` has no
observed user-mode effect. Same-attributes copies the source flags and
same-access copies its grant. Otherwise the request is mapped for the object
class, and `MAXIMUM_ALLOWED` does not expand the grant. The source handle and
its flags remain intact. Thread and process `ACCESS_SYSTEM_SECURITY` alone
returned `STATUS_PRIVILEGE_NOT_HELD`; the owned event received that bit in the
guest grant. The latter supplies no host security operation.

A non-null destination can be unaligned; the guest probes the entire
pointer-width span before handle validation or allocation. Observed handle and
access failures publish zero through a valid destination. Null output still
opens a guest handle on success, which remains owned by the process table
until closed or drained at exit. This change does not select foreign process
ownership, close-source operations, other option bits, or other object grants.

`matrix-v1.cpp` produced 3,500 non-closing observations per ABI, with 3,050
successful handles queried and closed and the parent count unchanged.
`bits-v1.cpp` produced 370 more rows per ABI, covering all 32 individual
access bits and mixed requests; 291 handles were queried and closed per ABI.
`boundaries-v2.cpp` ran 48 isolated child cases and 24 warmup children per ABI;
all exited naturally and all parent process/thread handles were closed. The
warmup took the one-time process-creation handle count changes before the
measured baseline. Close-source cases were included only to distinguish them
from the non-closing contract: in the observed successful replacement the
numeric handle value could be reused with the new grant. WoW64 and native
64-bit callers differed when closing a source and faulting on output.

Build each producer as a console executable for ARM64, AMD64, and x86 with the
Windows SDK and static CRT, using C++20. Run under the same Windows user on an
ARM64 machine with build 29704; require exit 0 and retain stdout exactly,
including CRLF. Both JSON fixtures name SHA-256 digests of the three native
stdout files. Each fixture row is `[source-index, desired, attributes,
options, status, grant, flags]`, using decimal integers; `null` means the
failed call returned no handle and no follow-up query was made. Native
pointer values, PIDs, TIDs, and numeric handle IDs are intentionally omitted.
The regression replays both fixtures and separately checks identity and
handle counts for every call through the real guest service dispatch paths.

The rights mapping is constant time and space. Finding the current process
object from its pseudo handle scans the guest object table; issuing a new
handle scans the contiguous used handle slots, with constant extra space.
