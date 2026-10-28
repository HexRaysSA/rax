# Native memory prefetch

[Documentation entrypoint](../../../../README.md)

`NtSetInformationVirtualMemory` class0 validates a list of guest address ranges
and accepts memory-prefetch advice. Flag1 performs best-effort population of
accessible committed guest pages. It preserves protection, guard, commitment,
object handles and input bytes. No guest address, process handle, range, flag or
service number is passed to a host kernel operation.

The motivating installed ARM64 CMD call uses its current-process pseudo-handle,
class0, one range at `0x1113000` of 4096 bytes, a four-byte information record,
and flag1. Read-only stopped-process inspection identified that allocation as
committed private `PAGE_READWRITE`. Its service number on kernel10.0.29695 is
`0x1B0`; the installed NTDLL service table, rather than that number, selects the
handler. A tail export family preserves previous synthetic ordinals and trap
addresses. The signature has six arguments; x86's installed epilogue uses RET24.

## Sources and independent observations

Microsoft documents the public cache-hint contract in
[PrefetchVirtualMemory](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-prefetchvirtualmemory).
Its public Flags argument is reserved and zero. That cache hint does not insert
pages into the process working set and may be partially satisfied under memory
pressure. The private native flag1 is a separate contract.
[System Informer's PHNT declarations](https://github.com/winsiderss/phnt/blob/master/ntmmapi.h)
provide the six-argument signature, class0, pointer-sized range fields, and
`VM_PREFETCH_TO_WORKING_SET = 1`. Private validation order and effects below are
independent kernel measurements, not consequences inferred from those headers.
Both sources were inspected on 2026-10-28.

The immutable `probe-v4.c` producer and `run-v4.py` runner execute 342 fresh
processes per ABI. The retained build29695 receipt has 1026 observations for
ARM64, x64 compatibility and x86 WoW64 on one ARM64 kernel. The source SHA-256 is
`d8e09d8376230012d86867fca3a4e056b286eaff63a5deeb2512f3cc04888870`.
The checked-in receipt preserves every observation field; the original runner
receipt additionally repeats each observation as raw stdout. The producer
records returned NTSTATUS separately from an escaping exception, LastError,
input snapshots and accessibility masks, page protections, and working-set
attributes before and after the call. It never reads or writes the target
before the measured call. Working-set queries and guarded-input snapshots do
not touch those target pages or consume input guards.

Earlier sources and runners remain frozen. Version1 failed compilation because
automatic include sorting placed `psapi.h` before `windows.h`. Version2 compiled
and completed 70 observations before its zero-access OpenProcess setup failed.
Version3 uses DuplicateHandle for that real zero-access self handle, adds
working-set access controls, and completed618 observations. Version4 adds class
and upper-address boundary exploration. These setup failures are not successful
kernel observations.

| Contract | Native64 | WoW64 |
|---|---|---|
| Range input | Four-byte alignment, two eight-byte fields | Unaligned two-four-byte-field records widened before native dispatch |
| Information input | Four-byte alignment and size, NULL rejected | Same native information record after range conversion |
| Handle | Current pseudo-handle or a current-process handle with `PROCESS_VM_OPERATION` (`0x8`) | Same |
| Conversion resource failure | No WoW64 conversion | `STATUS_NO_MEMORY` and LastError8 |
| Target coverage | Nonzero size and end within native user limit | Fields widened before checking against that native limit; range may exceed guest32 limit |
| Bad target address, reserved/free/protected target | An advice miss does not fail an otherwise valid request | Same |
| Flag0 | Leaves guest working-set residency unchanged | Same |
| Flag1 | Populates eligible committed pages, including execute-only pages | Same |
| Target guard/NOACCESS | Preserved and excluded from population | Same |

Native information-pointer/length checks precede count checks; the information
copy precedes the process check; the process check precedes range capture and
validation. Range validation precedes flag rejection. WoW64 captures and widens
the complete range list first. Guarded input faults consume the reached guard;
guarded target advice leaves the guard intact. Invalid class values at9 and
above produce `STATUS_INVALID_PARAMETER_2`, after WoW64's initial conversion.

## Implementation and validation boundary

The shared Windows model implements class0 on every host. It uses the existing
AddressSpace population path, including its anonymous and source/shared backing
owners. Population uses read access without dirtying executable pages or
acquiring a private copy. Allocation/state-run iteration skips large free
extents: O(log A + R + P) time for A allocations, R intersecting state runs, P
eligible pages, and O(R) temporary run metadata. Range capture/validation uses
O(N) descriptor work with O(1) extra host storage, never a guest-count-sized
host allocation. Native user-limit arithmetic is checked before population.

The model has no standby-list cache. Accepting flag0 therefore leaves guest
residency intact; this is not a claim of host-file readahead or reduced I/O.
Flag1 has actual guest residency effects. Resource failures can leave advice
partially satisfied without changing commitment or protection.

The retained replay selects822 class0 and invalid-class rows and compares exact
statuses, LastError, readable caller bytes with address relocation, guard
transitions, four-page residency masks, commitment and handle counts. The204
other observations explore declared information classes1..8. Those remain
explicit implementation frontiers and are tested as such; they are not included
in prefetch coverage. The existing free-address VirtualQuery protection baseline
differs from the native producer, so tests assert preservation of each target's
baseline and exact control-page protections. That separate query discrepancy
is not changed by prefetch.

Native Windows tests additionally execute installed NtSetInformationVirtualMemory
and NtQueryVirtualMemory leaves, verify observed working-set attributes, preserve
target guards and LastError, and check six-argument/x86 RET24 return behavior.
The existing native2022/2025 CI jobs collect684 fresh AMD64/WoW64 observations
per kernel and pass those receipts to the same replay. The original complete
hardware-fault fixture and its budgets remain intact. An ARM64-host x64 ABI is
not independent AMD64-kernel proof; Unix replay is not native Windows proof.

## Assumption Register

| ID | Assumption and basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| VM1 | The stopped CMD request is working-set prefetch, based on its native record and PHNT flag declaration | Real residency population | Flags0/1/every other bit, reserved/free/guard/execute targets, mixed ranges; native status/residency mismatch falsifies it | Confirmed on build29695 ARM64 kernel; independent AMD64 qualification pending |
| VM2 | Native64 and WoW64 use distinct capture order | Buffer/fault and resource semantics | Misaligned/truncated/guarded buffers, zero/huge counts and invalid handles; rerun complete producer to falsify it | Confirmed on the three retained ABIs; resource failure's LastError8 explicitly included |

High impact, nonblocking to this individual class: full Linux/macOS/Windows
installed-library process support remains unfinished, including Windows foreign
process namespaces, other information classes and later installed-program
services. No public C API, SDK ABI, package dependency, syscall budget, or
installed system image changes as part of this class.

## Initial validation ledger

Local Rust1.95.0 validation passed the822-row replay and explicit foreign/class
frontiers on macOS ARM64 and the translated Linux x86-64 container. Both passed
10 existing working-set tests,8 CLI regressions,191 C API tests and all-target
checking. macOS also passed the append-only ordinal regression and strict
production-library Clippy with `-D warnings`.

Windows ARM64 passed4 selected prefetch tests, including installed native/WoW64
leaves and the retained corpus,11 working-set tests, the ordinal regression,
10 CLI regressions,191 C API tests and all-target checking. The fresh-AMD64
replay wrapper falls back to the retained corpus when no fresh path is supplied;
that local pass is not fresh AMD64 evidence. Independent2022/2025 kernel
qualification remains pending in the validation branch. No package, installed
Assist plugin or real-IDB execution is claimed by these source checks.

The unchanged installed build29695 ARM64 CMD passed the prefetch service and
reached `NtOpenKey: registry key outside selected runtime snapshot`. Emulation
returned125 before stdout; native execution returned0 and emitted
`RAX_MEMORY_PREFETCH_CMD\r\n`. CMD SHA-256 before/after was
`d0f47e2d32ab33e593e5b49592d3dcfa3c8c5f9f9b345d512ef7269bca6b481a`;
the qualified local CLI SHA-256 was
`6e03143094be3501b901d3952801f28ba870381b5fb20bd1dedae67d153fec9d`.
This is service progress, not complete CMD or full process qualification.

## Independent AMD64 kernel capability

The [native qualification run](https://github.com/HexRaysSA/rax/actions/runs/40635212223)
at source`b034ba2a` collected684 successful observations on each native AMD64
kernel. Both receipts require native machine`0x8664`, observer machine0, and the
same frozen C4 source from Git. The Windows checkout uses CRLF, whose exact
source SHA-256 is
`0d37f56c5176cb276b3552156dbfe13bb908e7fbfe3adeafe2afec8c8a005984`.
Converting only its line endings to LF reproduces the Git/local-native source
hash`d8e09d8376230012d86867fca3a4e056b286eaff63a5deeb2512f3cc04888870`.
Both physical input identities are retained, without rewriting the executed
producer. Artifact SHA-256 and ZIP CRC were verified
before retaining their observations:

| Kernel | Original artifact SHA-256 | Retained receipt |
|---|---|---|
| Windows2022,10.0.20348 | `83fcfc279e0b51ecdecf4ab010fa697efeb3cdc700053ccab79a9add2abb84c7` | `observations-amd64-20348-v4.json` |
| Windows2025,10.0.26100 | `c6547d16772705119d68a2fee6dbaceb97367c8a1f204cbc61d2ecb337981457` | `observations-amd64-26100-v4.json` |

Build26100 matches every selected status, LastError, guard and residency result
from the retained ARM64 kernel for its two guest ABIs. Build20348 differs in54
selected rows: flag1 is rejected with `STATUS_INVALID_PARAMETER_5` after normal
range validation and does not populate pages. Flag0 and the remaining selected
capture/error results agree. The shared model therefore selects working-set
flag availability from the captured native kernel version/machine, independently
of guest-visible version settings. The portable built-in personality keeps its
build29695 reference behavior. An unknown native flag1 profile is an explicit
frontier; flag0 remains available through the existing cache-hint model.

The two new retained replays contribute548 cases each on every host, for1918
class0/invalid-class observations across three independent kernel profiles.
Installed-leaf tests require the native20348 rejection and absence of residency
changes, as well as working-set insertion on26100/29695. Unknown-profile and
guest-version-spoofing controls exercise the capability boundary.

| ID | Assumption and basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| VM3 | Captured native kernel identity selects flag1 availability; independent20348/26100/29695 controls differ only as recorded | Working-set capability gate | Spoof guest version; select supported, older and unknown native profiles; any admitted uncaptured flag1 or20348 population falsifies it | Native observations, three-host replay and both final native AMD64 source jobs passed |

The corrected source passed5 selected tests on macOS and Linux, including1918
retained observations and the unknown/spoofed-version boundary. Windows ARM64
passed7 selected tests including its installed native/WoW64 leaves. The existing
working-set, ordinal, CLI and191-test C API gates passed again; all-target
checking passed on all three hosts and strict production Clippy passed on macOS.
Linux evidence here uses the translated x86-64 container, while the two new
native AMD64 corpora come from the independent CI kernels above.

The initial source`b034ba2a` failed the fresh20348 replay at x64 case1: emulation
returned success where the native kernel returned `STATUS_INVALID_PARAMETER_5`.
The retained20348 corpus and corrected capability gate address that regression;
the final native AMD64 source run must pass before master publication. The
corrected local Windows CLI SHA-256 is
`80f6a29604aeec38137a6c3c79a60ce4154dca4bf8d23507057f57e1c749b34e`;
its CMD comparison preserves the same image hash and NtOpenKey frontier above.

## Final native source qualification

Both native AMD64 jobs passed at source`24c0f7ec` in
[run40636977605](https://github.com/HexRaysSA/rax/actions/runs/40636977605).
Each executed the fresh684-row producer, retained/fresh replay, installed
six-argument leaves, the whole original hardware-fault fixture, and CLI/write
regressions. The final prefetch artifacts have SHA-256
`d1f761e0a027929410cead703072f6a20eb65db76353dff6d68c657c9b7bb811`
(Windows2022) and
`5593ea126c9753fbc6b33e1a6b366eebc13c4878bc3527800bbcf25f283bb7f0`
(Windows2025). Their exact CRLF producer hashes, native machine/observer identity,
completed receipts,684 observations, archive digests and ZIP CRC were checked.
The subsequent provenance-only commit changes no Rust/C source, fixture input,
Cargo manifest, lockfile, API header or workflow from that qualified source.

The broader source matrix is
[run40637028679](https://github.com/HexRaysSA/rax/actions/runs/40637028679).
Its formatter/Clippy and Linux C API jobs passed; Windows C API was running and
macOS C API queued at publication preparation. Separate local C API checks
passed191 tests on each host. These results do not claim an entirely green
general matrix, packages, installed Assist or full process compatibility.
