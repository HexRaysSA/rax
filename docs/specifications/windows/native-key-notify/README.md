# Native registry notification controls

These controls measure user-mode `NtNotifyChangeKey` on Windows 10.0.29695,
running ARM64, x64, and x86 processes on an ARM64 kernel. The retained corpus
contains 496 observations per process ABI, or 1,488 observations in total.
Every executable reports its actual process handle count before and after the
matrix; all retained counts match. The corpus records producer hashes, PE
machine identifiers, image hashes, and original report hashes.

| Producer | Cases per ABI | Boundary |
|---|---:|---|
| `probe-lifetime-v1.c` | 32 | Duplicate versus independent opens, final key close |
| `probe-admission-v2.c` | 184 | Grants, event types, IOSB protection, buffers and APC admission |
| `probe-thread-v3.c` | 24 | Issuing-thread exit, synchronous cleanup and APC arguments |
| `probe-flags-v4.c` | 208 | Single/inverse filter bits, alignment and failure precedence |
| `probe-completion-v5.c` | 24 | Deferred-store faults and event handle reuse |
| `probe-completion-stores-v6.c` | 24 | Ordered stores across a protected page boundary |

The CMake build compiles these six producers with the static MSVC runtime and
warnings treated as errors. Each process reads the fixed OLE registry key and
creates only its own handles, events, threads, and memory allocations. It does
not change registry contents. Sources included by other producers remain part
of the recorded seven-file input set.

## Observed contract

The ten arguments retain the native pointer/ULONG/BOOLEAN widths. Ordinary
requests probe a 4-byte-aligned IOSB and any nonempty output buffer before
writing `STATUS_PENDING` and zero information. Filter and handle validation
follow those writes. `REG_NOTIFY_THREAD_AGNOSTIC` (`0x10000000`) requires an
asynchronous request, a supplied event, and no APC routine; this path does not
probe or write the IOSB or buffer. Accepted filter bits are the four change
bits (`0x0000000f`) and the thread-agnostic bit. A zero change mask is admitted.
Process and thread pseudo-handles supplied as an asynchronous event return
`STATUS_OBJECT_TYPE_MISMATCH` (`0xc0000024`), after key validation. The admission
matrix checks these handles with valid, invalid, and wrong-type key arguments.

Successful asynchronous registration resets and retains the event object.
Closing a numerical event handle and allocating a replacement cannot retarget
the request. Key handles duplicated from the same body share its cancellation
lifetime. Independently opened bodies remain separate even when their paths
match. The final key handle completes its requests with
`STATUS_NOTIFY_CLEANUP` (`0x0000010b`). Ordinary requests also complete when
their issuing thread exits; thread-agnostic requests survive that exit.

Synchronous calls ignore their supplied event and APC routine, remain blocked
until completion, and return the cleanup status. The guest implementation uses
a private scheduler event without publishing an extra caller handle. Normal
asynchronous APC requests retain their completion until APC delivery and call
the guest routine with `(ApcContext, IoStatusBlock, 0)`. Those callbacks share
the FIFO with ordinary `QueueUserAPC` callbacks.

IOSBs contain two pointer-sized fields: 16 bytes for ARM64/x64 and 8 bytes for
x86. Native64 completion stores occur in order. A late access fault preserves
preceding stores; WoW64 publishes its whole 8-byte record in one checked store.
A reached guard is consumed. The retained event still completes even
if the IOSB store cannot finish. The controls distinguish immediate samples
from final states: cross-thread `event_closed` samples can race with completion
delivery and are not fixed replay expectations.

## Scope and assumptions

Registry contents are immutable snapshots in the current personality. Pending
requests therefore observe their modeled cleanup lifetimes; later host registry
changes are not imported. This service adds no registry content writer and
forwards no guest notification request to the host. A future content writer
must implement change matching and the first-registration filter/tree policy
before it can coexist with these requests.

| ID | Assumption and basis | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| N1 | User-mode behavior needs direct controls; kernel-mode Zw prose is insufficient | Probe order, optional arguments, completion | Re-run all six producers in each native process ABI | Confirmed for the retained samples |
| N2 | Guest registry contents remain immutable; the dispatch table contains no content writer | No content-change completion source | Add or locate a guest content writer, then require matching/change-event controls | Retained implementation boundary |
| N3 | Immediate cross-thread observations can race; native runs differ in signal timing | Final-state assertions | Compare repeated native runs before treating any transient sample as fixed | Retained |

These are finite observations on the recorded kernel profile. They do not
establish behavior for every Windows build, mutable registry operations, or
complete command-processor execution. The Rust `Thread.apcs` payload now uses
explicit ordinary/I/O variants; the public C ABI is unchanged.

## Reproduce and verify

Verify producer identities and retained dataset hashes on any host:

```console
python tools/ci/windows_key_notify.py --verify-corpus
```

Expected totals are seven producer inputs, three retained process ABIs, and
1,488 observations. Replay the retained observations through the guest NT
dispatcher:

```console
cargo test --locked --no-default-features --lib registry_tests::key_notify:: -- --test-threads=1 --nocapture
```

On Windows with CMake, Visual Studio, Rust and Python available, capture fresh
controls and replay them:

```console
python tools/ci/windows_key_notify.py --output target/native-key-notify-v1
```

The output directory must not already exist. It contains raw native reports,
configure/build logs, a hash-indexed `observations.json`, and `guest-replay.log`.
The helper removes completed native build trees and keeps its scratch/Cargo
paths inside the checkout. AMD64 hosts run x64/x86 producers; ARM64 hosts also
run ARM64 producers. `RAX_KEY_NOTIFY_CORPUS` selects a fresh corpus for the same
portable replay tests. Existing Windows C API CI performs capture/replay and
preserves its output artifact; other hosts verify the retained producer set.
Full affected Cargo test binaries and the other consumer gates remain separate
from these focused commands.

For an independent native observation without guest replay, pass
`--capture-only`. Its summary reports `guest_replay: "not_requested"`; this
does not qualify the emulator. The existing Windows 2022/2025 observation jobs
use this mode to retain kernel-specific store behavior. The main Windows C API
CI lane still requires capture and guest replay together.

Primary references describe the signature and flags; the executable controls
own the user-mode failure order and lifecycle observations above:

- [Microsoft: ZwNotifyChangeKey](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwnotifychangekey)
- [Microsoft: RegNotifyChangeKeyValue](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regnotifychangekeyvalue)
