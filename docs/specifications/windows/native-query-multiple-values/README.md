# Native multiple-value registry queries

`NtQueryMultipleValueKey` reads values from one immutable guest key. Guest
handles, names, pointers, and requested rights remain inside the emulator.
The operation uses the existing selected registry values and `KEY_QUERY_VALUE`
access checks. Key handles retain their data after the selection namespace is
replaced. Prior synthetic DLL ordinals and trap slots remain unchanged.

## ABI and observed ordering

The installed Windows SDK 10.0.26100.0 `um/winternl.h` declares six arguments:
`HANDLE`, `PKEY_VALUE_ENTRY`, `ULONG`, `PVOID`, `PULONG`, `PULONG`.
MSVC compiled the SDK declaration for ARM64, x64, and x86. Compiler read logs
identify the actual header; its SHA-256 is
`a43424486349c38f697c009512dfe4eb8fca733d7665afab42f50752170b9785`.
`KEY_VALUE_ENTRY` sizes are 24 bytes on native64 and 16 bytes on x86; field
offsets are respectively `[0, 8, 12, 16]` and `[0, 4, 8, 12]` bytes. The x86
NTDLL leaf returns through `RET 24`.

Native64 validates the handle and reads `BufferLength` before allocating its
capture. It probes the entry array for writes, probes optional
`RequiredBufferLength`, then probes the data buffer. Entry arrays and data
require 4-byte alignment when their probed extent is nonzero. Descriptor
headers are captured and checked for odd lengths before name text is read.
Nonempty name text requires 2-byte alignment. Descriptor headers and the two
length pointers may be unaligned.

WoW64 first allocates and widens the caller's entries and nonnull descriptor
headers. Native validation follows. Metadata copies back even after native
failure; this can replace its status with a later caller-memory fault. A thunk
allocation failure sets `LastError` to 8 while retaining `LastStatusValue`.

Data starts are aligned to 4 bytes. Required length is the end of the final
logical value, without final rounding. Complete fitting values are copied;
inter-value padding is zeroed, including padding beyond the input capacity.
For lengths `[1, 3, 5]` bytes, offsets are `[0, 4, 8]` bytes and required length
is 13 bytes. Capacity 1 byte publishes 4 copied bytes. Missing values leave
data and entry metadata unchanged and publish required length zero. A late
`BufferLength` write fault preserves copied data and required length while
entry metadata remains unchanged. Replay checks these aliases and fault orders.

Required length is reported modulo `2^32` bytes. Logical offsets and the overflow
decision retain the aggregate size: 4,096 values of 1,048,576 bytes require
4,294,967,296 bytes, report zero, and return `STATUS_BUFFER_OVERFLOW`. Later
values do not become writable at the buffer start after this wrap. The handler
tracks logical positions in `u64` and truncates only the two ULONG reports.

Entry-array capture is bounded to 16 MiB of caller descriptors. Resource failure
occurs at the measured allocation stage: before caller capture on WoW64 and
after handle/length validation on native64. Aggregate name capture beyond
16 MiB remains an explicit unsupported boundary. Output capacity never causes
a proportional host allocation; data is streamed from immutable captured values.

For `n` entries, maximum name length `L` UTF-16 units, `V` selected values,
`B` copied bytes including padding, and `P` visited pages, the worst-case time
is `O(n (L + 1) log(V + 1) + B + P)`. Additional host space is `O(n + L)`;
the existing immutable key/value storage is excluded from that bound.

## Reproduction and evidence

The retained frame is Windows 10.0.29695 on an ARM64 kernel. Its native machine
was independently read through `IsWow64Process2`. ARM64, x64 under ARM64X, and
x86 under WoW64/CHPE are distinct process controls; this frame does not establish
AMD64-kernel behavior. Other kernel profiles require fresh native qualification.

`overflow/` also retains 15 length-wrap calls from build 29695 and 108 calls
from build 29698 on the same ARM64 host. The latter vary six entry counts and
six capacities, including buffers holding one or two 1 MiB values. Field runs
preserve all 4,098 initialized entries; data runs preserve the complete 2 MiB
destination. Both corpora reconstruct the original stdout bytes, including CRLF.
The overflow evidence manifests bind the exact compiled C and CMake inputs,
actual SDK header, native images, mapped providers, and verified runtime archives.
The retained overflow provider hashes were observed after each native process;
fresh CI additionally binds matching mapped provider bytes before and after it.

`probe-v1.c` and `CMakeLists.txt` are the exact consolidated producer inputs.
`evidence-v6.json` binds their hashes, the native runtime archive, and repeated
experiments. `controls-v6.json` retains 50,036 ARM64, 50,036 x64, and 48,884 x86
calls: 148,956 total. Every result field matched the earlier three experiments.
Column dictionaries preserve all JSON fields; decoding reconstructs each native
stdout byte for byte, including CRLF, checked against its SHA-256 digest.

The producer reserves a 65,536-byte arena plus a 4,096-byte inaccessible page
at a recorded low address. Replay maps that exact address. Pointer bytes remain
unchanged. Ordinary cases capture four output windows and verify a reconstruction
of the complete arena; large-count cases retain the complete arena directly.
All 17 page protections and both thread error/status values are checked.

Native fixtures use newly created volatile `HKCU\Software\RaxNativeQmv_*`
leaves. Creation must report a new key before writing. An owner marker permits
recovery of that exact leaf after an exited child. Both registry views are
independently checked for absence after cleanup.

With Python 3.9 or newer, verify retained evidence on any supported host:

```sh
python -B tools/ci/windows_query_multiple_values.py --verify-corpus
cargo test --locked --no-default-features --lib native_query_multiple_value_key
```

The verifier reports two primary producer inputs, three process ABIs, 148,956
primary calls, and 123 additional overflow calls; it also verifies the four
overflow producer inputs and both overflow stdout reconstructions.
Fresh Windows controls require MSVC, CMake, and a Windows SDK supplying the
declared types. Run from a new output directory inside the checkout:

```sh
python -B tools/ci/windows_query_multiple_values.py
```

The command retains native images, raw stdout, compiler/header identity,
provider hashes, cleanup evidence, and `observations.json` under
`target/native-query-multiple-values-v1`, then runs retained and fresh replay
plus installed NTDLL tests. On AMD64 hosts it captures x64 and x86; ARM64 hosts
also capture ARM64. Existing CI jobs verify retained evidence everywhere and run
fresh controls on Windows, including aggregate-size overflow and partial copies.
Windows replay selects four tests; other hosts select three. No additional CI
jobs are created. Full library qualification is separate from this filtered replay.

## Assumption register and boundaries

| ID | Assumption and basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| M1 | Selected immutable values represent the requested read; existing key bodies own their values. | Query results and lifetime. | Drop the namespace, vary rights/types/names, and replay all native outputs; an installed process requesting uncaptured data falsifies its runtime coverage. | Model confirmed by replay; whole-process coverage remains bounded. |
| M2 | The recorded low arena can be mapped exactly in each replay process. | Lossless pointer and alias comparison. | Fixed allocations and inaccessible boundaries; allocation collision fails the test on every host. | Confirmed in the three-host baseline; asserted by every replay run. |
| M3 | The measured ordering applies to the retained kernel/profile. | Probe, capture, and copy semantics. | Pairwise descriptor/text faults and resource failures; fresh native replay on another kernel can falsify parity. | Full retained frame on build 29695; overflow-copy controls on build 29698. Broader profiles pending. |

High impact: full Windows startup and the overall Linux/macOS/Windows process
goal remain incomplete beyond this service. Medium impact: AMD64-kernel and
other-build qualification remains separate from the retained ARM64 frame.
These findings bound the qualification claims; they do not introduce host
registry forwarding or change embedded permissions.

The Microsoft primary documents and redistribution notices are preserved beside
this file. `sources.json` identifies immutable upstream revision
`7515063cea4c9e98db6a92986c5b4ddb0463fd16`; retrieval date was 2026-10-30.
