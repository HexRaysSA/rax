# Native key queries

This group implements guest `NtQueryKey` class7 (`KeyHandleTagsInformation`)
from guest-owned key-body state. It does not forward guest arguments to a host
registry API. Other admitted information classes remain explicit implementation
frontiers until their native metadata is captured. It does not complete CMD or
full process emulation.

The service has five arguments, `[Handle, I32, Ptr, I32, Ptr]`; installed x86
leaf checks require RET20 and unchanged callback stack state. A separate tail
export family preserves every preceding synthetic ordinal and trap address.

## Native evidence

All retained observations in this directory came from the Windows10.0.29695
ARM64 kernel. ARM64 is the physical native ISA; x64 and x86 observations are
Windows compatibility personalities on that kernel. They are not physical AMD64
kernel evidence. `run-v2.py` makes fresh observations on the existing native
Windows2022/2025 CI lanes and records actual kernel/machine identities.

- `probe-v1.py` and `arm64-29695-v1.json`: 856 rows surveying all information
  classes0..11, sizes, grants, names, alignment and invalid handles.
- `probe-v2.cpp`, `build-controls-v2.json` and four `*-29695-v2.jsonl` files:
  2690 records per ABI (machine/open plus2688 queries). Each contains1632
  handle-tags cases and1056 exploratory cases for the other classes.
- `probe-v3.cpp` and `failed-control-v3.json`: preserved failed duplication
  control. The probe requested query-value access when duplicating a handle
  without that right. That failure is not an emulator or query-key result.
- `probe-v4.cpp` and `view-controls-v4.json`: corrected same-access duplication;
  28 view/access opens per ABI, including the rejected x86 dual-view request.
- `controller-v*.py`: the exact private acquisition controllers. Their fixed
  machine paths are historical evidence, not portable entry points.
- `run-v1.py` and `failed-runner-v1.json`: retained first portable runner and
  its falsified assumption that x64-on-ARM64 reports a nonzero process-machine
  value through `IsWow64Process2`. No emulator query result failed here.
- `pe-identities-v1.json`: PE machine identities of the eight retained probe
  binaries, each matched to its recorded unchanged before/after SHA256.
- `run-v2.py`: portable in-repository producer for the v2/v4 probes. It records
  compiler, adapter, source and executable hashes before and after execution,
  checks the PE machine type, pointer width and x86 LAA characteristic, captures
  logs, and fails on compilation, process, SEH or provenance failure. The
  observed x64-on-ARM64 process-machine value is zero despite PE machine0x8664.

Generated JSON/JSONL captures use binary Git diff presentation: their semantic
review is the producer, provenance checks and full native replay. Their bytes
remain unchanged and fully available to parsers. This also keeps multi-megabyte
raw data out of commit-message model input.

Executed producers and raw observations remain byte-for-byte frozen. Local
`.gitattributes` prevents Windows checkout newline conversion from changing
producer hashes. The separately authored portable runner is formatted before
execution. MSVC builds use in-tree object/PDB/EXE and temporary directories.

Native64 validates output ULONG alignment and the full advertised nonzero
length, then probes the mandatory byte-aligned ResultLength, then validates
class and key handle/access. Invalid classes9 and above return
`STATUS_INVALID_PARAMETER`. Class7 requires a nonzero granted mask, rather than
`KEY_QUERY_VALUE`. Short valid buffers return `STATUS_BUFFER_TOO_SMALL` and
ResultLength4. The four-byte tags record is written after ResultLength; aliasing
can therefore overwrite the latter. LastError remains unchanged.

The selected shared key's native64 tags are zero for each measured view. x86
opens retain default tags0x400, explicit64 tags0x100, and explicit32 tags0x600.
Both x86 view bits are rejected. Duplicate handles share key-body tags, while
independent opens have independent bodies. Low handle bits do not alter them.
This group does not implement the separate tag-setting native service.

WoW64 converts outputs not aligned to eight bytes, including ULONG-aligned
addresses. Its copy-out can replace a native failure and preserves completed
native stores before a fault. Store granularity reuses the already captured
native conversion profile used by mapped-filename conversion. The v2 replay
checks statuses, mandatory-result writes, output aliases, caller LastError and
guard consumption. Undefined converted scratch bytes remain in raw evidence but
are excluded from native equality assertions; the emulator initializes its own
scratch instead of exposing host allocator contents. The conversion allocation
limit remains16MiB and reports an explicit frontier above that bound.

## Reproduce

Use native Windows Python, Visual Studio C++ tools and Rust1.95.0:

```powershell
python -B docs/specifications/windows/native-query-key/run-v2.py --output target/native-query-key-v1
$env:RAX_NATIVE_QUERY_KEY_CORPUS = Join-Path $PWD 'target/native-query-key-v1/receipt.json'
cargo test --locked --no-default-features --lib native_query_key -- --nocapture --test-threads=1
```

`receipt.json` must say `state: finished` and `exit_code: 0`. Each v2 probe must
contain2690 rows, build/run return codes0 and identical before/after hashes.
Shared tests replay1920 cases per retained ABI (7680 total):1632 class7 cases
and288 invalid-class cases. Fresh v2 rows add1920 per observed ABI; view controls
add28 opens per observed ABI. Other admitted class rows are retained for the next
metadata implementation and do not count as supported-query proof.

The guest handler and retained replay compile/run on macOS, Linux and Windows.
Installed NTDLL leaves require native Windows, and execute the shipping loader,
leaf instructions, service dispatch, result behavior and return stack. This
is separate from running an entire native process, installing Assist, loading a
real IDB, or verifying final packages.

## Assumptions and remaining scope

| ID | Assumption and basis | Dependent result | Stress test and falsification | Status |
|---|---|---|---|---|
| KQ1 | Query tags describe opened key-body view state; v4 observes each view and duplicate | State ownership and open tags | Duplicate, close parent, drop snapshot, low bits; any native view/tag mismatch falsifies | Confirmed on29695 retained and fresh controls; independent AMD64 qualification pending |
| KQ2 | Native buffer order and converted copy stores follow v2 controls | Fault status, writes and guards | Short, null, unaligned, aliased, protected and crossing-page outputs; any defined replay mismatch falsifies | Retained replay passed on all three host OS; fresh29695 replay and installed leaves passed |

High: other `NtQueryKey` metadata classes, tag mutation, and the earlier native
`MAXIMUM_ALLOWED` grant disparity remain full-process frontiers. They do not
prevent validating this state/query group. No host writes or new host authority
are introduced. Runtime behavior on an unmeasured conversion kernel remains an
explicit unsupported profile through the existing conversion adapter.

Primary declarations: Microsoft [KEY_INFORMATION_CLASS](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_information_class)
and the pinned PHNT `ntregapi.h` described in
[`../native-nls-registry/sources.json`](../native-nls-registry/sources.json).
Microsoft reserves class7 for system use; the detailed behavior here is measured
rather than inferred from that declaration. Mutable documentation accessed
2026-10-28.

## Qualified runtime revision

All changed Rust sources are byte-identical across the macOS, Linux and native
Windows validation copies. The Linux container executes translated x86_64 on an
ARM64 physical host; it is not physical AMD64 proof. NativeWindows29695 executes
fresh probes for ARM64, x64, x86 and x86-LAA, then replays both retained and fresh
corpora and executes installed ARM64/x86 NTDLL leaves. Independent physical
AMD64 Windows2022/2025 qualification remains pending publication.

| Host | Targeted | Registry | Neighbor conversion | Objects | CLI | C API | Other |
|---|---:|---:|---:|---:|---:|---:|---|
| macOS ARM64 | 4 | 129 | 3 | 20 | 8 | 191 | all-target check, production Clippy |
| Linux x86_64 container | 4 | 126 | 3 | 20 | 8 | 191 | all-target check, production Clippy |
| Windows ARM64 | 5 | 156 | 5 | 20 | 10 | 191 | all-target check, explicit CLI build |

Every listed test passed without skips. Initial Linux Clippy invocation found
its pinned component absent; after installing that component inside the task
container, the same production lint gate passed. The two retained-artifact
provenance tests pass independently of the Rust implementation.

Unchanged installed ARM64 CMD SHA256:
`d0f47e2d32ab33e593e5b49592d3dcfa3c8c5f9f9b345d512ef7269bca6b481a`.
The qualified CLI SHA256 is
`a0ff9bd56c3ebbdeca6b7c94a8fcd02561d014413548951ba7647287804deed0`.
Native CMD exits0 with `RAX_QUERY_KEY_CMD\r\n`; emulation gets past class7
and stops at unimplemented `NtOpenKeyEx` (0x12b), exiting125 before stdout.
No successful whole-CMD/process result is claimed.

Native probe/qualification outputs were archived with CRC and per-file SHA256
verification before their generated trees were removed. Compatible warm Cargo
trees remain assigned to the immediate `NtOpenKeyEx` implementation and remaining
`NtQueryKey` metadata work; no extra CMake or Cargo build tree was allocated.
