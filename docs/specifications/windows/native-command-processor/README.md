# Fixed Command Processor snapshots and NT open controls

The engine captures the fixed HKLM `Software\Microsoft\Command Processor`
complete bounded subtree through both Win32 views. After acquiring the creator's
primary hive, it captures the same fixed suffix below that validated SID in
HKU. It does not substitute the host thread's HKCU for the captured creator.
Every native handle closes during selection. Runtime opens and value queries
use immutable records; guest names, rights and handles never reach a host
registry API.

The additional fixed System path has its own
[source-preserving native campaign](../native-system-command-processor/README.md).
Its inputs and evidence do not alter the retained producers below.

The shared view catalogue retains AppModel's existing independent trees and
adds the two CMD selections. MACHINE and primary-hive handles retain their original
catalogue across namespace replacement and duplication. Canonical names,
ordinary maximum grants and security-access results are captured per view.
Native file-not-found and path-not-found remain distinct NT results. Captures
of one physical key through two views must agree on values, child count and
access. Complete captures also compare every retained descendant. Values and
metadata share the existing aggregate snapshot budgets.

The installed adapter now enumerates every descendant within the fixed CMD
roots. Per-node values, canonical identity and access ceilings are retained;
no provider names or empty success records are synthesized. See
[complete subtree controls](../native-command-processor-tree/README.md) for
the bounded acquisition and descendant-open evidence. The internal partial
header representation still makes no claim about unknown descendants.

## Native evidence

`controls-v1.json` records kernel 10.0.29695 on Windows on ARM. ARM64 runs
natively; x64 and x86 run in that kernel's compatibility environments. These
are not AMD64-kernel observations. All three process ABIs compiled and executed
the six producers with unchanged input and executable hashes and zero retained
handles after the measured campaigns.

The producer groups are:

| Producer | Calls per process ABI | Contract |
|---|---:|---|
| `absolute-v1.c` | 136 | Two NT open services, 17 desired masks and four views on the logical machine leaf |
| `physical-v1.c` | 136 | The same controls on its explicit `WOW6432Node` spelling |
| `relative-v1.c` | 12 | Logical leaf from three MACHINE parent views, with four child view requests |
| `physical-relative-v1.c` | 12 | Explicit physical leaf from those parent views |
| `family-v1.c` | 48 in this context | 16 machine/user hive-relative opens and 32 successful-machine-parent self-opens |
| `graph-v1.c` | 32 ARM64, 32 x64, 48 x86 | Both services and four views from every reachable `(canonical name, tags)` state |

Thus `(136 + 136 + 12 + 12 + 48) × 3 + 32 + 32 + 48 = 1,144` NT open rows.
Win32 seed acquisitions, root/header/value observations and graph seeds are
retained separately. The machine key has six values and one child in this
context. The user leaf is absent: valid native requests return
`STATUS_OBJECT_NAME_NOT_FOUND`, and x86 `0x300` requests return
`STATUS_INVALID_PARAMETER` before absence resolution.

The graph uses at most 16 retained states per hive and explores eight edges per
state. A new state is queued once; exceeding the bound fails capture. Time is
`O(V × 8)` native calls plus bounded metadata queries, and storage is `O(V × 8)`.
It opens only empty relative names from already selected leaf handles.

For x86 the measured transitions include:

| Parent record and tags | Request 0 | Request `0x100` | Request `0x200` |
|---|---:|---:|---:|
| Native64 record, `0x100` | `0x100` | `0x100` | `0x600`, paired 32-bit record |
| Wow32 record, `0x100` | `0x100` | `0x100` | `0xE00` |
| Wow32 record, `0x400` | `0x400` | `0x500` | `0x600` |
| Wow32 record, `0x500` | `0x500` | `0x500` | `0x600` |
| Wow32 record, `0x600` | `0x600` | `0x500` | `0x600` |
| Wow32 record, `0xE00` | `0x600` | `0x500` | `0x600` |

Native64 empty-name reopens preserve their physical record and parent tags;
ordinary absolute native64 opens ignore the sampled view flags. An explicit
physical x86 open has tags `0xE00` unless its effective view is `0x100`.
These rules differ from the already measured shared NLS descendant rules.
Present AppModel WoW64 tags retain their prior uncaptured boundary.

`controls-amd64-v1.json` retains the two process ABIs from GitHub Actions run
40800064800, job 123205762565, on Windows Server 2022/AMD64. Its source hashes
are recorded both as checked out and LF-normalized. This corpus exposed a
replay fixture classification bug: the native physical component is spelled
`Wow6432Node`, while the fixture recognized only `WOW6432Node`. Physical-view
classification now ignores ASCII case in that fixed component. The retained
AMD64 corpus is replayed on every host, including all 80 graph edges.

The original ARM-host corpus preserves every observed result field except
`family.hives[1].root.name_hex`, the creator-hive canonical name. Its original
UTF-16 byte count and SHA-256 remain in `name_projection`. Raw report hashes,
producer hashes, compiler options, PE machines and executable hashes are
retained. Full unprojected reports are privately archived. Portable replay
uses a declared synthetic parent hive and tests the recorded leaf behavior;
fresh Windows replay uses the actual installed snapshot and creator SID.
The AMD64 corpus applies the same creator-name projection and retains the
original artifact identity and raw report hashes.

## Reproduction and qualification

Verify the exact LF-normalized producers on any supported host:

```sh
python tools/ci/windows_command_processor.py --verify-corpus
cargo test --locked --no-default-features --lib services_tests::registry_tests::command_processor:: -- --test-threads=1
cargo test --locked --no-default-features --lib registry::command_processor::tests:: -- --test-threads=1
```

On native Windows with CMake, MSVC, Python and Rust available:

```powershell
python tools/ci/windows_command_processor.py
```

The runner obtains executable paths from CMake, validates PE machines, retains
raw observations, removes completed native builds, and sets
`RAX_COMMAND_PROCESSOR_CORPUS` for fresh dispatcher and graph replay, and
`RAX_COMMAND_TREE_CORPUS` for the complete subtree controls. Native
capture, parsing or replay failures fail the command. Four dispatcher and
three Windows acquisition tests must run with zero failures and ignored tests.
Its output stays under `target/native-command-processor-v1`; the existing
Windows CI job uploads it. A new in-tree `--output` preserves prior evidence.
Raw Windows checkout hashes and LF-normalized producer hashes are recorded
separately, so CRLF checkout conversion does not masquerade as a source change.

The 165-test registry iteration and three dispatcher tests passed on macOS.
Complete owning library binaries, Windows acquisition, C API, all-target,
fresh AMD64 controls, actual CMD and installed Assist/package qualification
remain separate gates. This document does not establish complete process
execution or qualify an unobserved kernel/token context.

## Assumption register and bounded scope

| ID | Assumption | Basis and dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| CP1 | The measured CMD mappings and state transitions also apply to other supported kernels. | The 1,144 native rows establish the retained 29695 context; dispatcher policy depends on these rules. | Fresh native CI captures all producers and replays their rows and complete graph. Any differing status, grant, physical name or tag falsifies the corresponding rule. | Confirmed for retained context; retained for other kernels. |
| CP2 | A present creator-SID leaf follows the same generic key self-open mechanics, with its own captured physical identities and access. | The retained user leaf is absent; its absence behavior is direct evidence. Present-value selection is implemented and tested with distinct controlled views. | Fresh present-user native controls or an independently measured shared-HKU fixture must agree. A differing state transition falsifies this extension. | Retained; no independent present-user native result is claimed. |

High impact, qualification gates: native Windows acquisition and fresh AMD64
CMD controls remain required. Actual CMD progress must be measured against the
new executable before claiming its next boundary or success. Medium impact,
existing boundary: uncaptured AppModel body tags stay explicit. Complete CMD
subtrees have separate native controls and qualification requirements.
