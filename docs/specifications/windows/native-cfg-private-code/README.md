# Native private-code CFG lifecycle controls

This directory retains independent Windows API and private-call observations
needed to implement guest CFG state. The observers do not link RAX. Every
allocation and call target belongs to the observer process. They do not modify
other processes, installed DLLs or host mitigation settings.

`controls-arm64-29698-v1.json` binds exact observer source, executable, DLL and
stdout hashes to Windows ARM64 kernel `10.0.29698`. Its x64 process view uses
Windows translation; it is not a physical AMD64 result.

| Native process view | API observations | Private-call controls |
| --- | ---: | ---: |
| Translated x64 | 196 | 21 |
| ARM64 | 196 | 21 |

The API set contains 88 allocation, 66 protection, 24 Win32 target-update and
18 NT target-update observations. API results and private-call results are
different evidence: a successful update does not alone prove target admission.
Each call control runs in a fresh child. Successful children return `0x1234`
and release their reservation. Denied children reach the `CALL` marker before
their recorded `0xC0000409` exit; the operating system reclaims the process's
private allocations. Parent exit zero alone does not qualify any child.

Both recorded process views agree on all 21 call outcomes. Default private
executable allocation admits the leaf, including instruction-aligned targets
within a 16-byte slot. Explicit registration admits the aligned target without
admitting other offsets in the slot. These controls begin with executable
reservations: their invalid targets remain invalid across the recorded
protection, recommit and decommit operations. Release followed by fresh
executable allocation restores default admission. The original reservation
protection is material; the repeat controls below cover originally writable
reservations, whose ordinary executable transitions restore default validity.

The NT target-update controls require a 40-byte information record for these
64-bit process views, publish a separate processed count, and leave the target
record's input flags unchanged. The Win32 wrapper publishes the processed bit
in each target record. The measured kernel accepts target updates on writable,
non-executable private memory when the corresponding bitmap storage exists.
The API matrix reuses addresses and does not isolate that prerequisite. The
additional controls below do; validity and execute permission remain separate.

The call observer uses the documented WindowsApp import library for
`SetProcessValidCallTargets`. An earlier ARM64 observer called that API through
a dynamically resolved pointer and some children terminated before their
private `CALL` marker. Those exits are excluded. The cause of those earlier
terminations is unknown; they do not establish private target admission.
Compiler CFG instrumentation remains enabled at the private call site.

## Reproduction and capture

From the repository root, on Windows, macOS or Linux:

```text
python -B tools/ci/windows_cfg_private_code.py --verify-retained
python -B -m unittest discover -s tools/ci -p test_windows_cfg_private_code.py -v
```

Expected retained dimensions are four reports, 392 API observations and
42 private-call controls. The tests reject source drift, disabled CFG,
duplicate or missing observations, early child exits, wrong leaf returns,
unrelated exception statuses and missing release/completion markers.

To capture on native Windows AMD64 or ARM64 with Rust 1.95.0 and the matching
MSVC/Windows SDK linker libraries installed:

```text
python -B tools/ci/windows_cfg_private_code.py --output target/native-cfg-private-code-v1
```

The output directory must not exist and must resolve inside this checkout.
The collector compiles both observers with `-C control-flow-guard=yes` and
`/guard:cf`, verifies PE CFG metadata and native machine, and requires the
runtime CFG policy bit in every qualified call. Source and system-DLL hashes
are checked before and after execution. Process records preserve each original
PID and terminal result; there are no timeout restarts. Build and compiler
temporary directories remain inside the output directory and are removed
after successful capture. Raw stdout, stderr, compiler logs, process records
and `observations.json` remain as evidence.

The existing Windows 2022/2025 workflow captures independent AMD64 profiles and
uploads the observations even when a step fails. Its Cargo cache excludes the
corpus directory. Adding this wiring does not establish a successful CI result;
the resulting native artifacts must be inspected separately.

## Primary contracts and scope

- [Microsoft memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
  distinguish allocation-time `PAGE_TARGETS_INVALID` and protection-time
  `PAGE_TARGETS_NO_UPDATE`, both `0x40000000`.
- [Microsoft SetProcessValidCallTargets](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessvalidcalltargets)
  defines the public target-update API, offset alignment and import library.
- [Microsoft PE CFG metadata](https://learn.microsoft.com/en-us/windows/win32/secbp/pe-metadata)
  defines image target tables and the check/dispatch pointer contracts.

| ID | Assumption / dependent result | Stress test and falsification probe | Status |
| --- | --- | --- | --- |
| CFG1 | The retained outcomes describe kernel 29698 and the recorded DLL/source identities. | Run the same immutable observers on independent AMD64 and other ARM64 kernels; disagreement prevents reuse of this profile. | Confirmed only for the retained process views. |
| CFG2 | Only children reaching their private-call marker can qualify admission. | Remove that marker, alter CFG policy or substitute another terminal status; validation must fail. | Confirmed by rejection tests. |
| CFG3 | Canonical producer identity normalizes LF/CRLF checkout conversion; exact raw compiler inputs are recorded separately. | Validate CRLF source with the same canonical hash, while preserving raw capture hashes; any non-newline change must fail. | Confirmed by the source-drift test. |

| Impact | Remaining requirement | Blocks this collection? |
| --- | --- | --- |
| High | Image target metadata, guest NT target-record capture and indirect-call enforcement still require implementation. | No; private-memory state is implemented below. Full process emulation remains incomplete. |
| High | Other kernels, WoW64 CFG, mixed unwind/asynchronous dispatch and the pending general-registry permission/API choice remain open. | No; full process emulation remains incomplete. |
| Medium | The native collectors intentionally terminate denied-call children and run only on Windows. | No; macOS/Linux share the provenance validator and its tests, without a native-success stub. |

## Private-memory state

The guest VM accepts private allocation `PAGE_TARGETS_INVALID` and private
protection `PAGE_TARGETS_NO_UPDATE` requests and omits their request bit from
`AllocationProtect`, `Protect` and old-protection outputs. Section-creation
validation remains operation-specific. Invalid non-executable requests retain
their distinct allocation/protection NT statuses and old-protection stores.

The VM maintains sparse target/storage state and each reservation's original
execute protection. Default
executable reservations initialize every offset as valid; explicit registration
admits only the aligned address in its 16-byte slot. Invalidated and registered
slots survive decommit and release. A new non-executable reservation preserves
old bits. Every ordinary executable protect or commit request on an originally
non-executable reservation initializes the affected bits as default-valid,
including repeated requests after explicit registration or invalidation.
Originally executable reservations preserve those bits on ordinary transitions.
`NO_UPDATE` preserves either kind; allocation/commit `TARGETS_INVALID` explicitly
invalidates the requested range. Failed operations do not publish state.

Bitmap storage is independent of target permissions and validity. One bitmap
page covers an aligned 256 KiB guest interval. Writable private targets can be
registered after an executable neighbor establishes that storage, including
after the neighbor is released. Admission never grants execute permission or
consumes a guard. Target/state lookups take `O(log r)` time; range replacement
takes `O(k log r)` time and `O(k)` temporary space for `r` state boundaries and
`k` replaced boundaries. Huge reservations use boundary-sized metadata.

`native-memory-state-v1.rs` and `memory-state-arm64-29698-v1.json` retain the
independent producer and exact observations for ARM64 and translated x64 on
kernel `10.0.29698.1000`: 84 qualified private-call children and 14 storage
controls. Four preparatory cases are excluded because fresh writable target
registration depends on pre-existing bitmap storage. Instruction-fetch access
violations include the exception PC, access kind 8 and fault address; these
distinguish admitted NX targets from CFG failures. Storage controls keep all
seven allocations live until the end to prevent address reuse from carrying
bitmap storage between cases. The existing native AMD64 CI observations cover
the original 21 lifecycle controls; they do not qualify these additional cases.

`native-repeated-protection-v1.rs` and
`repeated-protection-arm64-29698-v1.json` add 12 initially writable repeat controls
across the same two process views. All reach their private `CALL`, return
`0x1234`, and release their reservations. They falsified an earlier model that
initialized originally non-executable pages only once. The corrected model uses
the original reservation protection and replays all 96 qualified observations.
`native-original-protection-v1.rs` and
`original-protection-arm64-29698-v1.json` retain the expanded cohort separately:
30 repeated-transition controls in each process view, starting from read/write,
read-only, no-access, execute-only and execute/read reservations. Each view has
18 leaf returns and 12 terminal `0xC0000409` outcomes. Every qualified child
reaches its private `CALL` with CFG enabled and records its original protection.
The observer does not capture an exception-record subcode for those terminal
outcomes. Its other 44 children per view are terminality checks, not additional
original-protection evidence.

The portable validator rejects missing calls, source/DLL drift, changed original
protections, disabled CFG, missing terminal records, wrong leaf values and
outcomes that contradict the original-protection rule:

```text
python -B tools/ci/windows_cfg_original_protection.py --verify-retained
python -B -m unittest discover -s tools/ci -p test_windows_cfg_original_protection.py -v
```

On native Windows, capture with:

```text
python -B tools/ci/windows_cfg_original_protection.py --output target/native-cfg-original-protection-v1
```

The existing Windows 2022/2025 lane captures this producer in addition to the
original API/call observers and preserves both output directories. Wiring does
not establish successful AMD64 results; inspect the resulting artifacts before
extending the measured profile beyond kernel 29698's two recorded process views.

To reproduce the additional observer on native Windows with Rust 1.95.0 and
the matching MSVC/Windows SDK libraries, create an in-checkout build directory,
set `TMP`, `TEMP` and `TMPDIR` to a subdirectory within it, then run:

```text
rustc +1.95.0 --edition=2024 docs/specifications/windows/native-cfg-private-code/native-memory-state-v1.rs -C control-flow-guard=yes -C link-arg=/guard:cf --out-dir target/cfg-memory-native-v1
target/cfg-memory-native-v1/native-memory-state-v1.exe --all
```

The parent reports 44 terminal children and seven storage observations. Only
42 children per process view qualify target admission. The Rust library tests
replay those 84 qualified observations plus the 12 repeat controls through the guest VM and check storage
boundaries, operation outputs, sparse replacement, huge reservations and failed
mutation rollback. The Windows personality runs on Windows, macOS and Linux;
this private-memory group does not establish image registration, guest bitmap
address publication, NT record capture or indirect-call enforcement.

The `references/` directory preserves unchanged Microsoft documentation and its
license, retrieval URLs and content hashes. Its general protection description
does not replace the separately observed original-protection behavior.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| MEMCFG1 | The recorded transitions generalize to other private addresses within the measured profile. | Independent child processes and non-reused storage ranges in both process views. | Arbitrary-address sparse state. | Exact reuse, overlapping pages, last slots, original protection and huge reservations. | Run the immutable producer at other addresses or on another kernel; disagreement limits that profile. | Retained; additional AMD64 and WoW64 observations remain open. |
| MEMCFG2 | Guest VM mutations are serialized. | The guest scheduler owns VM mutation on one host thread. | Preflight and metadata publication after successful mapping. | Failed commits/protects, bitmap neighbors and released-address reuse. | A concurrent host mutation path changes the same address space during dispatch. | Retained; rollback tests cover synchronous mutations. |
| MEMCFG3 | Storage spans aligned 256 KiB intervals independently of VAD lifetime. | Before/after registration at seven distances, with all allocations retained. | Sparse storage ranges and writable-target updates. | Distances 4 KiB through 1 MiB, including 252 KiB and 256 KiB. | A precondition-qualified fresh span admits registration across that boundary. | Confirmed for both recorded process views. |
| MEMCFG4 | Originally non-executable pages initialize default targets only once. | The first cohort covered first transitions. | Rejected initialized-run map. | Repeat protect/commit after explicit invalidation or alignment restriction. | All 12 additional native controls return while the old model denies. | Falsified; replaced with original-protection state. |
| MEMCFG5 | Original execute protection selects reset versus preservation on ordinary executable transitions. | Sixty expanded native controls across five original protections in two process views. | Per-reservation original-execute metadata. | Repeated protect/commit, explicit invalidation/alignment and executable neighbors. | Run the immutable producer on independent AMD64 and other kernels; disagreement limits the rule. | Confirmed for the two recorded kernel 29698 views; additional-kernel expanded results remain open. |
