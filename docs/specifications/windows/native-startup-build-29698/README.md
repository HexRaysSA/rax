# Native startup metadata on Windows ARM64 build 29698

These inputs qualify three existing startup recipes for the exact captured
native identity `(10, 0, 29698, IMAGE_FILE_MACHINE_ARM64)`. The observers ran
on that kernel in ARM64, x64 compatibility and x86 processes. They do not
qualify another build, an AMD64 kernel or complete command-processor execution.

| Input | Fresh observations | Existing recipe exercised |
| --- | ---: | --- |
| `prefetch-v1.json` | 1026 | Class 0 advice, flag 1 working-set population and validation precedence |
| `flush-v1.json` | 1056 | Class 192 metadata, full output bytes, return lengths and guard transitions |
| `notify-v1.json` | 1488 | Admission, filter bits, key/thread lifetime, APC delivery and ordered IOSB stores |

Prefetch contributes 822 class-0 and invalid-class rows to the shared replay.
The other 204 rows explore classes 1 through 8; those remain explicit execution
frontiers, covered by the existing rejection test. Native observation counts
are not counts of every setup or working-set query made by the producers.

All 1056 flush-query rows match the retained build-29695 rows byte for byte.
All 18 selected notification datasets match the retained rows after removing
only the separate pointer-width and handle-count metadata, using the existing
notification corpus grammar. Raw widths and handle counts remain in the replay
reports and are independently verified. The prefetch replay relocates only
native addresses through its existing, checked relocation procedure.

The admitted behavior uses the immutable captured kernel identity. Changing a
guest-reported version cannot select a recipe. Adjacent unmeasured builds,
missing or mismatched native machines and different major/minor versions remain
explicitly unavailable. Existing AMD64 20348/26100 behavior is unchanged. No
guest-supplied pointer, class, handle or length is forwarded to a native query.

## Original failure and supplementary controls

The initial combined capture ended with the unchanged x86 thread-notification
observer returning 11 after producing all 24 rows: its handle count was 70
before and 72 after. That capture remains failed. Its prefetch and flush
components had already completed with zero exit codes, complete matrices and
unchanged inputs; their individual completion is what the projected component
state denotes.

An independent bare-thread control subsequently observed temporary counts of
71 and 72 while creating and closing threads, and ended at its original count.
Three repetitions of the original, byte-identical notification executable each
returned zero with counts 70 to 70 and the same 24 semantic rows. The three
unexecuted x86 suites then passed using their original binaries. No assertion,
producer source or execution deadline was weakened. The identities of the two
handles in the failed run, and its precise cause, are unknown. The successful
corpus selects the first successful unchanged thread repetition; it does not
replace or relabel the failed capture.

## Provenance and verification

`inputs-v1.json` binds all three projections, 15 frozen compiler/validator inputs
and both evidence archives by SHA-256. `capture-build-v1/` preserves the three
small CMake adapters used with the existing frozen producers. The source
manifest records the actual compiled bytes. Local producer verification permits
CRLF checkout conversion by comparing LF-normalized source; archive verification
compares the original compiler-input bytes exactly.

| Archive | Bytes | SHA-256 |
| --- | ---: | --- |
| Original failed combined capture | 157680913 | `e9ffcbe50ced3e0566f6d9811e43afdae69ac4c7c9421f14e5ea90211bf60860` |
| Notification diagnostic and finishing controls | 5900779 | `bfee4a1709a14e57c6ab3a23810dd04e4b0964661621fcae4b5872c987ec9317` |

Check the retained projections and local producer identities on any host:

```console
python -I -B docs/specifications/windows/native-startup-build-29698/check.py
```

With the two archives available, additionally verify all 4046 payloads, raw
reports, component exit codes, original failure, executed PE images, unchanged
compiler inputs and provider DLLs:

```console
python -I -B docs/specifications/windows/native-startup-build-29698/check.py --archive path/to/original.zip --supplement path/to/supplement.zip
```

Expected selected totals are 1026 prefetch observations, 1056 flush queries and
1488 notification observations. The complete shared Rust replays also retain
the older kernel controls:

```console
cargo test --locked --no-default-features --lib memory_prefetch -- --test-threads=1
cargo test --locked --no-default-features --lib system_flush -- --test-threads=1
cargo test --locked --no-default-features --lib registry_tests::key_notify:: -- --test-threads=1
```

Native Windows installed-leaf tests must also pass; portable corpus replay is
not evidence that an installed native leaf executed. Whole-library, C API and
CLI validation remain separate acceptance gates.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| P98-A1 | Captured native identity selects the finite measured recipe. | Three process ABIs and their raw reports. | Exact 29698 admissions. | Guest-version spoofing, adjacent builds, wrong/missing machines, major/minor changes. | An uncaptured identity reaches the recipe or a captured row differs. | Confirmed for the retained observations; other identities remain unavailable. |
| P98-A2 | A later component failure does not invalidate completed, unchanged components. | All prefetch/flush exit codes, raw reports, image hashes and post-capture input checks. | Individual component projections. | Verify every raw row and source/image identity before and after execution. | A missing row, failed component exit or changed input. | Confirmed for these components; combined capture remains failed. |
| P98-A3 | The failed thread observer may include a transient runtime effect. | Bare-thread counts and three unchanged successful notification repetitions. | Interpretation of the failed counter check only. | Repeated unchanged controls without notification calls. | Reproducible notification-specific retained-handle growth. | Retained hypothesis; original handle identities and exact cause unknown. |

High impact: these finite startup controls do not establish full installed
process execution. Medium impact: the transient handle observation is retained
as a separate diagnostic result and cannot support a general no-leak claim.
Neither item authorizes changing unrelated emulation policy or host state.
