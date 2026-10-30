# Native Local Settings controls

This campaign checks the captured creator's fixed
`\Registry\User\<SID>\Software\Classes\Local Settings` subject. Acquisition
retains both views, every bounded descendant, raw value names/types/data,
canonical names, native maximum grants, and ordered child names/FILETIMEs.
Guest handles retain immutable records and view routes after duplication,
parent-handle closure, and replacement of the active registry catalog.

The independent C producer uses native NT opens, queries and enumeration.
The installed Rust acquisition uses the fixed selection and Win32 enumeration.
Their separately implemented encoders compare complete snapshots through the
[versioned digest wire format](wire-v1.md). Snapshot value bodies and descendant
names remain inside SHA-256. The open matrix retains only fixed root names and
fixed missing names.

`controls-v1.json` binds the five producer inputs to three compiled PE images
and their stdout hashes. It records ARM64, AMD64 and i386 processes on the
ARM64 Windows kernel `10.0.29695`, under SYSTEM. Each process observes 670
nodes, 1,906 values and 840,452 wire bytes across the two views, with digest
`15317217e016fee45574d45f0ed4e07eb30a7fbe9e1eae7ed1947cc42be8f28f`.
All native handle counts balance.

The same producer also completed under an ordinary console user's primary
token on that kernel: 8,630 nodes, 23,336 values, 7,660,748 wire bytes and
digest `772d5186a9cf29ecaafbb00f7618d426e28eb9c79e02854567cf848033f71290`
on all three process ABIs. That user-specific corpus is retained as task
evidence rather than a public user profile fixture. A fresh Windows campaign
always captures its actual creator and compares that creator's installed
snapshot.

Each present-root report contains 288 opens: logical and physical absolute
names, creator-hive-relative names and self reopens; `NtOpenKey` and
`NtOpenKeyEx`; source view flags `0`, `0x100`, `0x200`; target view flags with
the same values; read and maximum-access requests; and missing leaves and
intermediate components. Absolute routes have no source handle. Rows bind
the source tags, returned status, handle publication, granted access and
result tags. The guest replay repeats relative rows after namespace retirement.
Minimal synthetic bodies isolate these open mechanics from the separate
complete installed-snapshot comparison.

The x86 controls distinguish entry through a USER hive from self reopens.
They also distinguish SYSTEM's `.DEFAULT` alias from the ordinary user's
separate `<SID>_Classes` hive. The implementation preserves ordinary relative
tag inheritance and applies the measured Classes-hive entry/conversion rules.
Native ARM64 and AMD64 opens in this campaign return zero tags. Other native
kernels require fresh controls; this retained corpus alone establishes no
cross-kernel measurement.

The tag override matches directly below the captured creator's USER hive.
An identical suffix nested inside a Command Processor or OLE subtree retains
that subtree's existing policy; it does not become a Local Settings subject.

The fixed subject has a separate aggregate budget across both views: 16,384
keys, depth 32, 8 MiB canonical paths, 65,536 values, 32 MiB value names/data,
32,768 child entries and 2 MiB child names/FILETIMEs. Existing startup-subject
budgets retain their previous limits. Individual values remain bounded to
1 MiB, names to 16,383 UTF-16 units and components to 255 units. Acquisition
rejects incomplete metadata, escaped names, inconsistent creator identities,
view-content differences, and observed instability.

Verify the retained source identities on any supported host:

```sh
python tools/ci/windows_local_settings.py --verify-corpus
```

Expected output includes `"verified_inputs": 5` and
`"retained_process_abis": 3`. On native Windows with MSVC, CMake and the pinned
Rust toolchain available:

```sh
python tools/ci/windows_local_settings.py
```

The helper builds the applicable native process ABIs, checks PE machine types
and source/image hashes, captures new reports, compares snapshot digests, and
runs the twelve Local Settings model/dispatcher/installed tests. The output is
`target/native-local-settings-v1/observations.json` plus raw reports and logs.
Existing output is preserved; use `--output target/<new-name>` for another
campaign. A missing root is an explicitly compared native absence, with no
invented contents. Access failures or inconsistent snapshots fail the command.

The helper prepares the Rust test binary before capturing the live registry;
a cold compile therefore cannot make the reference stale before comparison.
`RAX_LOCAL_SETTINGS_CORPUS` identifies that immediate comparison's reference.
Run a long full-library suite in its ordinary environment without that variable,
then run the helper again for a fresh native comparison. A retained corpus
does not assert that the host registry remains unchanged during a long suite.

The C acquisition encountered native empty `REG_SZ` enumeration records with
`DataLength=0`, `DataOffset=0xffffffff`, and a returned span ending after the
name. It never dereferences the unused data offset and retains all nonempty
data bounds. This is acquisition evidence; these controls do not establish
guest `NtEnumerateValueKey` support or complete installed CMD startup.

The official API documentation retained beside this file is indexed by URL,
retrieval time, length and SHA-256 in `sources.json`. Its original HTML and
license notices are preserved. Corpus values and tag transitions come from
the native executable observations, not from API documentation prose.

The installed-subject test
`installed_local_settings_subject_matches_native_without_unrelated_startup_roots`
also compares the complete native digest after acquiring the creator hive
header and Local Settings with the production adapters. It isolates this
subject from unrelated startup roots. Run it under the same creator as the
fresh corpus with `RAX_LOCAL_SETTINGS_CORPUS` set:

```sh
cargo test --locked --no-default-features --lib installed_local_settings_subject_matches_native_without_unrelated_startup_roots -- --test-threads=1 --nocapture
```

Expected result is one passed test. This does not replace the whole-startup
snapshot tests. On the measured kernel, ordinary-user whole-startup selection
fails when reading the protected IFEO child `DefenderAgentScan.exe`;
`NtOpenKeyEx` returns `STATUS_ACCESS_DENIED` for every measured access request,
including `MAXIMUM_ALLOWED`. That separate acquisition limitation remains a
blocker for complete ordinary-user process startup.
