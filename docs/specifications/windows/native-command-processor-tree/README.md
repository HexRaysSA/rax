# Complete fixed Command Processor subtrees

Installed Windows selection captures the complete subtrees rooted at
`HKLM\Software\Microsoft\Command Processor` and at the same suffix below
the captured creator SID in HKU. Native64 and Wow32 are captured independently.
Every node retains its canonical name, raw values, immediate child names,
ordinary maximum grant and `ACCESS_SYSTEM_SECURITY` open status. A parent
handle closes before descendant acquisition. Runtime guest opens use only the
immutable selection and never invoke the host registry.

The shared registry limits apply across previously selected trees and views:
1,024 keys, depth 32 below a selected root, 4,096 values, 1 MiB per value,
16 MiB aggregate value data and 1 MiB of canonical UTF-16 path storage.
Native enumeration and values must agree across two samples, with at most
three attempts per key. Canonical identity and ordinary grants are checked
again before closing the key. Pending sibling names reserve the global key
budget before descent. Count, duplicate, depth, path, access and shared-physical
view contradictions fail selection.

This is a bounded series of native observations. It is not an atomic registry
transaction: a change after a key's final observation is outside that key's
sample. Ordinary descendant canonical paths must remain beneath the captured
parent. Redirecting symbolic links fail this validation rather than extending
selection to another host location.

## Native evidence

`tree-v1.c` uses the native definitions in
`../native-command-processor/absolute-v1.c`; neither input is generated.
`controls-v1.json` records unchanged input, compiler and PE identities for
ARM64, x64 and x86 execution on Windows kernel 10.0.29695 on ARM. The x64 and
x86 reports describe that kernel's compatibility environments, rather than
an AMD64 kernel.

The measured machine tree has four nodes per view: the root,
`KnownPackageManagers`, `choco` and `winget`. Those are observations, not names
encoded in the implementation. Both creator-SID roots are absent. All raw
tree nodes, values, security results and open rows are retained. No creator
identity projection is necessary in this corpus because it has no present
creator nodes.

For each node the probe retains a Win32 seed, four absolute NT seed requests,
an empty-name reopen with `KEY_WOW64_64KEY`, and a reduced `KEY_READ` reopen.
Each successful seed tests the empty name, every immediate child and a
verified absent sentinel through both NT open services, two access masks and
four view flags. The retained total is
`2,464 + 2,464 + 2,112 = 7,040` relative/self/missing-name open rows. Absolute
seed requests and independent security probes are additional observations.
Handle counts before and after each completed native campaign agree.

Descendant and empty-name CMD opens use the same measured view/tag
transitions. In particular, an x86 native64 parent with tags `0x100` selects
the paired Wow32 descendant with tags `0x600` on a `0x200` request. Physical
Wow32 descendants use the measured explicit-path rules. The distinct NLS
descendant rule is not substituted for these CMD observations.

Portable replay compares statuses, grants, canonical names, key-body tags and
all captured values. It duplicates each seed, closes the original handle and
replaces the process registry namespace before replaying the relative rows.
Separate model tests cover distinct per-node access ceilings, malformed
trees, depth and aggregate budget boundaries, shared physical trees and
partial-header compatibility. Fresh Windows replay uses the actual installed
snapshot and creator SID through `RAX_COMMAND_TREE_CORPUS`.

## Reproduction

```sh
python tools/ci/windows_command_processor.py --verify-corpus
cargo test --locked --no-default-features --lib command_processor -- --test-threads=1 --nocapture
```

On native Windows with CMake, MSVC, Python and Rust available:

```powershell
python tools/ci/windows_command_processor.py
```

The existing runner builds both header/view and subtree producers for x64
and x86, plus ARM64 on an ARM64 host. It checks PE machine types, captures raw
reports, verifies unchanged producers, removes completed native build trees
and replays both fresh corpora. Zero selected, failed or ignored tests fails
qualification. Raw checkout and LF-normalized hashes are separate. Reports
remain inside `target/native-command-processor-v1`, which the existing Windows
CI job uploads. `--output` must select a new path inside the checkout.

For `N` selected keys, `B` retained value bytes and at most `C` children per
key, construction uses `O(B + N log C)` time excluding bounded path folding
and native API latency, and `O(B + N)` record storage excluding path units.
Traversal depth is bounded by 32. Native acquisition holds no ancestor HKEY
while acquiring a descendant; a temporary security probe can coexist with the
current node's ordinary handle.

## Assumption register and bounded scope

| ID | Assumption | Basis and dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| CT1 | CMD descendant view/tag mechanics follow the retained transitions on other supported kernels. | All 7,040 rows agree in the 29695 context; runtime routing uses those transitions. | Fresh AMD64 and ARM64 controls compare every status, grant, name and tag. Any mismatch falsifies the corresponding extension. | Confirmed for the retained context; retained for others. |
| CT2 | Ordinary descendants retain canonical parent/component identity. | All eight captured machine nodes satisfy that relation; selection enforces it. | A native symbolic link or alias resolving elsewhere must fail capture. A legitimate required alias would require independently measured selection semantics. | Confirmed for retained nodes; explicit acquisition boundary elsewhere. |
| CT3 | Present creator-SID trees use the same key-object mechanics with their own captured data and access ceilings. | Both retained creator roots are absent; controlled model fixtures cover present data. | Fresh present-user native controls must match. A differing transition falsifies the extension. | Retained; no independent present-user native proof. |

High impact: actual installed CMD execution, fresh AMD64 subtree replay and
native acquisition remain independent qualification gates. A portable corpus
pass does not establish their results or complete process emulation. Medium
impact: cross-key mutation is not transactionally frozen; each node has bounded
stability and identity checks. Uncaptured AppModel body tags remain a separate
runtime boundary. These items do not authorize unrelated registry expansion.
