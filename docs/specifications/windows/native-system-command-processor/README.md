# Fixed System Command Processor selection

The installed snapshot selects the fixed machine path
`System\Software\Microsoft\Command Processor` in both Win32 views. It retains
an actual not-found result or a complete bounded tree with canonical identity,
values, enumeration metadata, and captured access. No guest-provided name or
handle is passed to a host registry function. Other System descendants remain
unselected.

This selection admits one fixed canonical path. Its two captured views must
agree on presence, absence class, and physical contents. A contradictory pair
fails acquisition. Values in both retained view records count toward the
existing aggregate storage limits. MACHINE handles retain the selection across
duplication and namespace replacement; child accounting distinguishes System
from Software.

## Independent native evidence

`controls-system-v1.json` retains ARM64-kernel Windows 10.0.29695 observations.
ARM64 executes natively; x64 and x86 execute in that kernel's compatibility
environments. This is not native AMD64-kernel qualification. Source, executable,
and raw-report hashes identify all 15 producer executions; all measured handle
counts balance. The original CMD producers and their pinned CMake input remain
unchanged. This campaign reuses their absolute/relative helpers and records a
separately versioned fixed-parent graph.

| Producer | Rows per process ABI | Subject |
| --- | ---: | --- |
| `system-v1.c` | 136 | Fixed leaf, two services, 17 access masks, four views |
| `system-relative-v1.c` | 12 | Fixed leaf from three retained MACHINE views |
| `system-parent-v1.c` | 136 | Present `System\Software` parent |
| `system-parent-relative-v1.c` | 12 | That parent from the same MACHINE views |
| `system-parent-graph-v1.c` | 24 ARM64, 24 x64, 32 x86 | Closed empty-name reopen graph of the present shared parent |

The retained matrix contains `(136 + 12 + 136 + 12) × 3 + 24 + 24 + 32 = 968`
NT rows. Root acquisitions, graph seeds, and warmup opens are separate. The
actual leaf is absent in this context: valid requests produce
`STATUS_OBJECT_NAME_NOT_FOUND`; contradictory x86 view flags produce
`STATUS_INVALID_PARAMETER`. The parent graph supplies positive shared-key
handle mechanics. Positive exact-leaf contents are synthetic model tests;
native positive exact-leaf behavior remains unobserved here.

## Reproduction and validation

From the repository root, verify retained source identity on any host:

```console
python -I tools/ci/windows_system_command_processor.py --verify-corpus
```

Expected output reports eight verified inputs and three retained process ABIs.
On native Windows with MSVC, CMake, and Cargo available:

```console
python tools/ci/windows_system_command_processor.py
```

The runner builds x64/x86 producers and additionally ARM64 producers on an
ARM64 host. It verifies PE machine types, pointer widths, nonempty parent
graphs, handle balance, and unchanged input/image hashes. Fresh observations
drive both the real guest NT dispatcher and the shared reopen-state tests.
Native acquisition tests independently compare the installed selection with
Win32 metadata. At least seven selected tests must pass without ignores.
The output defaults to `target/native-system-command-processor-v1`; an existing
directory is preserved and requires a new in-tree output path for another run.

These focused checks do not replace complete library/C API/CLI/platform gates
or prove that the installed CMD process reaches its final output. Acquisition
scans only the fixed bounded trees. Guest routing uses immutable catalogue
lookups and retains no native registry handles or callbacks.
